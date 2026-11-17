#include "common.h"
#include "gov.h"
#include <errno.h>
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXW 10

typedef struct {
    uint32_t next;
    struct {
        uint64_t files, bytes, findings, skipped;
        uint64_t er[EXT_N], ef[EXT_N], en[EXT_N];
    } w[MAXW];
} shared_t;

typedef struct {
    uint32_t file;
    finding_t f;
} rec_t;

typedef struct {
    char path[256];
    uint64_t hash;
    uint32_t n;
    uint32_t pad;
} hdr_t;

typedef struct {
    hdr_t h;
    finding_t *f;
} cent_t;

static char root[PATH_MAX], out[PATH_MAX] = "dbvf-out", sub[PATH_MAX] = "", vdir[PATH_MAX] = "", ver[48] = "";
static size_t rootlen;
static int nw = 8, cpu_cap = 97, mem_cap = 95, only_built = 1, fresh, update_vulns, use_cocci, no_ext, any_ext;
static long every;
static char **files;
static int *tiers;
static uint32_t *todo;
static uint32_t ntodo;
static size_t nfiles, capfiles;
static shared_t *sh;
static volatile sig_atomic_t stop_flag;
static FILE *wf;
static uint32_t cur_file;
static int cur_id;
static rec_t *recs;
static size_t nrec, caprec;

static void on_sig(int s)
{
    (void)s;
    stop_flag = 1;
}

static int visit(const char *p, const struct stat *sb, int flag, struct FTW *ftw)
{
    const char *rel = p + rootlen, *b = p + ftw->base;
    size_t n = strlen(p);
    (void)sb;

    while (*rel == '/')
        rel++;
    if (flag == FTW_D) {
        if (ftw->level > 0 && (!strcmp(b, ".git") || !strcmp(b, "Documentation") || !strcmp(b, "tools") ||
                               !strcmp(b, "scripts") || !strcmp(b, "samples")))
            return FTW_SKIP_SUBTREE;
        return FTW_CONTINUE;
    }
    if (flag != FTW_F || n < 3)
        return FTW_CONTINUE;
    if (only_built) {
        char o[PATH_MAX];
        struct stat st;
        if (strcmp(p + n - 2, ".c") != 0 || n >= sizeof o)
            return FTW_CONTINUE;
        memcpy(o, p, n + 1);
        o[n - 1] = 'o';
        if (stat(o, &st) != 0)
            return FTW_CONTINUE;
    } else if (strcmp(p + n - 2, ".c") != 0 && strcmp(p + n - 2, ".h") != 0) {
        return FTW_CONTINUE;
    }
    if (nfiles == capfiles) {
        capfiles = capfiles ? capfiles * 2 : 4096;
        files = realloc(files, capfiles * sizeof *files);
        if (!files)
            return FTW_STOP;
    }
    files[nfiles] = strdup(rel);
    if (!files[nfiles])
        return FTW_STOP;
    nfiles++;
    return FTW_CONTINUE;
}

static int cmp_path(const void *a, const void *b)
{
    const char *x = *(char *const *)a, *y = *(char *const *)b;
    int tx = tier_of(x), ty = tier_of(y);
    if (tx != ty)
        return tx - ty;
    return strcmp(x, y);
}

static void push_rec(uint32_t file, const finding_t *f)
{
    if (nrec == caprec) {
        caprec = caprec ? caprec * 2 : 1024;
        recs = realloc(recs, caprec * sizeof *recs);
        if (!recs)
            exit(1);
    }
    recs[nrec].file = file;
    recs[nrec].f = *f;
    nrec++;
}

static void emit(void *ctx, const finding_t *f)
{
    rec_t r;
    (void)ctx;
    r.file = cur_file;
    r.f = *f;
    if (wf && fwrite(&r, sizeof r, 1, wf) == 1)
        sh->w[cur_id].findings++;
}

static void cve_emit(void *ctx, size_t idx, const finding_t *f)
{
    (void)ctx;
    push_rec((uint32_t)idx, f);
}

static void worker(int id, const char *odir)
{
    char path[PATH_MAX];

    setpgid(0, 0);
    setpriority(PRIO_PROCESS, 0, 19);
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    cur_id = id;
    snprintf(path, sizeof path, "%s/w%d.bin", odir, id);
    wf = fopen(path, "wb");
    if (!wf)
        _exit(1);
    for (;;) {
        uint32_t k = __atomic_fetch_add(&sh->next, 1, __ATOMIC_RELAXED), i;
        size_t b = 0;
        if (k >= ntodo)
            break;
        i = todo[k];
        cur_file = i;
        snprintf(path, sizeof path, "%s/%s", root, files[i]);
        if (rules_scan(path, tiers[i], emit, NULL, &b) != 0) {
            sh->w[id].skipped++;
            continue;
        }
        sh->w[id].files++;
        sh->w[id].bytes += b;
        if (any_ext) {
            ext_res_t er;
            int t;
            memset(&er, 0, sizeof er);
            ext_scan(root, files[i], tiers[i], emit, NULL, &er);
            for (t = 0; t < EXT_N; t++) {
                if (er.state[t] == 1)
                    sh->w[id].er[t]++;
                else if (er.state[t] == 2)
                    sh->w[id].ef[t]++;
                sh->w[id].en[t] += (uint64_t)er.nf[t];
            }
        }
    }
    fclose(wf);
    _exit(0);
}

static void sleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int cmp_rec(const void *a, const void *b)
{
    const rec_t *x = a, *y = b;
    if (x->f.sev != y->f.sev)
        return x->f.sev - y->f.sev;
    if (x->f.tier != y->f.tier)
        return x->f.tier - y->f.tier;
    if (x->file != y->file)
        return x->file < y->file ? -1 : 1;
    return x->f.line - y->f.line;
}

static int cmp_rec_file(const void *a, const void *b)
{
    const rec_t *x = a, *y = b;
    if (x->file != y->file)
        return x->file < y->file ? -1 : 1;
    return x->f.line - y->f.line;
}

static int cmp_cent(const void *a, const void *b)
{
    return strcmp(((const cent_t *)a)->h.path, ((const cent_t *)b)->h.path);
}

static uint64_t hash_file(const char *path)
{
    unsigned char buf[65536];
    uint64_t h = 1469598103934665603ULL;
    FILE *f = fopen(path, "rb");
    size_t n, i;

    if (!f)
        return 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        for (i = 0; i < n; i++)
            h = (h ^ buf[i]) * 1099511628211ULL;
    fclose(f);
    return h ? h : 1;
}

static void jstr(FILE *o, const char *s)
{
    fputc('"', o);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            fprintf(o, "\\%c", c);
        else if (c < 0x20 || c >= 0x7f)
            fputc(c < 0x20 ? ' ' : '?', o);
        else
            fputc(c, o);
    }
    fputc('"', o);
}

static const char *conf_name(int c)
{
    return c >= 2 ? "high" : c == 1 ? "medium" : "low";
}

static void usage(const char *a)
{
    fprintf(stderr,
            "usage: %s [options] <kernel-tree>\n"
            "  -w N      workers, 1-10, default 8\n"
            "  -c PCT    cpu cap, default 97\n"
            "  -m PCT    ram cap, default 95\n"
            "  -a        scan every .c and .h, not only files with a compiled .o beside them\n"
            "  -s DIR    scan only this subdirectory of the tree\n"
            "  -o DIR    output directory, default dbvf-out\n"
            "  -e TIME   periodic mode, repeat every TIME (90, 30m, 6h, 1d); unchanged files are not rescanned\n"
            "  -f        ignore the saved per-file state and rescan everything\n"
            "  -V DIR    kernel vulns dataset, default ~/src/vulns, 'none' skips the CVE cross-check\n"
            "  -U        git pull the vulns dataset before each CVE cross-check\n"
            "  -X        do not run external analyzers\n"
            "  -C        also run coccinelle (slow, tier 0 and 1 only)\n"
            "  --hardening-needed  list where the tree's .config is not at max hardening, with locations only\n"
            "  --config FILE       config to check instead of <kernel-tree>/.config\n",
            a);
}

static long parse_every(const char *s)
{
    char *e;
    long v = strtol(s, &e, 10);
    if (v <= 0)
        return -1;
    if (*e == 'm')
        v *= 60;
    else if (*e == 'h')
        v *= 3600;
    else if (*e == 'd')
        v *= 86400;
    else if (*e && *e != 's')
        return -1;
    return v;
}

static size_t cache_load(const char *sp, const char *fp, cent_t **outc)
{
    FILE *f = fopen(sp, "rb");
    char magic[8], buf[1024];
    uint32_t fl;
    cent_t *c = NULL;
    size_t n = 0, cap = 0;
    hdr_t h;

    *outc = NULL;
    if (!f)
        return 0;
    if (fread(magic, 8, 1, f) != 1 || memcmp(magic, "DBVF19S1", 8) != 0 || fread(&fl, 4, 1, f) != 1 || fl == 0 ||
        fl >= sizeof buf || fread(buf, fl, 1, f) != 1) {
        fclose(f);
        return 0;
    }
    buf[fl] = 0;
    if (strcmp(buf, fp) != 0) {
        fclose(f);
        return 0;
    }
    while (fread(&h, sizeof h, 1, f) == 1) {
        finding_t *fa = NULL;
        h.path[255] = 0;
        if (h.n > 0) {
            fa = malloc(h.n * sizeof *fa);
            if (!fa || fread(fa, sizeof *fa, h.n, f) != h.n) {
                free(fa);
                break;
            }
        }
        if (n == cap) {
            cap = cap ? cap * 2 : 4096;
            c = realloc(c, cap * sizeof *c);
            if (!c)
                exit(1);
        }
        c[n].h = h;
        c[n].f = fa;
        n++;
    }
    fclose(f);
    qsort(c, n, sizeof *c, cmp_cent);
    *outc = c;
    return n;
}

static int run_pass(int passno)
{
    pid_t pids[MAXW];
    int alive[MAXW], paused[MAXW], nalive, episode = 0, throttle_events = 0, interrupted = 0, i, t;
    char p[PATH_MAX], start[PATH_MAX], sp[PATH_MAX], fp[1024], tbuf[64];
    uint32_t last_target = 0, cpu_seen = 0, mem_seen = 0;
    size_t tier_n[4] = { 0, 0, 0, 0 }, sev_n[SEV_N] = { 0 }, k, ncache = 0, reused = 0;
    uint64_t tf = 0, tb = 0, ts = 0, *hashes, er[EXT_N] = { 0 }, ef[EXT_N] = { 0 }, en[EXT_N] = { 0 };
    cent_t **cached, *cache = NULL;
    time_t t0 = time(NULL);
    struct tm tmv;
    void *g;
    gov_out_t go;
    long tick = 0;
    cve_stats_t cst;
    int cve_rc = -2;
    FILE *fj, *fr, *fh;
    uint32_t h32 = 2166136261u;

    files = NULL;
    nfiles = capfiles = 0;
    recs = NULL;
    nrec = caprec = 0;
    snprintf(start, sizeof start, "%s%s%s", root, sub[0] ? "/" : "", sub);
    if (nftw(start, visit, 64, FTW_PHYS | FTW_ACTIONRETVAL) < 0 || nfiles == 0) {
        fprintf(stderr, "no files queued (%s mode); try -a if the tree is not built\n", only_built ? "compiled-only" : "all");
        return 3;
    }
    qsort(files, nfiles, sizeof *files, cmp_path);
    tiers = malloc(nfiles * sizeof *tiers);
    hashes = malloc(nfiles * sizeof *hashes);
    cached = calloc(nfiles, sizeof *cached);
    todo = malloc(nfiles * sizeof *todo);
    if (!tiers || !hashes || !cached || !todo)
        return 1;
    for (k = 0; k < nfiles; k++) {
        tiers[k] = tier_of(files[k]);
        tier_n[tiers[k]]++;
    }

    {
        const char *tn = "";
        char tools[128] = "";
        for (t = 0; t < EXT_N; t++)
            if (ext_enabled(t))
                snprintf(tools + strlen(tools), sizeof tools - strlen(tools), "%s%s", tools[0] ? "," : "", ext_name(t));
        (void)tn;
        snprintf(fp, sizeof fp, "dbvf19-state-1 rules=%zu tools=%s mode=%s sub=%s root=%s", rules_count(), tools,
                 only_built ? "built" : "all", sub, root);
    }
    for (k = 0; fp[k]; k++)
        h32 = (h32 ^ (unsigned char)fp[k]) * 16777619u;
    snprintf(sp, sizeof sp, "%s/state-%08x.bin", out, h32);

    for (k = 0; k < nfiles; k++) {
        snprintf(p, sizeof p, "%s/%s", root, files[k]);
        hashes[k] = hash_file(p);
    }
    if (!fresh)
        ncache = cache_load(sp, fp, &cache);
    ntodo = 0;
    for (k = 0; k < nfiles; k++) {
        cent_t key, *hit = NULL;
        if (ncache && strlen(files[k]) < 255 && hashes[k]) {
            memset(&key, 0, sizeof key);
            snprintf(key.h.path, sizeof key.h.path, "%s", files[k]);
            hit = bsearch(&key, cache, ncache, sizeof *cache, cmp_cent);
        }
        if (hit && hit->h.hash == hashes[k]) {
            cached[k] = hit;
            reused++;
            for (uint32_t j = 0; j < hit->h.n; j++)
                push_rec((uint32_t)k, &hit->f[j]);
        } else {
            todo[ntodo++] = (uint32_t)k;
        }
    }

    if (mkdir(out, 0755) != 0 && errno != EEXIST) {
        perror(out);
        return 1;
    }
    if (!sh) {
        sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (sh == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
    }
    memset(sh, 0, sizeof *sh);

    g = gov_new((uint32_t)cpu_cap, (uint32_t)mem_cap);
    fprintf(stderr, "pass %d: kernel %s, %zu files queued (%s), %zu reused from state, %u to scan, %d workers, caps cpu %d%% mem %d%%\n",
            passno, ver, nfiles, only_built ? "compiled only" : "all", reused, ntodo, nw, cpu_cap, mem_cap);

    for (i = 0; i < nw; i++) {
        alive[i] = 0;
        paused[i] = 0;
        pids[i] = 0;
    }
    if (ntodo > 0) {
        for (i = 0; i < nw; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                continue;
            }
            if (pid == 0)
                worker(i, out);
            setpgid(pid, pid);
            pids[i] = pid;
            alive[i] = 1;
        }
    }
    nalive = 0;
    for (i = 0; i < nw; i++)
        nalive += alive[i];

    while (nalive > 0) {
        int st, rank = 0;
        pid_t r;

        sleep_ms(500);
        while ((r = waitpid(-1, &st, WNOHANG)) > 0)
            for (i = 0; i < nw; i++)
                if (pids[i] == r && alive[i]) {
                    alive[i] = 0;
                    nalive--;
                }
        if (stop_flag) {
            interrupted = 1;
            for (i = 0; i < nw; i++)
                if (alive[i]) {
                    kill(-pids[i], SIGCONT);
                    kill(-pids[i], SIGTERM);
                }
            for (i = 0; i < nw; i++)
                if (alive[i]) {
                    waitpid(pids[i], NULL, 0);
                    alive[i] = 0;
                }
            nalive = 0;
            break;
        }
        if (nalive == 0)
            break;
        gov_poll(g, (uint32_t)nalive, &go);
        cpu_seen = go.cpu_pct;
        mem_seen = go.mem_pct;
        last_target = go.target;
        if (go.throttled && !episode) {
            episode = 1;
            throttle_events++;
            fprintf(stderr, "\n2 many resources hold on :(\n");
        } else if (!go.throttled) {
            episode = 0;
        }
        for (i = 0; i < nw; i++) {
            if (!alive[i])
                continue;
            if ((uint32_t)rank < go.target) {
                if (paused[i]) {
                    kill(-pids[i], SIGCONT);
                    paused[i] = 0;
                }
            } else if (!paused[i]) {
                kill(-pids[i], SIGSTOP);
                paused[i] = 1;
            }
            rank++;
        }
        if (++tick % 4 == 0) {
            uint32_t d = sh->next > ntodo ? ntodo : sh->next;
            fprintf(stderr, "\rqueue %u/%u  cpu %u%%  mem %u%%  running %u/%d   ", d, ntodo, cpu_seen, mem_seen, last_target, nalive);
        }
    }
    if (ntodo > 0)
        fprintf(stderr, "\n");
    gov_free(g);

    for (i = 0; i < nw; i++) {
        FILE *f;
        rec_t r;
        tf += sh->w[i].files;
        tb += sh->w[i].bytes;
        ts += sh->w[i].skipped;
        for (t = 0; t < EXT_N; t++) {
            er[t] += sh->w[i].er[t];
            ef[t] += sh->w[i].ef[t];
            en[t] += sh->w[i].en[t];
        }
        snprintf(p, sizeof p, "%s/w%d.bin", out, i);
        f = fopen(p, "rb");
        if (!f)
            continue;
        while (fread(&r, sizeof r, 1, f) == 1)
            if (r.file < nfiles && r.f.sev >= 0 && r.f.sev < SEV_N)
                push_rec(r.file, &r.f);
        fclose(f);
        unlink(p);
    }

    if (!interrupted) {
        char tmp[PATH_MAX];
        FILE *sf;
        uint32_t fl = (uint32_t)strlen(fp);
        qsort(recs, nrec, sizeof *recs, cmp_rec_file);
        snprintf(tmp, sizeof tmp, "%s.tmp", sp);
        sf = fopen(tmp, "wb");
        if (sf) {
            size_t pos = 0;
            fwrite("DBVF19S1", 8, 1, sf);
            fwrite(&fl, 4, 1, sf);
            fwrite(fp, fl, 1, sf);
            for (k = 0; k < nfiles; k++) {
                hdr_t h;
                size_t s0 = pos;
                while (pos < nrec && recs[pos].file == k)
                    pos++;
                if (strlen(files[k]) >= 255 || !hashes[k])
                    continue;
                memset(&h, 0, sizeof h);
                snprintf(h.path, sizeof h.path, "%s", files[k]);
                h.hash = hashes[k];
                h.n = (uint32_t)(pos - s0);
                fwrite(&h, sizeof h, 1, sf);
                for (size_t j = s0; j < pos; j++)
                    fwrite(&recs[j].f, sizeof(finding_t), 1, sf);
            }
            if (fclose(sf) == 0)
                rename(tmp, sp);
            else
                unlink(tmp);
        }
    }

    if (vdir[0] && strcmp(vdir, "none") != 0) {
        if (update_vulns && !interrupted) {
            char *av[] = { "git", "-C", vdir, "pull", "--ff-only", "--quiet", NULL };
            fprintf(stderr, "updating vulns dataset\n");
            if (ext_exec(av, NULL, 300, NULL, NULL) != 0)
                fprintf(stderr, "vulns update failed, using what is on disk\n");
        }
        cve_rc = cve_scan(vdir, root, ver, files, nfiles, cve_emit, NULL, &cst);
    }

    qsort(recs, nrec, sizeof *recs, cmp_rec);
    for (k = 0; k < nrec; k++)
        sev_n[recs[k].f.sev]++;

    snprintf(p, sizeof p, "%s/findings.jsonl", out);
    fj = fopen(p, "w");
    for (k = 0; fj && k < nrec; k++) {
        const rec_t *x = &recs[k];
        fprintf(fj, "{\"severity\":\"%s\",\"tier\":%d,\"confidence\":\"%s\",\"file\":", sev_name(x->f.sev), x->f.tier,
                conf_name(x->f.conf));
        jstr(fj, files[x->file]);
        fprintf(fj, ",\"line\":%d,\"rule\":", x->f.line);
        jstr(fj, x->f.rule);
        fputs(",\"message\":", fj);
        jstr(fj, x->f.msg);
        fputs(",\"snippet\":", fj);
        jstr(fj, x->f.snippet);
        fputs("}\n", fj);
    }
    if (fj)
        fclose(fj);

    localtime_r(&t0, &tmv);
    strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tmv);
    snprintf(p, sizeof p, "%s/REPORT.md", out);
    fr = fopen(p, "w");
    if (!fr) {
        perror(p);
        return 1;
    }
    fprintf(fr, "# deanbluntVulnSeeker19 report\n\n");
    if (interrupted)
        fprintf(fr, "**INTERRUPTED: partial results only.**\n\n");
    fprintf(fr, "## Coverage\n\n");
    fprintf(fr, "- tree: `%s` (kernel %s)\n- pass %d started %s, took %lds\n", root, ver, passno, tbuf, (long)(time(NULL) - t0));
    fprintf(fr, "- scope: %s%s%s\n", only_built ? "compiled files only (.c with a .o beside it)" : "all .c and .h",
            sub[0] ? ", subdir " : "", sub);
    fprintf(fr, "- files queued: %zu (tier 0: %zu, tier 1: %zu, tier 2: %zu, tier 3: %zu)\n", nfiles, tier_n[0], tier_n[1],
            tier_n[2], tier_n[3]);
    fprintf(fr, "- scanned this pass: %llu files (%llu unreadable or skipped, %llu bytes); reused unchanged from saved state: %zu\n",
            (unsigned long long)tf, (unsigned long long)ts, (unsigned long long)tb, reused);
    fprintf(fr, "- workers: %d, caps cpu %d%% mem %d%%, throttle episodes: %d\n", nw, cpu_cap, mem_cap, throttle_events);
    fprintf(fr, "- built-in rules run: %zu (", rules_count());
    for (k = 0; k < rules_count(); k++)
        fprintf(fr, "%s%s", k ? ", " : "", rules_name(k));
    fprintf(fr, ")\n- external analyzers (counts are for files scanned this pass):\n");
    for (t = 0; t < EXT_N; t++) {
        if (!ext_found(t))
            fprintf(fr, "  - %s: not installed\n", ext_name(t));
        else if (!ext_enabled(t))
            fprintf(fr, "  - %s: installed, %s\n", ext_name(t), t == EXT_SPATCH && !no_ext ? "not run (opt-in with -C)" : "not run (-X)");
        else
            fprintf(fr, "  - %s: ran on %llu files, %llu skipped (no kbuild compile command, timeout or error), %llu findings\n",
                    ext_name(t), (unsigned long long)er[t], (unsigned long long)ef[t], (unsigned long long)en[t]);
    }
    if (cve_rc == -2)
        fprintf(fr, "- CVE cross-check: not run (%s)\n", vdir[0] ? "disabled with -V none" : "no dataset");
    else if (cve_rc != 0)
        fprintf(fr, "- CVE cross-check: not run, dataset not usable at `%s`\n", vdir);
    else
        fprintf(fr,
                "- CVE cross-check: %zu CVEs in dataset, %zu apply to version %s by the version test, %zu of those touch files in this queue, "
                "%zu dropped because the fix commit is in the tree's git history, %zu findings\n",
                cst.total, cst.ver_hits, ver, cst.compiled_hits, cst.git_fixed, cst.findings);
    fprintf(fr, "\nSeverity is the tool's estimate from the rule and the tier, not proof of exploitability. A hit is a place to read, a miss proves nothing.\n\n");
    fprintf(fr, "## Summary\n\n| severity | count |\n|---|---|\n");
    for (i = 0; i < SEV_N; i++)
        fprintf(fr, "| %s | %zu |\n", sev_name(i), sev_n[i]);
    for (i = 0; i < SEV_N; i++) {
        size_t shown = 0;
        if (!sev_n[i])
            continue;
        fprintf(fr, "\n## %s (%zu)\n\n", sev_name(i), sev_n[i]);
        for (k = 0; k < nrec; k++) {
            const rec_t *x = &recs[k];
            char sn[sizeof x->f.snippet];
            size_t j;
            if (x->f.sev != i)
                continue;
            if (shown == 300) {
                fprintf(fr, "- ... %zu more in findings.jsonl\n", sev_n[i] - shown);
                break;
            }
            for (j = 0; j < sizeof sn; j++)
                sn[j] = x->f.snippet[j] == '`' ? '\'' : x->f.snippet[j];
            fprintf(fr, "- `%s:%d` [%s] tier %d, confidence %s: %s\n", files[x->file], x->f.line, x->f.rule, x->f.tier,
                    conf_name(x->f.conf), x->f.msg);
            if (sn[0])
                fprintf(fr, "  `%s`\n", sn);
            shown++;
        }
    }
    fprintf(fr, "\n");
    fclose(fr);

    snprintf(p, sizeof p, "%s/history.log", out);
    fh = fopen(p, "a");
    if (fh) {
        fprintf(fh, "%s pass %d%s scanned %llu reused %zu findings %zu crit %zu high %zu med %zu low %zu info %zu\n", tbuf, passno,
                interrupted ? " INTERRUPTED" : "", (unsigned long long)tf, reused, nrec, sev_n[0], sev_n[1], sev_n[2],
                sev_n[3], sev_n[4]);
        fclose(fh);
    }
    fprintf(stderr, "scanned %llu files (%zu reused), %zu findings -> %s/REPORT.md, %s/findings.jsonl\n", (unsigned long long)tf,
            reused, nrec, out, out);

    for (k = 0; k < ncache; k++)
        free(cache[k].f);
    free(cache);
    for (k = 0; k < nfiles; k++)
        free(files[k]);
    free(files);
    free(tiers);
    free(hashes);
    free(cached);
    free(todo);
    free(recs);
    recs = NULL;
    return interrupted ? 130 : 0;
}

int main(int argc, char **argv)
{
    int opt, rc = 0, pass = 1, hardening = 0;
    const char *hcfg = NULL;
    static const struct option lopts[] = {
        { "hardening-needed", no_argument, NULL, 1000 },
        { "config", required_argument, NULL, 1001 },
        { 0, 0, 0, 0 }
    };
    struct sigaction sa;
    char hp[PATH_MAX];
    const char *home = getenv("HOME");

    snprintf(hp, sizeof hp, "%s/src/vulns", home ? home : ".");
    snprintf(vdir, sizeof vdir, "%s", hp);
    while ((opt = getopt_long(argc, argv, "w:c:m:as:o:e:fV:UXCh", lopts, NULL)) != -1) {
        switch (opt) {
        case 1000: hardening = 1; break;
        case 1001: hcfg = optarg; break;
        case 'w': nw = atoi(optarg); break;
        case 'c': cpu_cap = atoi(optarg); break;
        case 'm': mem_cap = atoi(optarg); break;
        case 'a': only_built = 0; break;
        case 's': snprintf(sub, sizeof sub, "%s", optarg); break;
        case 'o': snprintf(out, sizeof out, "%s", optarg); break;
        case 'e':
            every = parse_every(optarg);
            if (every < 0) {
                fprintf(stderr, "bad interval: %s\n", optarg);
                return 1;
            }
            break;
        case 'f': fresh = 1; break;
        case 'V': snprintf(vdir, sizeof vdir, "%s", optarg); break;
        case 'U': update_vulns = 1; break;
        case 'X': no_ext = 1; break;
        case 'C': use_cocci = 1; break;
        default: usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }
    if (nw < 1) nw = 1;
    if (nw > MAXW) nw = MAXW;
    if (!realpath(argv[optind], root)) {
        perror(argv[optind]);
        return 1;
    }
    rootlen = strlen(root);
    if (!preflight_kernel(root, ver, sizeof ver)) {
        puts("yo this isn't even a fucking kernel bro");
        return 2;
    }
    if (hardening)
        return hardening_scan(root, ver, hcfg);
    ext_init(root, use_cocci, no_ext);
    {
        int t;
        for (t = 0; t < EXT_N; t++)
            any_ext |= ext_enabled(t);
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (;;) {
        rc = run_pass(pass);
        if (!every || stop_flag || rc == 3)
            break;
        fprintf(stderr, "next pass in %lds, Ctrl-C to stop\n", every);
        {
            long left;
            for (left = every; left > 0 && !stop_flag; left--)
                sleep_ms(1000);
        }
        if (stop_flag)
            break;
        pass++;
    }
    return rc;
}

/* coordinator: preflight, collect and tier-sort the queue, hash every file, reuse saved findings for unchanged files, fork workers for the rest, then merge worker results */
/* workers each get their own process group so the governor can SIGSTOP a worker together with any analyzer it spawned, and PDEATHSIG kills them if the coordinator dies */
/* saved state lives in the output directory per scope and tool set, a different tool set or mode invalidates it, cve findings are never cached because the dataset moves */
/* findings from workers are binary records merged here, severity order then tier then path, the report always opens with what actually ran */
