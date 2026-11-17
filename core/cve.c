#include "common.h"
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    int a, b, c;
} ver_t;

typedef struct {
    ver_t iv, fv;
    int fixed, patch, ipatch;
    char ivs[24], fvs[24], fsha[48];
} dy_t;

#define MAXDY 160

static char **g_files;

static int vparse(const char *s, ver_t *v, int *patch)
{
    int a = 0, b = 0, c = 0, n = sscanf(s, "%d.%d.%d", &a, &b, &c);

    if (n < 2)
        return 0;
    if (patch)
        *patch = (n == 3);
    if (n < 3)
        c = 0;
    if (strstr(s, "-rc"))
        c = -1;
    v->a = a;
    v->b = b;
    v->c = c;
    return 1;
}

static int vcmp(const ver_t *x, const ver_t *y)
{
    if (x->a != y->a)
        return x->a - y->a;
    if (x->b != y->b)
        return x->b - y->b;
    return x->c - y->c;
}

static char *slurp(const char *path, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *b;
    size_t n;

    if (!f)
        return NULL;
    b = malloc(cap + 1);
    if (!b) {
        fclose(f);
        return NULL;
    }
    n = fread(b, 1, cap, f);
    fclose(f);
    b[n] = 0;
    if (len)
        *len = n;
    return b;
}

static int ishex(const char *s)
{
    size_t n = strlen(s), i;
    if (n < 7 || n > 40)
        return 0;
    for (i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

static int parse_dyad(char *buf, dy_t *d)
{
    int n = 0;
    char *save = NULL, *ln;

    for (ln = strtok_r(buf, "\n", &save); ln && n < MAXDY; ln = strtok_r(NULL, "\n", &save)) {
        char *f[4], *p = ln;
        int i;
        dy_t *x = &d[n];
        if (*ln == '#')
            continue;
        for (i = 0; i < 3; i++) {
            char *c = strchr(p, ':');
            if (!c)
                break;
            *c = 0;
            f[i] = p;
            p = c + 1;
        }
        if (i < 3)
            continue;
        f[3] = p;
        memset(x, 0, sizeof *x);
        if (!vparse(f[0], &x->iv, &x->ipatch))
            continue;
        snprintf(x->ivs, sizeof x->ivs, "%s", f[0]);
        snprintf(x->fvs, sizeof x->fvs, "%s", f[2]);
        if (!strcmp(f[2], "0") || !vparse(f[2], &x->fv, &x->patch)) {
            x->fixed = 0;
        } else {
            x->fixed = 1;
            snprintf(x->fsha, sizeof x->fsha, "%s", f[3]);
        }
        n++;
    }
    return n;
}

static int same_branch(const dy_t *x, const ver_t *V)
{
    return x->fixed && x->patch && x->fv.a == V->a && x->fv.b == V->b;
}

static int evaluate(const dy_t *d, int n, const ver_t *V, int *pick)
{
    int same = 0, i;

    for (i = 0; i < n; i++)
        if (same_branch(&d[i], V))
            same = 1;
    for (i = 0; i < n; i++) {
        if (vcmp(&d[i].iv, V) > 0)
            continue;
        if (!d[i].fixed) {
            if (d[i].ipatch && !(d[i].iv.a == V->a && d[i].iv.b == V->b))
                continue;
            *pick = i;
            return 1;
        }
        if (same) {
            if (same_branch(&d[i], V) && vcmp(V, &d[i].fv) < 0) {
                *pick = i;
                return 1;
            }
        } else if (!d[i].patch && vcmp(V, &d[i].fv) < 0) {
            *pick = i;
            return 1;
        }
    }
    return 0;
}

static int cmp_idx(const void *a, const void *b)
{
    return strcmp(g_files[*(const size_t *)a], g_files[*(const size_t *)b]);
}

typedef struct {
    size_t *idx;
    size_t n;
} lookup_t;

static long find_file(const lookup_t *lk, const char *path)
{
    size_t lo = 0, hi = lk->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(path, g_files[lk->idx[mid]]);
        if (c == 0)
            return (long)lk->idx[mid];
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return -1;
}

static int sev_of(const char *mbox)
{
    const char *p = strstr(mbox, "CVSS v");
    const char *e;

    if (!p)
        return SEV_MED;
    e = strchr(p, '\n');
    if (!e)
        e = p + strlen(p);
    for (; p < e; p++) {
        if (!strncmp(p, "CRITICAL", 8))
            return SEV_CRIT;
        if (!strncmp(p, "HIGH", 4))
            return SEV_HIGH;
        if (!strncmp(p, "MEDIUM", 6))
            return SEV_MED;
        if (!strncmp(p, "LOW", 3))
            return SEV_LOW;
    }
    return SEV_MED;
}

static void subject_of(const char *mbox, char *out, size_t n)
{
    const char *p = strstr(mbox, "\nSubject: ");
    const char *e, *c;

    out[0] = 0;
    if (!p)
        return;
    p += 10;
    e = strchr(p, '\n');
    c = strstr(p, ": ");
    if (c && (!e || c < e))
        p = c + 2;
    snprintf(out, n, "%.*s", e ? (int)(e - p) : (int)strlen(p), p);
}

static int collect_files(char *mbox, char **list, int max)
{
    char *p = strstr(mbox, "\nAffected files\n");
    int n = 0, seen = 0;

    if (!p)
        return 0;
    p += 16;
    while (*p && n < max) {
        char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (p[0] == '\t') {
            char *s = p + 1;
            if (e)
                *e = 0;
            while (l > 1 && (p[l - 1] == ' ' || p[l - 1] == '\r'))
                p[--l] = 0;
            if (*s)
                list[n++] = s;
            seen = 1;
        } else if (seen && l > 0 && p[0] != '=' ) {
            break;
        }
        if (!e)
            break;
        p = e + 1;
    }
    return n;
}

static int git_has(const char *root, const char *sha)
{
    char *av[] = { "git", "-C", (char *)root, "merge-base", "--is-ancestor", (char *)sha, "HEAD", NULL };
    if (!ishex(sha))
        return 0;
    return ext_exec(av, NULL, 30, NULL, NULL) == 0;
}

int cve_scan(const char *vdir, const char *root, const char *ver, char **files, size_t n, cve_emit_fn emit, void *ctx,
             cve_stats_t *st)
{
    char base[PATH_MAX], ydir[PATH_MAX], p[PATH_MAX];
    DIR *yd, *fd;
    struct dirent *ye, *fe;
    ver_t V;
    lookup_t lk;
    struct stat sb;
    int have_git, i;
    size_t k;

    memset(st, 0, sizeof *st);
    if (!vparse(ver, &V, NULL))
        return -1;
    snprintf(base, sizeof base, "%s/cve/published", vdir);
    yd = opendir(base);
    if (!yd)
        return -1;
    lk.idx = malloc((n ? n : 1) * sizeof *lk.idx);
    lk.n = n;
    for (k = 0; k < n; k++)
        lk.idx[k] = k;
    g_files = files;
    qsort(lk.idx, n, sizeof *lk.idx, cmp_idx);
    snprintf(p, sizeof p, "%s/.git", root);
    have_git = stat(p, &sb) == 0;
    st->ok = 1;

    while ((ye = readdir(yd)) != NULL) {
        if (ye->d_name[0] == '.')
            continue;
        snprintf(ydir, sizeof ydir, "%s/%s", base, ye->d_name);
        fd = opendir(ydir);
        if (!fd)
            continue;
        while ((fe = readdir(fd)) != NULL) {
            size_t nl = strlen(fe->d_name);
            char stem[64], *dbuf, *mbuf, *flist[512], subj[160], note[200];
            dy_t d[MAXDY];
            int nd, pick = -1, nf, nmatch = 0, fixed_git = 0, sev;
            long mi[512];

            if (nl < 11 || strcmp(fe->d_name + nl - 5, ".dyad") != 0 || strncmp(fe->d_name, "CVE-", 4) != 0)
                continue;
            st->total++;
            snprintf(stem, sizeof stem, "%.*s", (int)(nl - 5), fe->d_name);
            snprintf(p, sizeof p, "%s/%s", ydir, fe->d_name);
            dbuf = slurp(p, 65536, NULL);
            if (!dbuf)
                continue;
            nd = parse_dyad(dbuf, d);
            if (nd == 0 || !evaluate(d, nd, &V, &pick)) {
                free(dbuf);
                continue;
            }
            st->ver_hits++;
            snprintf(p, sizeof p, "%s/%s.mbox", ydir, stem);
            mbuf = slurp(p, 2u << 20, NULL);
            if (!mbuf) {
                free(dbuf);
                continue;
            }
            nf = collect_files(mbuf, flist, 512);
            for (i = 0; i < nf; i++) {
                long idx = find_file(&lk, flist[i]);
                if (idx >= 0)
                    mi[nmatch++] = idx;
            }
            if (nmatch == 0) {
                free(dbuf);
                free(mbuf);
                continue;
            }
            st->compiled_hits++;
            if (have_git) {
                for (i = 0; i < nd && !fixed_git; i++)
                    if (d[i].fixed && (!d[i].patch || same_branch(&d[i], &V)) && git_has(root, d[i].fsha))
                        fixed_git = 1;
                if (fixed_git) {
                    st->git_fixed++;
                    free(dbuf);
                    free(mbuf);
                    continue;
                }
            }
            sev = sev_of(mbuf);
            subject_of(mbuf, subj, sizeof subj);
            snprintf(note, sizeof note, "introduced %s, %s%s; %s", d[pick].ivs, d[pick].fixed ? "fixed in " : "unfixed",
                     d[pick].fixed ? d[pick].fvs : "", have_git ? "fix commit not in HEAD history" : "no git history to confirm");
            for (i = 0; i < nmatch; i++) {
                finding_t f;
                memset(&f, 0, sizeof f);
                f.sev = sev;
                f.tier = tier_of(files[mi[i]]);
                f.line = 0;
                f.conf = 1;
                snprintf(f.rule, sizeof f.rule, "%s", stem);
                snprintf(f.msg, sizeof f.msg, "%s", subj);
                snprintf(f.snippet, sizeof f.snippet, "%s", note);
                emit(ctx, (size_t)mi[i], &f);
                st->findings++;
            }
            free(dbuf);
            free(mbuf);
        }
        closedir(fd);
    }
    closedir(yd);
    free(lk.idx);
    return 0;
}

/* an unfixed line whose introducing version is a stable release of another branch (like 5.7.7) is about that branch only and is ignored for this tree */
/* data source is the kernel vulns repo, the .dyad file holds introduced:fixed version and commit pairs and the .mbox holds the subject, cvss and affected files */
/* version test is branch aware: if the tree's x.y branch has its own fix line only that line counts, otherwise a mainline fix newer than the tree counts, other stable branches are ignored */
/* a cve is reported only when one of its affected files is in the queue, and dropped when a fix commit for this branch or mainline is an ancestor of HEAD in the tree's git history */
/* confidence is medium because a backport with a different commit id looks unfixed here, and a hand patched fix is invisible to both the version test and the git test */
