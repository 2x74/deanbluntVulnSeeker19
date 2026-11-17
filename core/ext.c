#include "common.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *NAMES[EXT_N] = { "sparse", "smatch", "cppcheck", "spatch" };
static int found[EXT_N], enabled[EXT_N];
static char *cocci[64];
static int ncocci;

static int in_path(const char *name)
{
    const char *p = getenv("PATH");
    char buf[PATH_MAX];

    while (p && *p) {
        const char *e = strchr(p, ':');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n && n + strlen(name) + 2 < sizeof buf) {
            memcpy(buf, p, n);
            snprintf(buf + n, sizeof buf - n, "/%s", name);
            if (access(buf, X_OK) == 0)
                return 1;
        }
        p = e ? e + 1 : NULL;
    }
    return 0;
}

const char *ext_name(int t)
{
    return (t >= 0 && t < EXT_N) ? NAMES[t] : "?";
}

int ext_found(int t)
{
    return (t >= 0 && t < EXT_N) ? found[t] : 0;
}

int ext_enabled(int t)
{
    return (t >= 0 && t < EXT_N) ? enabled[t] : 0;
}

void ext_init(const char *root, int use_cocci, int disabled)
{
    static const char *dirs[] = { "free", "locks", "null" };
    int t;
    size_t d;

    for (t = 0; t < EXT_N; t++) {
        found[t] = in_path(NAMES[t]);
        enabled[t] = found[t] && !disabled && (t != EXT_SPATCH || use_cocci);
    }
    if (!enabled[EXT_SPATCH])
        return;
    for (d = 0; d < sizeof dirs / sizeof dirs[0]; d++) {
        char p[PATH_MAX];
        DIR *dp;
        struct dirent *e;
        snprintf(p, sizeof p, "%s/scripts/coccinelle/%s", root, dirs[d]);
        dp = opendir(p);
        if (!dp)
            continue;
        while ((e = readdir(dp)) != NULL && ncocci < 64) {
            size_t n = strlen(e->d_name);
            if (n > 6 && !strcmp(e->d_name + n - 6, ".cocci")) {
                char rel[PATH_MAX];
                snprintf(rel, sizeof rel, "scripts/coccinelle/%s/%s", dirs[d], e->d_name);
                cocci[ncocci++] = strdup(rel);
            }
        }
        closedir(dp);
    }
    if (ncocci == 0)
        enabled[EXT_SPATCH] = 0;
}

int ext_exec(char *const argv[], const char *cwd, unsigned cpu_secs, char **out, size_t *outlen)
{
    int pfd[2] = { -1, -1 };
    pid_t pid;
    size_t len = 0, cap = 0;
    char *buf = NULL;
    int st;

    if (out) {
        if (pipe(pfd) < 0)
            return -1;
    }
    pid = fork();
    if (pid < 0) {
        if (out) {
            close(pfd[0]);
            close(pfd[1]);
        }
        return -1;
    }
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        struct rlimit rl;
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (cpu_secs) {
            rl.rlim_cur = rl.rlim_max = cpu_secs;
            setrlimit(RLIMIT_CPU, &rl);
        }
        if (cwd && chdir(cwd) != 0)
            _exit(126);
        if (dn >= 0)
            dup2(dn, 0);
        if (out) {
            dup2(pfd[1], 1);
            dup2(pfd[1], 2);
            close(pfd[0]);
            close(pfd[1]);
        } else if (dn >= 0) {
            dup2(dn, 1);
            dup2(dn, 2);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (out) {
        char tmp[8192];
        ssize_t r;
        close(pfd[1]);
        for (;;) {
            r = read(pfd[0], tmp, sizeof tmp);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                break;
            if (len + (size_t)r + 1 > (8u << 20))
                continue;
            if (len + (size_t)r + 1 > cap) {
                cap = (len + (size_t)r + 1) * 2;
                buf = realloc(buf, cap);
                if (!buf)
                    break;
            }
            memcpy(buf + len, tmp, (size_t)r);
            len += (size_t)r;
        }
        close(pfd[0]);
        if (buf)
            buf[len] = 0;
        *out = buf;
        if (outlen)
            *outlen = len;
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -2;
}

static char **tokenize(const char *s, int *n)
{
    char **v = NULL;
    int cnt = 0, cap = 0;

    while (*s) {
        char *t;
        size_t l = 0;
        int q = 0;
        while (*s == ' ' || *s == '\t' || *s == '\n')
            s++;
        if (!*s)
            break;
        t = malloc(strlen(s) + 1);
        while (*s && (q || !(*s == ' ' || *s == '\t' || *s == '\n'))) {
            if (q) {
                if (*s == q) {
                    q = 0;
                    s++;
                    continue;
                }
                if (q == '"' && *s == '\\' && s[1])
                    s++;
                t[l++] = *s++;
                continue;
            }
            if (*s == '\'' || *s == '"') {
                q = *s++;
                continue;
            }
            if (*s == '\\' && s[1])
                s++;
            t[l++] = *s++;
        }
        t[l] = 0;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 64;
            v = realloc(v, (size_t)cap * sizeof *v);
        }
        v[cnt++] = t;
    }
    *n = cnt;
    return v;
}

static int wanted_flag(const char *t)
{
    return !strncmp(t, "-I", 2) || !strncmp(t, "-D", 2) || !strncmp(t, "-U", 2) || !strcmp(t, "-nostdinc") ||
           !strncmp(t, "-std=", 5) || !strcmp(t, "-m64") || !strcmp(t, "-funsigned-char") || !strcmp(t, "-fshort-wchar");
}

static char **load_flags(const char *root, const char *rel, int *nout)
{
    char p[PATH_MAX], dir[PATH_MAX], base[PATH_MAX];
    char *line = NULL, *body, **tok, **out = NULL;
    size_t cap = 0, l;
    FILE *f;
    const char *slash = strrchr(rel, '/');
    int nt = 0, i, no = 0;

    *nout = 0;
    if (slash) {
        snprintf(dir, sizeof dir, "%.*s", (int)(slash - rel), rel);
        snprintf(base, sizeof base, "%s", slash + 1);
    } else {
        dir[0] = 0;
        snprintf(base, sizeof base, "%s", rel);
    }
    l = strlen(base);
    if (l < 3 || strcmp(base + l - 2, ".c") != 0)
        return NULL;
    base[l - 2] = 0;
    if (dir[0])
        snprintf(p, sizeof p, "%s/%s/.%s.o.cmd", root, dir, base);
    else
        snprintf(p, sizeof p, "%s/.%s.o.cmd", root, base);
    f = fopen(p, "r");
    if (!f)
        return NULL;
    body = NULL;
    while (getline(&line, &cap, f) > 0) {
        if (!strncmp(line, "savedcmd_", 9) || !strncmp(line, "cmd_", 4)) {
            body = strstr(line, ":= ");
            break;
        }
    }
    fclose(f);
    if (!body) {
        free(line);
        return NULL;
    }
    tok = tokenize(body + 3, &nt);
    free(line);
    out = calloc((size_t)nt + 1, sizeof *out);
    for (i = 1; i < nt; i++) {
        if ((!strcmp(tok[i], "-include") || !strcmp(tok[i], "-isystem")) && i + 1 < nt) {
            out[no++] = strdup(tok[i]);
            out[no++] = strdup(tok[i + 1]);
            i++;
        } else if (wanted_flag(tok[i])) {
            out[no++] = strdup(tok[i]);
        }
    }
    for (i = 0; i < nt; i++)
        free(tok[i]);
    free(tok);
    *nout = no;
    return out;
}

static void free_flags(char **v, int n)
{
    int i;
    for (i = 0; i < n; i++)
        free(v[i]);
    free(v);
}

static int skip_id(const char *id)
{
    static const char *bad[] = { "unknownMacro", "syntaxError", "missingInclude", "missingIncludeSystem",
                                 "preprocessorErrorDirective", "toomanyconfigs", "normalCheckLevelMaxBranches",
                                 "checkLevelNormal", "unmatchedSuppression", "internalAstError" };
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (!strcmp(id, bad[i]))
            return 1;
    return 0;
}

static int parse_line(int t, const char *line, const char *rel, int tier, finding_t *f)
{
    const char *p = line, *msg, *k;
    size_t rl = strlen(rel);
    int ln, sev = -1, conf = 0;

    if (p[0] == '.' && p[1] == '/')
        p += 2;
    if (strncmp(p, rel, rl) != 0 || p[rl] != ':')
        return 0;
    p += rl + 1;
    if (!isdigit((unsigned char)*p))
        return 0;
    ln = atoi(p);
    while (isdigit((unsigned char)*p))
        p++;
    while (*p == ':' && (isdigit((unsigned char)p[1]))) {
        p++;
        while (isdigit((unsigned char)*p) || *p == '-')
            p++;
    }
    if (*p == ':')
        p++;
    while (*p == ' ')
        p++;
    msg = p;
    memset(f, 0, sizeof *f);
    f->line = ln;
    f->tier = tier;
    snprintf(f->rule, sizeof f->rule, "%s", NAMES[t]);
    if (t == EXT_SPARSE) {
        if (!strncmp(msg, "error: ", 7)) {
            sev = SEV_HIGH;
            msg += 7;
        } else if (!strncmp(msg, "warning: ", 9)) {
            sev = SEV_LOW;
            msg += 9;
        }
    } else if (t == EXT_SMATCH) {
        if ((k = strstr(msg, " error: ")) != NULL) {
            sev = SEV_HIGH;
            msg = k + 8;
        } else if ((k = strstr(msg, " warn: ")) != NULL) {
            sev = SEV_MED;
            msg = k + 7;
        }
        conf = 1;
    } else if (t == EXT_CPPCHECK) {
        const char *b = strrchr(msg, '[');
        if (!strncmp(msg, "error: ", 7)) {
            sev = SEV_HIGH;
            msg += 7;
        } else if (!strncmp(msg, "warning: ", 9)) {
            sev = SEV_MED;
            msg += 9;
        } else if (!strncmp(msg, "style: ", 7) || !strncmp(msg, "performance: ", 13) || !strncmp(msg, "portability: ", 13)) {
            sev = SEV_INFO;
            msg = strchr(msg, ' ') + 1;
        }
        if (b && sev >= 0) {
            char id[48];
            const char *e = strchr(b, ']');
            if (e && (size_t)(e - b - 1) < sizeof id) {
                snprintf(id, sizeof id, "%.*s", (int)(e - b - 1), b + 1);
                if (skip_id(id))
                    return 0;
                snprintf(f->rule, sizeof f->rule, "cppcheck:%s", id);
            }
        }
    } else {
        sev = SEV_MED;
        conf = 1;
    }
    if (sev < 0)
        return 0;
    f->sev = sev;
    f->conf = conf;
    snprintf(f->msg, sizeof f->msg, "%s", msg);
    {
        size_t n = strlen(f->msg);
        if (t == EXT_CPPCHECK) {
            char *b = strrchr(f->msg, '[');
            if (b && b > f->msg)
                *(b - 1) = 0;
        }
        n = strlen(f->msg);
        while (n && (f->msg[n - 1] == ' ' || f->msg[n - 1] == '\r'))
            f->msg[--n] = 0;
    }
    return 1;
}

static int run_tool(int t, char **argv, const char *root, const char *rel, int tier, emit_fn emit, void *ctx, int *nf)
{
    char *out = NULL, *save = NULL, *ln;
    size_t olen = 0;
    int rc = ext_exec(argv, root, 120, &out, &olen), emitted = 0;

    if (rc < 0 || rc == 126 || rc == 127) {
        free(out);
        return 2;
    }
    if (out) {
        for (ln = strtok_r(out, "\n", &save); ln && emitted < 200; ln = strtok_r(NULL, "\n", &save)) {
            finding_t f;
            if (parse_line(t, ln, rel, tier, &f)) {
                emit(ctx, &f);
                emitted++;
            }
        }
    }
    *nf += emitted;
    free(out);
    return 1;
}

void ext_scan(const char *root, const char *rel, int tier, emit_fn emit, void *ctx, ext_res_t *res)
{
    char **kf = NULL, **argv;
    int nk = 0, loaded = 0, t, i, k;

    for (t = 0; t < EXT_N; t++) {
        if (!enabled[t])
            continue;
        if (t == EXT_SPARSE || t == EXT_SMATCH) {
            if (!loaded) {
                kf = load_flags(root, rel, &nk);
                loaded = 1;
            }
            if (!kf) {
                res->state[t] = 2;
                continue;
            }
            argv = calloc((size_t)nk + 10, sizeof *argv);
            k = 0;
            argv[k++] = (char *)NAMES[t];
            if (t == EXT_SPARSE) {
                argv[k++] = "-D__CHECKER__";
                argv[k++] = "-Wbitwise";
                argv[k++] = "-Wno-return-void";
                argv[k++] = "-Wno-unknown-attribute";
            } else {
                argv[k++] = "-p=kernel";
                argv[k++] = "-D__CHECKER__";
            }
            for (i = 0; i < nk; i++)
                argv[k++] = kf[i];
            argv[k++] = (char *)rel;
            argv[k] = NULL;
            res->state[t] = run_tool(t, argv, root, rel, tier, emit, ctx, &res->nf[t]);
            free(argv);
        } else if (t == EXT_CPPCHECK) {
            char *av[] = { "cppcheck", "--quiet", "--language=c", "--std=c11", "--max-configs=1", "--enable=warning",
                           "--inline-suppr", "--suppress=missingInclude", "--suppress=missingIncludeSystem",
                           "-D__KERNEL__", "--template={file}:{line}:{column}: {severity}: {message} [{id}]",
                           (char *)rel, NULL };
            res->state[t] = run_tool(t, av, root, rel, tier, emit, ctx, &res->nf[t]);
        } else {
            int ok = 1;
            if (tier > 1)
                continue;
            for (i = 0; i < ncocci; i++) {
                char *av[] = { "spatch", "-D", "report", "--very-quiet", "--no-show-diff", "--cocci-file", cocci[i],
                               (char *)rel, NULL };
                if (run_tool(t, av, root, rel, tier, emit, ctx, &res->nf[t]) != 1)
                    ok = 2;
            }
            res->state[t] = ok;
        }
    }
    if (kf)
        free_flags(kf, nk);
}

/* external analyzers run per file with the exact compile flags saved by kbuild in .name.o.cmd, so nothing in the tree is touched or rebuilt */
/* commands are executed without a shell, one argv per tool, with a cpu time limit and parent death signal on every child */
/* sparse and smatch need the .cmd flags, cppcheck runs on the single file with only -D__KERNEL__, spatch is opt in and only tier 0 and 1 */
/* findings are kept only when the reported path is the scanned file itself, header findings are not attributed to the .c file */
