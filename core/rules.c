#include "common.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    const char *name;
    int sev;
    const char *msg;
    int kind;
} rule_t;

enum { K_CALL = 0, K_ALLOC = 1 };

static const rule_t RULES[] = {
    { "gets", SEV_HIGH, "gets() cannot bound its input", K_CALL },
    { "strcpy", SEV_MED, "strcpy() is unbounded, prefer strscpy()", K_CALL },
    { "strcat", SEV_MED, "strcat() is unbounded, prefer strlcat() or scnprintf()", K_CALL },
    { "sprintf", SEV_MED, "sprintf() is unbounded, prefer scnprintf()", K_CALL },
    { "vsprintf", SEV_MED, "vsprintf() is unbounded, prefer vscnprintf()", K_CALL },
    { "strncpy", SEV_LOW, "strncpy() may leave the buffer unterminated, prefer strscpy()", K_CALL },
    { "strlcpy", SEV_INFO, "strlcpy() reads the whole source, prefer strscpy()", K_CALL },
    { "simple_strtol", SEV_LOW, "no error checking, prefer kstrtol()", K_CALL },
    { "simple_strtoul", SEV_LOW, "no error checking, prefer kstrtoul()", K_CALL },
    { "simple_strtoll", SEV_LOW, "no error checking, prefer kstrtoll()", K_CALL },
    { "simple_strtoull", SEV_LOW, "no error checking, prefer kstrtoull()", K_CALL },
    { "__copy_from_user", SEV_LOW, "unchecked user copy, caller must have called access_ok()", K_CALL },
    { "__copy_to_user", SEV_LOW, "unchecked user copy, caller must have called access_ok()", K_CALL },
    { "__get_user", SEV_LOW, "unchecked user access, caller must have called access_ok()", K_CALL },
    { "__put_user", SEV_LOW, "unchecked user access, caller must have called access_ok()", K_CALL },
    { "kmalloc", SEV_MED, "multiplication in allocation size, prefer kmalloc_array()", K_ALLOC },
    { "kzalloc", SEV_MED, "multiplication in allocation size, prefer kcalloc()", K_ALLOC },
    { "vmalloc", SEV_MED, "multiplication in allocation size, prefer vmalloc_array()", K_ALLOC },
    { "vzalloc", SEV_MED, "multiplication in allocation size, prefer vcalloc()", K_ALLOC },
    { "kvmalloc", SEV_MED, "multiplication in allocation size, prefer kvmalloc_array()", K_ALLOC },
    { "kvzalloc", SEV_MED, "multiplication in allocation size, prefer kvcalloc()", K_ALLOC },
};
#define NRULES (sizeof RULES / sizeof RULES[0])

static uint32_t pfx[NRULES];
static size_t npfx;

typedef struct {
    size_t lpos;
    int line;
} lc_t;

size_t rules_count(void)
{
    return NRULES;
}

const char *rules_name(size_t i)
{
    return i < NRULES ? RULES[i].name : "";
}

const char *sev_name(int s)
{
    static const char *n[] = { "critical", "high", "medium", "low", "info" };
    return (s >= 0 && s < SEV_N) ? n[s] : "?";
}

static void init_pfx(void)
{
    size_t i, j;

    if (npfx)
        return;
    for (i = 0; i < NRULES; i++) {
        uint32_t v;
        memcpy(&v, RULES[i].name, 4);
        for (j = 0; j < npfx; j++)
            if (pfx[j] == v)
                break;
        if (j == npfx)
            pfx[npfx++] = v;
    }
}

static int isident(int c)
{
    return isalnum(c) || c == '_';
}

static size_t line_start(const uint8_t *buf, size_t j)
{
    while (j > 0 && buf[j - 1] != '\n')
        j--;
    return j;
}

static size_t line_end(const uint8_t *buf, size_t len, size_t j)
{
    while (j < len && buf[j] != '\n')
        j++;
    return j;
}

static int skip_context(const uint8_t *buf, size_t ls, size_t j)
{
    size_t k = ls, m;
    int instr = 0;

    while (k < j && (buf[k] == ' ' || buf[k] == '\t'))
        k++;
    if (k < j) {
        if (buf[k] == '#')
            return 1;
        if (buf[k] == '*' && k + 1 < j && (buf[k + 1] == ' ' || buf[k + 1] == '/'))
            return 1;
    }
    for (k = ls; k < j; k++) {
        int c = buf[k];
        if (instr) {
            if (c == '\\')
                k++;
            else if (c == instr)
                instr = 0;
            continue;
        }
        if (c == '"' || c == '\'') {
            instr = c;
            continue;
        }
        if (c == '/' && k + 1 < j && buf[k + 1] == '/')
            return 1;
        if (c == '/' && k + 1 < j && buf[k + 1] == '*') {
            int closed = 0;
            for (m = k + 2; m + 1 < j; m++) {
                if (buf[m] == '*' && buf[m + 1] == '/') {
                    closed = 1;
                    break;
                }
            }
            if (!closed)
                return 1;
            k = m + 1;
        }
    }
    return instr != 0;
}

static const rule_t *match_at(const uint8_t *buf, size_t len, size_t j, size_t *argpos)
{
    size_t i;

    if (j > 0 && isident(buf[j - 1]))
        return NULL;
    for (i = 0; i < NRULES; i++) {
        size_t n = strlen(RULES[i].name), e;
        if (j + n > len || memcmp(buf + j, RULES[i].name, n))
            continue;
        e = j + n;
        if (e < len && isident(buf[e]))
            continue;
        while (e < len && (buf[e] == ' ' || buf[e] == '\t'))
            e++;
        if (e >= len || buf[e] != '(')
            continue;
        *argpos = e + 1;
        return &RULES[i];
    }
    return NULL;
}

static int alloc_multiplies(const uint8_t *buf, size_t len, size_t p)
{
    int depth = 0, last = '(';

    for (; p < len && buf[p] != '\n'; p++) {
        int c = buf[p];
        if (c == ' ' || c == '\t')
            continue;
        if (c == '(') {
            depth++;
        } else if (c == ')') {
            if (depth == 0)
                return 0;
            depth--;
        } else if (c == ',' && depth == 0) {
            return 0;
        } else if (c == '*' && depth == 0 && (isident(last) || last == ')')) {
            return 1;
        }
        last = c;
    }
    return 0;
}

static int line_of(const uint8_t *buf, size_t j, lc_t *lc)
{
    while (lc->lpos < j) {
        const uint8_t *nl = memchr(buf + lc->lpos, '\n', j - lc->lpos);
        if (!nl) {
            lc->lpos = j;
            break;
        }
        lc->line++;
        lc->lpos = (size_t)(nl - buf) + 1;
    }
    return lc->line;
}

static void check_pos(const uint8_t *buf, size_t len, size_t j, int tier, emit_fn emit, void *ctx, lc_t *lc)
{
    size_t ap = 0, ls, le, k, n, i;
    const rule_t *r = match_at(buf, len, j, &ap);
    finding_t f;

    if (!r)
        return;
    ls = line_start(buf, j);
    if (skip_context(buf, ls, j))
        return;
    if (r->kind == K_ALLOC && !alloc_multiplies(buf, len, ap))
        return;
    memset(&f, 0, sizeof f);
    f.sev = r->sev;
    f.conf = r->sev == SEV_HIGH;
    if (tier == 0 && (f.sev == SEV_MED || f.sev == SEV_LOW))
        f.sev--;
    f.tier = tier;
    f.line = line_of(buf, j, lc);
    snprintf(f.rule, sizeof f.rule, "%s", r->name);
    snprintf(f.msg, sizeof f.msg, "%s", r->msg);
    le = line_end(buf, len, j);
    k = ls;
    while (k < le && (buf[k] == ' ' || buf[k] == '\t'))
        k++;
    n = le - k;
    if (n > sizeof f.snippet - 1)
        n = sizeof f.snippet - 1;
    for (i = 0; i < n; i++) {
        unsigned char c = buf[k + i];
        f.snippet[i] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    emit(ctx, &f);
}

int rules_scan(const char *path, int tier, emit_fn emit, void *ctx, size_t *bytes_out)
{
    int fd;
    struct stat st;
    const uint8_t *buf;
    size_t len, off = 0, j;
    lc_t lc = { 0, 1 };

    init_pfx();
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size == 0 || st.st_size > (off_t)(32 << 20)) {
        close(fd);
        return -1;
    }
    len = (size_t)st.st_size;
    buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (buf == MAP_FAILED)
        return -1;

    while (off < len) {
        size_t rem = len - off;
        size_t lim = rem >= 19 ? ((rem - 19) / 16 + 1) * 16 : 0;
        size_t r = dbvf_prefilter(buf + off, rem, pfx, npfx);
        size_t end;
        if (r >= lim) {
            for (j = off + lim; j < len; j++)
                check_pos(buf, len, j, tier, emit, ctx, &lc);
            break;
        }
        end = off + r + 16;
        if (end > len)
            end = len;
        for (j = off + r; j < end; j++)
            check_pos(buf, len, j, tier, emit, ctx, &lc);
        off = end;
    }
    munmap((void *)buf, len);
    if (bytes_out)
        *bytes_out = len;
    return 0;
}

/* the asm prefilter returns the first 16 byte block holding the first four bytes of any rule name, c then checks those 16 positions exactly */
/* exact checks need an identifier boundary on both sides and an open paren, and skip comment lines, preprocessor lines and string literals */
/* allocation rule only fires on a top level multiplication in the first argument, sizeof(*p) and casts are inside parens so they are ignored */
/* these are pattern matches, a hit is a place to read and a miss proves nothing */
