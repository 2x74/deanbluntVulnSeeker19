#ifndef DBVF_COMMON_H
#define DBVF_COMMON_H
#include <stddef.h>
#include <stdint.h>

enum { SEV_CRIT = 0, SEV_HIGH, SEV_MED, SEV_LOW, SEV_INFO, SEV_N };
enum { EXT_SPARSE = 0, EXT_SMATCH, EXT_CPPCHECK, EXT_SPATCH, EXT_N };

typedef struct {
    int sev;
    int tier;
    int line;
    int conf;
    char rule[32];
    char msg[160];
    char snippet[200];
} finding_t;

typedef struct {
    int state[EXT_N];
    int nf[EXT_N];
} ext_res_t;

typedef struct {
    size_t total, ver_hits, compiled_hits, git_fixed, findings;
    int ok;
} cve_stats_t;

typedef void (*emit_fn)(void *ctx, const finding_t *f);
typedef void (*cve_emit_fn)(void *ctx, size_t fileidx, const finding_t *f);

size_t dbvf_prefilter(const uint8_t *buf, size_t len, const uint32_t *pfx, size_t npfx);
int rules_scan(const char *path, int tier, emit_fn emit, void *ctx, size_t *bytes_out);
size_t rules_count(void);
const char *rules_name(size_t i);
const char *sev_name(int sev);
int preflight_kernel(const char *root, char *ver, size_t vlen);
int tier_of(const char *relpath);
int hardening_scan(const char *root, const char *ver, const char *cfgpath);

void ext_init(const char *root, int use_cocci, int disabled);
const char *ext_name(int t);
int ext_found(int t);
int ext_enabled(int t);
void ext_scan(const char *root, const char *rel, int tier, emit_fn emit, void *ctx, ext_res_t *res);
int ext_exec(char *const argv[], const char *cwd, unsigned cpu_secs, char **out, size_t *outlen);

int cve_scan(const char *vdir, const char *root, const char *ver, char **files, size_t n, cve_emit_fn emit, void *ctx,
             cve_stats_t *st);

#endif
