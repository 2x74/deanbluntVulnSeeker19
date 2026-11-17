#include "common.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int preflight_kernel(const char *root, char *ver, size_t vlen)
{
    static const char *dirs[] = { "kernel", "mm", "arch", "security", "fs", "drivers" };
    char p[PATH_MAX], v[3][16] = { "", "", "" };
    struct stat st;
    FILE *fp;
    char line[256];
    size_t i;

    for (i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", root, dirs[i]);
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
            return 0;
    }
    snprintf(p, sizeof p, "%s/Kconfig", root);
    if (stat(p, &st) != 0)
        return 0;
    snprintf(p, sizeof p, "%s/Makefile", root);
    fp = fopen(p, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof line, fp)) {
        if (!strncmp(line, "VERSION", 7))
            sscanf(line, "VERSION = %15s", v[0]);
        else if (!strncmp(line, "PATCHLEVEL", 10))
            sscanf(line, "PATCHLEVEL = %15s", v[1]);
        else if (!strncmp(line, "SUBLEVEL", 8))
            sscanf(line, "SUBLEVEL = %15s", v[2]);
        if (v[0][0] && v[1][0] && v[2][0])
            break;
    }
    fclose(fp);
    if (!v[0][0] || !v[1][0])
        return 0;
    snprintf(ver, vlen, "%s.%s.%s", v[0], v[1], v[2][0] ? v[2] : "0");
    return 1;
}

int tier_of(const char *p)
{
    static const char *t0[] = { "security/", "kernel/", "mm/", "io_uring/", "fs/exec.c", "ipc/" };
    static const char *t1[] = { "net/", "fs/", "crypto/", "block/", "lib/", "arch/x86/" };
    static const char *t2[] = { "drivers/usb/", "drivers/net/", "drivers/gpu/drm/amd/", "sound/",
                                "drivers/bluetooth/", "drivers/input/" };
    size_t i;

    for (i = 0; i < sizeof t0 / sizeof t0[0]; i++)
        if (!strncmp(p, t0[i], strlen(t0[i])))
            return 0;
    for (i = 0; i < sizeof t1 / sizeof t1[0]; i++)
        if (!strncmp(p, t1[i], strlen(t1[i])))
            return 1;
    for (i = 0; i < sizeof t2 / sizeof t2[0]; i++)
        if (!strncmp(p, t2[i], strlen(t2[i])))
            return 2;
    return 3;
}

/* a tree counts as a kernel when it has kernel/ mm/ arch/ security/ fs/ drivers/, a Kconfig and a Makefile with VERSION and PATCHLEVEL */
/* tiers are path prefixes, tier 0 is code where one bug is root, tier 3 is everything else */
