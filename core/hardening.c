#define _XOPEN_SOURCE 700
#include "common.h"
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { W_Y = 0, W_OFF, W_STR };

typedef struct {
    const char *name;
    int want;
    const char *str;
} hrule_t;

static const hrule_t rules[] = {
    { "STRICT_KERNEL_RWX", W_Y, 0 }, { "STRICT_MODULE_RWX", W_Y, 0 }, { "DEBUG_WX", W_Y, 0 },
    { "VMAP_STACK", W_Y, 0 }, { "RANDOMIZE_BASE", W_Y, 0 }, { "RANDOMIZE_MEMORY", W_Y, 0 },
    { "RANDOMIZE_KSTACK_OFFSET", W_Y, 0 }, { "RANDOMIZE_KSTACK_OFFSET_DEFAULT", W_Y, 0 },
    { "STACKPROTECTOR", W_Y, 0 }, { "STACKPROTECTOR_STRONG", W_Y, 0 }, { "HARDENED_USERCOPY", W_Y, 0 },
    { "HARDENED_USERCOPY_DEFAULT_ON", W_Y, 0 }, { "FORTIFY_SOURCE", W_Y, 0 },
    { "SLAB_FREELIST_RANDOM", W_Y, 0 }, { "SLAB_FREELIST_HARDENED", W_Y, 0 }, { "SLAB_BUCKETS", W_Y, 0 },
    { "SHUFFLE_PAGE_ALLOCATOR", W_Y, 0 }, { "INIT_ON_ALLOC_DEFAULT_ON", W_Y, 0 },
    { "INIT_ON_FREE_DEFAULT_ON", W_Y, 0 }, { "INIT_STACK_ALL_ZERO", W_Y, 0 }, { "ZERO_CALL_USED_REGS", W_Y, 0 },
    { "KSTACK_ERASE", W_Y, 0 }, { "GCC_PLUGIN_STACKLEAK", W_Y, 0 }, { "RANDSTRUCT_FULL", W_Y, 0 },
    { "SCHED_STACK_END_CHECK", W_Y, 0 }, { "PAGE_POISONING", W_Y, 0 }, { "KFENCE", W_Y, 0 },
    { "DEFAULT_MMAP_MIN_ADDR", W_STR, "65536" },
    { "BUG", W_Y, 0 }, { "BUG_ON_DATA_CORRUPTION", W_Y, 0 }, { "DEBUG_LIST", W_Y, 0 }, { "LIST_HARDENED", W_Y, 0 },
    { "DEBUG_SG", W_Y, 0 }, { "DEBUG_NOTIFIERS", W_Y, 0 }, { "DEBUG_CREDENTIALS", W_Y, 0 },
    { "PANIC_ON_OOPS", W_Y, 0 }, { "UBSAN_BOUNDS", W_Y, 0 }, { "UBSAN_TRAP", W_Y, 0 },
    { "UBSAN_LOCAL_BOUNDS", W_Y, 0 }, { "CFI", W_Y, 0 }, { "IA32_RUNTIME_GATE", W_Y, 0 }, { "GCC_PLUGINS", W_Y, 0 }, { "GCC_PLUGIN_LATENT_ENTROPY", W_Y, 0 }, { "UBSAN", W_Y, 0 },
    { "MITIGATION_PAGE_TABLE_ISOLATION", W_Y, 0 }, { "PAGE_TABLE_ISOLATION", W_Y, 0 },
    { "MITIGATION_RETPOLINE", W_Y, 0 }, { "RETPOLINE", W_Y, 0 }, { "MITIGATION_RETHUNK", W_Y, 0 },
    { "MITIGATION_SLS", W_Y, 0 }, { "MITIGATION_SPECTRE_BHI", W_Y, 0 }, { "MITIGATION_SRSO", W_Y, 0 },
    { "MITIGATION_UNRET_ENTRY", W_Y, 0 }, { "MITIGATION_IBPB_ENTRY", W_Y, 0 },
    { "MITIGATION_IBRS_ENTRY", W_Y, 0 }, { "MITIGATION_CALL_DEPTH_TRACKING", W_Y, 0 },
    { "MITIGATION_RFDS", W_Y, 0 }, { "MITIGATION_ITS", W_Y, 0 }, { "MITIGATION_SPECTRE_V2", W_Y, 0 },
    { "MITIGATION_MDS", W_Y, 0 }, { "X86_UMIP", W_Y, 0 }, { "X86_KERNEL_IBT", W_Y, 0 },
    { "X86_USER_SHADOW_STACK", W_Y, 0 }, { "CPU_MITIGATIONS", W_Y, 0 },
    { "INTEL_IOMMU", W_Y, 0 }, { "INTEL_IOMMU_DEFAULT_ON", W_Y, 0 }, { "AMD_IOMMU", W_Y, 0 },
    { "IOMMU_DEFAULT_DMA_STRICT", W_Y, 0 }, { "EFI_DISABLE_PCI_DMA", W_Y, 0 },
    { "RESET_ATTACK_MITIGATION", W_Y, 0 }, { "EFI_SECRET", W_OFF, 0 },
    { "SECURITY", W_Y, 0 }, { "SECURITY_YAMA", W_Y, 0 }, { "SECURITY_DMESG_RESTRICT", W_Y, 0 },
    { "SECURITY_LOCKDOWN_LSM", W_Y, 0 }, { "SECURITY_LOCKDOWN_LSM_EARLY", W_Y, 0 },
    { "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY", W_Y, 0 }, { "SECURITY_LANDLOCK", W_Y, 0 },
    { "SECURITY_SAFESETID", W_Y, 0 }, { "SECURITY_LOADPIN", W_Y, 0 }, { "SECURITY_NETWORK", W_Y, 0 },
    { "SECURITY_PATH", W_Y, 0 }, { "SECCOMP", W_Y, 0 }, { "SECCOMP_FILTER", W_Y, 0 },
    { "BPF_JIT_ALWAYS_ON", W_Y, 0 }, { "BPF_UNPRIV_DEFAULT_OFF", W_Y, 0 }, { "STRICT_DEVMEM", W_Y, 0 },
    { "IO_STRICT_DEVMEM", W_Y, 0 }, { "LEGACY_VSYSCALL_NONE", W_Y, 0 },
    { "MODULE_SIG", W_Y, 0 }, { "MODULE_SIG_FORCE", W_Y, 0 }, { "MODULE_SIG_ALL", W_Y, 0 },
    { "MODULE_SIG_HASH", W_STR, "\"sha512\"" }, { "MODULE_SIG_PROTECT", W_Y, 0 },
    { "DEVMEM", W_OFF, 0 }, { "DEVKMEM", W_OFF, 0 }, { "DEVPORT", W_OFF, 0 }, { "PROC_KCORE", W_OFF, 0 },
    { "PROC_VMCORE", W_OFF, 0 }, { "PROC_PAGE_MONITOR", W_OFF, 0 }, { "KEXEC", W_OFF, 0 },
    { "KEXEC_FILE", W_OFF, 0 }, { "CRASH_DUMP", W_OFF, 0 }, { "HIBERNATION", W_OFF, 0 },
    { "MODIFY_LDT_SYSCALL", W_OFF, 0 }, { "X86_VSYSCALL_EMULATION", W_OFF, 0 },
    { "LEGACY_VSYSCALL_EMULATE", W_OFF, 0 }, { "LEGACY_VSYSCALL_XONLY", W_OFF, 0 },
    { "COMPAT_BRK", W_OFF, 0 }, { "COMPAT_VDSO", W_OFF, 0 }, { "IA32_EMULATION", W_OFF, 0 },
    { "X86_X32_ABI", W_OFF, 0 }, { "X86_IOPL_IOPERM", W_OFF, 0 }, { "X86_MSR", W_OFF, 0 },
    { "KPROBES", W_OFF, 0 }, { "UPROBES", W_OFF, 0 }, { "KGDB", W_OFF, 0 }, { "LIVEPATCH", W_OFF, 0 },
    { "USERFAULTFD", W_OFF, 0 }, { "LDISC_AUTOLOAD", W_OFF, 0 }, { "LEGACY_PTYS", W_OFF, 0 },
    { "ACPI_CUSTOM_METHOD", W_OFF, 0 }, { "ACPI_TABLE_UPGRADE", W_OFF, 0 }, { "ACPI_APEI_EINJ", W_OFF, 0 },
    { "DEBUG_FS", W_OFF, 0 }, { "MAGIC_SYSRQ", W_OFF, 0 }, { "SLAB_MERGE_DEFAULT", W_OFF, 0 },
    { "INET_DIAG", W_OFF, 0 }, { "KSM", W_OFF, 0 }, { "FW_LOADER_USER_HELPER", W_OFF, 0 },
    { "EFI_TEST", W_OFF, 0 }, { "NOTIFIER_ERROR_INJECTION", W_OFF, 0 }, { "FAULT_INJECTION", W_OFF, 0 },
    { "HWPOISON_INJECT", W_OFF, 0 }, { "DRM_LEGACY", W_OFF, 0 }, { "SECURITY_SELINUX_DEVELOP", W_OFF, 0 },
    { "IO_URING", W_OFF, 0 }, { "KCOV", W_OFF, 0 }, { "PROFILING", W_OFF, 0 },
    { "STATIC_USERMODEHELPER", W_Y, 0 }, { "RANDOM_KMALLOC_CACHES", W_Y, 0 }, { "STACKPROTECTOR_PER_TASK", W_Y, 0 },
    { "TRIM_UNUSED_KSYMS", W_Y, 0 }, { "PAGE_TABLE_CHECK", W_Y, 0 }, { "PAGE_TABLE_CHECK_ENFORCED", W_Y, 0 },
    { "DEBUG_VIRTUAL", W_Y, 0 }, { "SLUB_DEBUG", W_Y, 0 }, { "SYN_COOKIES", W_Y, 0 },
    { "X86_INTEL_TSX_MODE_OFF", W_Y, 0 }, { "MITIGATION_SSB", W_Y, 0 }, { "MITIGATION_L1TF", W_Y, 0 },
    { "MITIGATION_GDS", W_Y, 0 }, { "MITIGATION_TSA", W_Y, 0 }, { "MITIGATION_VMSCAPE", W_Y, 0 },
    { "LOCK_DOWN_IN_EFI_SECURE_BOOT", W_Y, 0 },
    { "SECURITY_SELINUX_BOOTPARAM", W_OFF, 0 }, { "SECURITY_SELINUX_DISABLE", W_OFF, 0 }, { "SECURITY_WRITABLE_HOOKS", W_OFF, 0 },
    { "BINFMT_MISC", W_OFF, 0 }, { "COREDUMP", W_OFF, 0 }, { "X86_PTDUMP", W_OFF, 0 },
    { "PTDUMP_DEBUGFS", W_OFF, 0 }, { "MMIOTRACE", W_OFF, 0 }, { "DEBUG_KMEMLEAK", W_OFF, 0 },
    { "FTRACE", W_OFF, 0 }, { "FUNCTION_TRACER", W_OFF, 0 },
    { "BLK_DEV_IO_TRACE", W_OFF, 0 }, { "BPF_SYSCALL", W_OFF, 0 }, { "BPF_EVENTS", W_OFF, 0 },
    { "KALLSYMS_ALL", W_OFF, 0 }, { "CFI_PERMISSIVE", W_OFF, 0 }, { "X86_CPUID", W_OFF, 0 },
    { "X86_MCE_INJECT", W_OFF, 0 }, { "X86_16BIT", W_OFF, 0 }, { "ACPI_DEBUGGER", W_OFF, 0 },
    { "ACPI_DEBUG", W_OFF, 0 }, { "KEXEC_JUMP", W_OFF, 0 }, { "MEM_SOFT_DIRTY", W_OFF, 0 },
    { "COMPAT", W_OFF, 0 }, { "INPUT_EVBUG", W_OFF, 0 }, { "DEBUG_BOOT_PARAMS", W_OFF, 0 },
    { "DEBUG_TLBFLUSH", W_OFF, 0 }, { "MODULE_FORCE_LOAD", W_OFF, 0 }, { "MODULE_FORCE_UNLOAD", W_OFF, 0 },
    { "UEVENT_HELPER", W_OFF, 0 }, { "KSTACK_ERASE_METRICS", W_OFF, 0 }, { "DEBUG_ENTRY", W_OFF, 0 },
    { "X86_DEBUG_FPU", W_OFF, 0 }, { "EFI_PGT_DUMP", W_OFF, 0 },
    { "KSTACK_ERASE_RUNTIME_DISABLE", W_OFF, 0 },
};
#define NRULES (sizeof rules / sizeof rules[0])

typedef struct {
    const char *name;
    const char *ctl;
    const char *ctlval;
} ctl_t;

static const ctl_t ctls[] = {
    { "DEBUG_FS", "DEBUG_FS_ALLOW_NONE", "y" },
    { "BPF_SYSCALL", "BPF_UNPRIV_DEFAULT_OFF", "y" },
    { "X86_VSYSCALL_EMULATION", "LEGACY_VSYSCALL_NONE", "y" },
    { "MAGIC_SYSRQ", "MAGIC_SYSRQ_DEFAULT_ENABLE", "0x0" },
    { "IA32_EMULATION", "IA32_EMULATION_DEFAULT_DISABLED", "y" },
    { "IA32_EMULATION", "IA32_RUNTIME_GATE", "y" },
    { "COMPAT", "IA32_RUNTIME_GATE", "y" },
    { "MODIFY_LDT_SYSCALL", "IA32_RUNTIME_GATE", "y" },
};
#define NCTLS (sizeof ctls / sizeof ctls[0])

typedef struct {
    int defined;
    char file[PATH_MAX];
    int line;
    int cfg_line;
    int constrained;
    char val[256];
} hstate_t;

static hstate_t st[NRULES];
static size_t g_rootlen;
static char g_skiparch[32][32];
static int g_nskip;

static int sym_index(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < NRULES; i++)
        if (strlen(rules[i].name) == n && !strncmp(rules[i].name, s, n))
            return (int)i;
    return -1;
}

static int skip_arch_path(const char *rel)
{
    int i;
    if (strncmp(rel, "arch/", 5))
        return 0;
    for (i = 0; i < g_nskip; i++) {
        size_t l = strlen(g_skiparch[i]);
        if (!strncmp(rel + 5, g_skiparch[i], l) && (rel[5 + l] == '/' || !rel[5 + l]))
            return 1;
    }
    return 0;
}

static int kvisit(const char *p, const struct stat *sb, int flag, struct FTW *ftw)
{
    const char *base = p + ftw->base, *rel = p + g_rootlen + 1;
    FILE *fp;
    char line[512];
    int ln = 0;

    (void)sb;
    if (flag == FTW_D || flag == FTW_DNR) {
        if (ftw->level && (!strcmp(base, ".git") || !strcmp(base, "Documentation") || !strcmp(base, "tools")))
            return FTW_SKIP_SUBTREE;
        if (ftw->level && skip_arch_path(rel))
            return FTW_SKIP_SUBTREE;
        return FTW_CONTINUE;
    }
    if (flag != FTW_F || strncmp(base, "Kconfig", 7))
        return FTW_CONTINUE;
    fp = fopen(p, "r");
    if (!fp)
        return FTW_CONTINUE;
    while (fgets(line, sizeof line, fp)) {
        const char *s = line;
        int idx;
        size_t n;
        ln++;
        if (!strncmp(s, "config ", 7))
            s += 7;
        else if (!strncmp(s, "menuconfig ", 11))
            s += 11;
        else
            continue;
        n = strcspn(s, " \t\r\n");
        idx = sym_index(s, n);
        if (idx >= 0 && !st[idx].defined) {
            st[idx].defined = 1;
            snprintf(st[idx].file, sizeof st[idx].file, "%s", rel);
            st[idx].line = ln;
        }
    }
    fclose(fp);
    return FTW_CONTINUE;
}

static int load_config(const char *path, size_t *nopts)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    int ln = 0;

    if (!fp)
        return 0;
    *nopts = 0;
    while (fgets(line, sizeof line, fp)) {
        char *s = line, *eq;
        int idx;
        size_t n;
        ln++;
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(s, "# CONFIG_", 9)) {
            s += 9;
            n = strcspn(s, " ");
            idx = sym_index(s, n);
            if (idx >= 0) {
                st[idx].cfg_line = ln;
                st[idx].val[0] = 0;
            }
            continue;
        }
        if (strncmp(s, "CONFIG_", 7))
            continue;
        (*nopts)++;
        s += 7;
        eq = strchr(s, '=');
        if (!eq)
            continue;
        idx = sym_index(s, (size_t)(eq - s));
        if (idx >= 0) {
            st[idx].cfg_line = ln;
            snprintf(st[idx].val, sizeof st[idx].val, "%s", eq + 1);
        }
    }
    fclose(fp);
    return 1;
}

static int cfg_has(const char *path, const char *key)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    size_t kl = strlen(key);
    int r = 0;
    if (!fp)
        return 0;
    while (fgets(line, sizeof line, fp))
        if (!strncmp(line, key, kl) && line[kl] == '=' && line[kl + 1] == 'y') {
            r = 1;
            break;
        }
    fclose(fp);
    return r;
}

static int g_order[4096];
static const char *g_gtitle[4] = {
    "explicitly not set in .config (line present, wrong value)",
    "set to the wrong value in .config",
    "absent from .config (never selected, or a dependency or compiler requirement is unmet)",
    "present (the surface remains, the default is locked down or gated at runtime)"
};

static int group_of(size_t i)
{
    if (st[i].constrained)
        return 3;
    if (!st[i].cfg_line)
        return 2;
    return st[i].val[0] ? 1 : 0;
}

static int cmp_bad(const void *a, const void *b)
{
    size_t x = (size_t)*(const int *)a, y = (size_t)*(const int *)b;
    int gx = group_of(x), gy = group_of(y);
    if (gx != gy)
        return gx - gy;
    return strcmp(rules[x].name, rules[y].name);
}

static void print_one(size_t i, const char *cshow)
{
    const char *v = st[i].val;
    if (st[i].cfg_line)
        printf("  CONFIG_%-40s %-10s %s:%d  defined %s:%d\n", rules[i].name, v[0] ? v : "not set", cshow,
               st[i].cfg_line, st[i].file, st[i].line);
    else
        printf("  CONFIG_%-40s %-10s %s:-  defined %s:%d\n", rules[i].name, "not set", cshow, st[i].file,
               st[i].line);
}

static int cfg_val_is(const char *path, const char *key, const char *want)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    size_t kl = strlen(key) + 7;
    int r = 0;
    if (!fp)
        return 0;
    while (fgets(line, sizeof line, fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "CONFIG_", 7) && !strncmp(line + 7, key, strlen(key)) && line[kl] == '=')
            r = !strcmp(line + kl + 1, want);
    }
    fclose(fp);
    return r;
}

/* an option that cannot exist (or is meaningless) because its parent is off counts as satisfied */
typedef struct {
    const char *name;
    const char *parent;
} waive_t;

static const waive_t waives[] = {
    { "STRICT_DEVMEM", "DEVMEM" }, { "IO_STRICT_DEVMEM", "DEVMEM" },
    { "BPF_JIT_ALWAYS_ON", "BPF_SYSCALL" }, { "BPF_UNPRIV_DEFAULT_OFF", "BPF_SYSCALL" },
    { "LEGACY_VSYSCALL_NONE", "X86_VSYSCALL_EMULATION" },
};
#define NWAIVES (sizeof waives / sizeof waives[0])

static int cfg_is_off(const char *path, const char *key)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    size_t kl = strlen(key) + 7;
    int off = 1;
    if (!fp)
        return 0;
    while (fgets(line, sizeof line, fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "CONFIG_", 7) && !strncmp(line + 7, key, strlen(key)) && line[kl] == '=')
            off = !strcmp(line + kl + 1, "n");
    }
    fclose(fp);
    return off;
}

int hardening_scan(const char *root, const char *ver, const char *cfgpath)
{
    char cfg[PATH_MAX];
    size_t nopts = 0, i, checked = 0, bad = 0, gcount[4] = { 0, 0, 0, 0 };
    const char *cshow;
    int g;

    g_rootlen = strlen(root);
    if (cfgpath && *cfgpath)
        snprintf(cfg, sizeof cfg, "%s", cfgpath);
    else
        snprintf(cfg, sizeof cfg, "%s/.config", root);
    if (!load_config(cfg, &nopts)) {
        fprintf(stderr, "hardening: cannot read %s\n", cfg);
        return 1;
    }
    {
        static const char *all[] = { "alpha", "arc", "arm", "arm64", "csky", "hexagon", "loongarch", "m68k",
                                     "microblaze", "mips", "nios2", "openrisc", "parisc", "powerpc", "riscv",
                                     "s390", "sh", "sparc", "um", "x86", "xtensa" };
        const char *mine = cfg_has(cfg, "CONFIG_X86") ? "x86" : cfg_has(cfg, "CONFIG_ARM64") ? "arm64"
                         : cfg_has(cfg, "CONFIG_ARM") ? "arm" : cfg_has(cfg, "CONFIG_RISCV") ? "riscv" : NULL;
        size_t k;
        g_nskip = 0;
        if (mine)
            for (k = 0; k < sizeof all / sizeof all[0]; k++)
                if (strcmp(all[k], mine) && g_nskip < 32)
                    snprintf(g_skiparch[g_nskip++], sizeof g_skiparch[0], "%s", all[k]);
    }
    nftw(root, kvisit, 32, FTW_ACTIONRETVAL | FTW_PHYS);

    cshow = !strncmp(cfg, root, g_rootlen) && cfg[g_rootlen] == '/' ? cfg + g_rootlen + 1 : cfg;
    printf("hardening: kernel %s, %s, %zu options set, %zu rules\n", ver, cshow, nopts, NRULES);
    for (i = 0; i < NRULES; i++) {
        const hrule_t *r = &rules[i];
        const char *v = st[i].val;
        int ok;

        if (!st[i].defined)
            continue;
        checked++;
        if (r->want == W_Y)
            ok = !strcmp(v, "y");
        else if (r->want == W_OFF)
            ok = !v[0] || !strcmp(v, "n");
        else
            ok = !strcmp(v, r->str);
        if (!ok) {
            size_t w;
            for (w = 0; w < NWAIVES; w++)
                if (!strcmp(waives[w].name, r->name) && cfg_is_off(cfg, waives[w].parent))
                    ok = 1;
        }
        if (ok)
            continue;
        if (st[i].cfg_line && v[0]) {
            size_t c;
            for (c = 0; c < NCTLS; c++)
                if (!strcmp(ctls[c].name, r->name) && (!strcmp(ctls[c].ctlval, "off") ? cfg_is_off(cfg, ctls[c].ctl) : cfg_val_is(cfg, ctls[c].ctl, ctls[c].ctlval)))
                    st[i].constrained = 1;
        }
        g_order[bad++] = (int)i;
        gcount[group_of(i)]++;
    }
    qsort(g_order, bad, sizeof g_order[0], cmp_bad);
    for (g = 0; g < 4; g++) {
        size_t k;
        if (!gcount[g])
            continue;
        printf("\n[%s] %zu\n", g_gtitle[g], gcount[g]);
        for (k = 0; k < bad; k++)
            if (group_of((size_t)g_order[k]) == g)
                print_one((size_t)g_order[k], cshow);
    }
    printf("\nhardening: %zu of %zu applicable options are not at max hardening, %zu more are constrained\n",
           bad - gcount[3], checked, gcount[3]);
    return bad - gcount[3] ? 4 : 0;
}

/* a rule only counts when the option has a Kconfig definition in this tree for this architecture, so renamed or removed options never show up as false findings */
/* the report gives the option, its current state, the line in .config and the Kconfig file and line that defines it, it never says what to change it to */
/* findings are grouped by how the option appears in .config, then sorted by name, and groups only describe state, never a fix */
/* rules that name an option with no Kconfig definition for this tree and architecture are skipped silently, so extra rule names for other versions are harmless */
/* a constrained option still counts as present attack surface, it is listed apart and does not set the exit code */
