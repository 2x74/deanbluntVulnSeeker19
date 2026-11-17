#ifndef DBVF_GOV_H
#define DBVF_GOV_H
#include <stdint.h>

typedef struct {
    uint32_t cpu_pct;
    uint32_t mem_pct;
    uint32_t target;
    uint32_t throttled;
    uint32_t psi_mem_x100;
} gov_out_t;

void *gov_new(uint32_t cpu_cap, uint32_t mem_cap);
void gov_poll(void *g, uint32_t total, gov_out_t *out);
void gov_free(void *g);

#endif
