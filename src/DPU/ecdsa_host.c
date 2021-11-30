#include <assert.h>
#include <stdio.h>

#include <dpu.h>
#include <dpu_log.h>

#ifndef DPU_BINARY
#define DPU_BINARY "./ecdsa_dpu"
#endif

int
main(void)
{
    struct dpu_set_t set, dpu;
    int dpu_ret = 0xff;
#ifndef GEN_BY_SW
    uint32_t dpu_cycles = 0xAA;
    uint32_t clock_per_sec = 0xAA;
#endif

    DPU_ASSERT(dpu_alloc(1, NULL, &set));
    DPU_ASSERT(dpu_load(set, DPU_BINARY, NULL));
    DPU_ASSERT(dpu_launch(set, DPU_SYNCHRONOUS));

    DPU_FOREACH (set, dpu) {
#ifdef GEN_BY_SW
        DPU_ASSERT(dpu_log_read(dpu, stdout));
#endif
        DPU_ASSERT(dpu_copy_from(dpu, "ret", 0, (uint8_t *)&dpu_ret, sizeof(dpu_ret)));
        printf("ret value %d\n", dpu_ret);
#ifndef GEN_BY_SW
        DPU_ASSERT(dpu_copy_from(dpu, "cycles", 0, (uint8_t *)&dpu_cycles, sizeof(dpu_cycles)));
        DPU_ASSERT(dpu_copy_from(dpu, "clock_per_sec", 0, (uint8_t *)&clock_per_sec, sizeof(clock_per_sec)));
        printf("dpu_cycles %u\n", dpu_cycles);
        printf("clock_per_sec %u\n", clock_per_sec);
        printf("dpu_msec %u\n", dpu_cycles/(clock_per_sec/1000));
#endif
    }

    DPU_ASSERT(dpu_free(set));

    return 0;
}