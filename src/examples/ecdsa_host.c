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
    uint32_t dpu_debug = 0xAA;
    uint32_t dpu_val1 = 0xAA;
    uint32_t dpu_val2 = 0xAA;
    uint32_t dpu_val3 = 0xAA;
    uint32_t dpu_val4 = 0xAA;
    uint32_t dpu_cycles = 0xAA;
    uint32_t clock_per_sec = 0xAA;

    DPU_ASSERT(dpu_alloc(1, NULL, &set));
    DPU_ASSERT(dpu_load(set, DPU_BINARY, NULL));
    DPU_ASSERT(dpu_launch(set, DPU_SYNCHRONOUS));

    DPU_FOREACH (set, dpu) {
#ifdef GEN_BY_SW
        DPU_ASSERT(dpu_log_read(dpu, stdout));
#endif
        DPU_ASSERT(dpu_copy_from(dpu, "ret", 0, (uint8_t *)&dpu_ret, sizeof(dpu_ret)));
        DPU_ASSERT(dpu_copy_from(dpu, "dpu_debug", 0, (uint8_t *)&dpu_debug, sizeof(dpu_debug)));
        DPU_ASSERT(dpu_copy_from(dpu, "dpu_val1", 0, (uint8_t *)&dpu_val1, sizeof(dpu_val1)));
        DPU_ASSERT(dpu_copy_from(dpu, "dpu_val2", 0, (uint8_t *)&dpu_val2, sizeof(dpu_val2)));
        DPU_ASSERT(dpu_copy_from(dpu, "dpu_val3", 0, (uint8_t *)&dpu_val3, sizeof(dpu_val3)));
        DPU_ASSERT(dpu_copy_from(dpu, "dpu_val4", 0, (uint8_t *)&dpu_val4, sizeof(dpu_val4)));
        DPU_ASSERT(dpu_copy_from(dpu, "cycles", 0, (uint8_t *)&dpu_cycles, sizeof(dpu_cycles)));
        DPU_ASSERT(dpu_copy_from(dpu, "clock_per_sec", 0, (uint8_t *)&clock_per_sec, sizeof(clock_per_sec)));


        printf("ret value %d\n", dpu_ret);
        printf("debug value 0x%x\n", dpu_debug);
        printf("dpu_val1 0x%x\n", dpu_val1);
        printf("dpu_val2 0x%x\n", dpu_val2);
        printf("dpu_val3 0x%x\n", dpu_val3);
        printf("dpu_val4 0x%x\n", dpu_val4);
        printf("dpu_cycles %u\n", dpu_cycles);
        printf("clock_per_sec %u\n", clock_per_sec);
        printf("dpu_msec %u\n", dpu_cycles/(clock_per_sec/1000));

    }

    DPU_ASSERT(dpu_free(set));

    return 0;
}