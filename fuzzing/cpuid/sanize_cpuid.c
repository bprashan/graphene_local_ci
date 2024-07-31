#include <asm/fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "cpu.h"
#include <time.h>
#include <stdbool.h>

#define IS_IN_RANGE_INCL(value, start, end) (((value) < (start) || (value) > (end)) ? 0 : 1)

int64_t  non_null_edx = 0;
int64_t  ex_state_enum_leaf_error = 0;
int64_t  tile_info_subleaf_0x0_error = 0;
int64_t  tile_info_subleaf_error = 0;
int64_t  tmul_info_leaf_error = 0;
int64_t  cpu_sanitized = 0;
int16_t is_cpuid_present = 0;
int16_t add_cpuid_cache = 0;
int64_t  get_cpuid_cache = 0;
time_t start, end;
bool start_timer;
double elapsed = 0.0;


const uint32_t g_cpu_extension_sizes[] = {
    [AVX] = 256,
    [MPX_BNDREGS] = 64, [MPX_BNDCSR] = 64,
    [AVX512_OPMASK] = 64, [AVX512_ZMM256] = 512, [AVX512_ZMM512] = 1024,
    [PKRU] = 8,
    [AMX_TILECFG] = 64, [AMX_TILEDATA] = 8192,
};

const uint32_t g_cpu_extension_offsets[] = {
    [AVX] = 576,
    [MPX_BNDREGS] = 960, [MPX_BNDCSR] = 1024,
    [AVX512_OPMASK] = 1088, [AVX512_ZMM256] = 1152, [AVX512_ZMM512] = 1664,
    [PKRU] = 2688,
    [AMX_TILECFG] = 2752, [AMX_TILEDATA] = 2816,
};

static int g_pal_cpuid_cache_top = 0;
#define CPUID_CACHE_SIZE 64 /* cache only 64 distinct CPUID entries; sufficient for most apps */
static struct pal_cpuid {
    unsigned int leaf, subleaf;
    unsigned int values[4];
} g_pal_cpuid_cache[CPUID_CACHE_SIZE];

static int get_cpuid_from_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    int ret = -1;
    for (int i = 0; i < g_pal_cpuid_cache_top; i++) {
        if (g_pal_cpuid_cache[i].leaf == leaf && g_pal_cpuid_cache[i].subleaf == subleaf) {
            values[0] = g_pal_cpuid_cache[i].values[0];
            values[1] = g_pal_cpuid_cache[i].values[1];
            values[2] = g_pal_cpuid_cache[i].values[2];
            values[3] = g_pal_cpuid_cache[i].values[3];
            ret = 0;
            get_cpuid_cache++;
            break;
        }
    }
    return ret;
}

static void add_cpuid_to_cache(unsigned int leaf, unsigned int subleaf, unsigned int values[4]) {
    struct pal_cpuid* chosen = NULL;
    if (g_pal_cpuid_cache_top < CPUID_CACHE_SIZE) {
        for (int i = 0; i < g_pal_cpuid_cache_top; i++) {
            if (g_pal_cpuid_cache[i].leaf == leaf && g_pal_cpuid_cache[i].subleaf == subleaf) {
                /* this CPUID entry is already present in the cache, no need to add */
                is_cpuid_present++;
                break;
            }
        }
        chosen = &g_pal_cpuid_cache[g_pal_cpuid_cache_top++];
    }

    if (chosen) {
        chosen->leaf      = leaf;
        chosen->subleaf   = subleaf;
        chosen->values[0] = values[0];
        chosen->values[1] = values[1];
        chosen->values[2] = values[2];
        chosen->values[3] = values[3];
        add_cpuid_cache++;
    }

}

static inline uint32_t extension_enabled(uint32_t xfrm, uint32_t bit_idx) {
    uint32_t feature_bit = 1U << bit_idx;
    return xfrm & feature_bit;
}

void sanitize_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t values[static 4]) {
    uint64_t xfrm = 231; //-----------------g_pal_linuxsgx_state.enclave_info.attributes.xfrm;

    if (leaf == CPU_VENDOR_LEAF) {
        /* hardcode the only possible values for SGX PAL */
        values[CPUID_WORD_EBX] = 0x756e6547; /* 'Genu' */
        values[CPUID_WORD_EDX] = 0x49656e69; /* 'ineI' */
        values[CPUID_WORD_ECX] = 0x6c65746e; /* 'ntel' */
    } else if (leaf == FEATURE_FLAGS_LEAF) {
        /* We have to enforce these feature bits, otherwise some crypto libraries (e.g. mbedtls)
         * silently switch to side-channel-prone software implementations of crypto algorithms.
         *
         * On hosts which really don't support these, the untrusted PAL should emit an error and
         * refuse to start.
         */
        values[CPUID_WORD_ECX] |= 1 << 25; // AESNI
        values[CPUID_WORD_ECX] |= 1 << 26; // XSAVE (this one is for Gramine code, it relies on it)
        values[CPUID_WORD_ECX] |= 1 << 30; // RDRAND
    } else if (leaf == EXTENDED_FEATURE_FLAGS_LEAF) {
        if (subleaf == 0x0) {
            values[CPUID_WORD_EAX] = 2;//-----------------g_extended_feature_flags_max_supported_sub_leaves;
            values[CPUID_WORD_EBX] |= 1U << 0; /* CPUs with SGX always support FSGSBASE */
            values[CPUID_WORD_EBX] |= 1U << 2; /* CPUs with SGX always report the SGX bit */
        }
    } else if (leaf == EXTENDED_STATE_LEAF) {
        switch (subleaf) {
            case X87:
                /* From the SDM: "EDX:EAX is a bitmap of all the user state components that can be
                 * managed using the XSAVE feature set. A bit can be set in XCR0 if and only if the
                 * corresponding bit is set in this bitmap. Every processor that supports the XSAVE
                 * feature set will set EAX[0] (x87 state) and EAX[1] (SSE state)."
                 *
                 * On EENTER/ERESUME, the system installs xfrm into XCR0. Hence, we return xfrm here
                 * in EAX.
                 */
                values[CPUID_WORD_EAX] = xfrm;

                /* From the SDM: "EBX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components
                 * corresponding to bits currently set in XCR0."
                 */
                uint32_t xsave_size = 0;
                /* Start from AVX since x87 and SSE are always captured using XSAVE. Also, x87 and
                 * SSE state size is implicitly included in the extension's offset, e.g., AVX's
                 * offset is 576 which includes x87 and SSE state as well as the XSAVE header. */
                for (int i = AVX; i < LAST_CPU_EXTENSION; i++) {
                    if (extension_enabled(xfrm, i)) {
                        xsave_size = g_cpu_extension_offsets[i] + g_cpu_extension_sizes[i];
                    }
                }
                values[CPUID_WORD_EBX] = xsave_size;

                /* From the SDM: "ECX enumerates the size (in bytes) required by the XSAVE
                 * instruction for an XSAVE area containing all the user state components supported
                 * by this processor."
                 *
                 * We are assuming here that inside the enclave, ECX and EBX for leaf 0xD and
                 * subleaf 0x1 should always be identical, while outside they can potentially be
                 * different. Also, outside of SGX EBX can change at runtime, while ECX is a static
                 * property.
                 */
                values[CPUID_WORD_ECX] = values[CPUID_WORD_EBX];
                values[CPUID_WORD_EDX] = 0;

                break;
            case SSE: {
                const uint32_t xsave_legacy_size = 512;
                const uint32_t xsave_header = 64;
                uint32_t save_size_bytes = xsave_legacy_size + xsave_header;

                /* Start with AVX, since x87 and SSE state is already included when initializing
                 * `save_size_bytes`. */
                for (int i = AVX; i < LAST_CPU_EXTENSION; i++) {
                    if (extension_enabled(xfrm, i)) {
                        save_size_bytes += g_cpu_extension_sizes[i];
                    }
                }
                /* EBX reports the actual size occupied by those extensions irrespective of their
                 * offsets within the xsave area.
                 */
                values[CPUID_WORD_EBX] = save_size_bytes;

                break;
            }
            case AVX:
            case MPX_BNDREGS:
            case MPX_BNDCSR:
            case AVX512_OPMASK:
            case AVX512_ZMM256:
            case AVX512_ZMM512:
            case PKRU:
            case AMX_TILECFG:
            case AMX_TILEDATA:
                /*
                 * Sanitize ECX:
                 *   - bit 0 is always clear because all features are user state (in XCR0)
                 *   - bit 1 is always set because all features are located on 64B boundary
                 *   - bit 2 is set only for AMX_TILEDATA (support for XFD faulting)
                 *   - bits 3-31 are reserved and are zeros
                 */
                values[CPUID_WORD_ECX] = 0x2;
                if (subleaf == AMX_TILEDATA)
                    values[CPUID_WORD_ECX] |= 0x4;

                if (values[CPUID_WORD_EDX] != 0) {
                    non_null_edx++;
                    return;
                }

                if (extension_enabled(xfrm, subleaf)) {
                    if (values[CPUID_WORD_EAX] != g_cpu_extension_sizes[subleaf] ||
                            values[CPUID_WORD_EBX] != g_cpu_extension_offsets[subleaf]) {
                        ex_state_enum_leaf_error++;
                        return;
                    }
                } else {
                    /* SGX enclave doesn't use this CPU extension, pretend it doesn't exist by
                     * forcing EAX ("size in bytes of the save area for an extended state feature")
                     * and EBX ("offset in bytes of this extended state component's save area from
                     * the beginning of the XSAVE/XRSTOR area") to zero */
                    values[CPUID_WORD_EAX] = 0;
                    values[CPUID_WORD_EBX] = 0;
                }
                break;
        }
    } else if (leaf == AMX_TILE_INFO_LEAF) {
        if (subleaf == 0x0) {
            /* EAX = 1DH, ECX = 0: special subleaf, returns EAX=max_palette, EBX=ECX=EDX=0 */
            if (!IS_IN_RANGE_INCL(values[CPUID_WORD_EAX], 1, 16) || values[CPUID_WORD_EBX] != 0
                    || values[CPUID_WORD_ECX] != 0 || values[CPUID_WORD_EDX] != 0) {
                tile_info_subleaf_0x0_error++;
                return;
            }
        } else {
            /* EAX = 1DH, ECX > 0: subleaf for each supported palette, returns palette limits */
            uint32_t total_tile_bytes = values[CPUID_WORD_EAX] & 0xFFFF;
            uint32_t bytes_per_tile = values[CPUID_WORD_EAX] >> 16;
            uint32_t bytes_per_row = values[CPUID_WORD_EBX] & 0xFFFF;
            uint32_t max_names = values[CPUID_WORD_EBX] >> 16; /* (# of tile regs) */
            uint32_t max_rows = values[CPUID_WORD_ECX] & 0xFFFF;
            if (!IS_IN_RANGE_INCL(total_tile_bytes, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(bytes_per_tile, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(bytes_per_row, 1, 0xFFFF)
                    || !IS_IN_RANGE_INCL(max_names, 1, 256)
                    || !IS_IN_RANGE_INCL(max_rows, 1, 256)
                    || (values[CPUID_WORD_ECX] >> 16) != 0 || values[CPUID_WORD_EDX] != 0) {
                tile_info_subleaf_error++;
                return;
            }
        }
    } else if (leaf == AMX_TMUL_INFO_LEAF) {
        /* EAX = 1EH, ECX = 0: returns TMUL hardware unit limits */
        uint32_t tmul_maxk = values[CPUID_WORD_EBX] & 0xFF; /* (rows or columns) */
        uint32_t tmul_maxn = (values[CPUID_WORD_EBX] >> 8) & 0xFFFF;
        if (!IS_IN_RANGE_INCL(tmul_maxk, 1, 0xFF)
                || !IS_IN_RANGE_INCL(tmul_maxn, 1, 0xFFFF)
                || (values[CPUID_WORD_EBX] >> 24) != 0
                || values[CPUID_WORD_EAX] != 0
                || values[CPUID_WORD_ECX] != 0
                || values[CPUID_WORD_EDX] != 0) {
            tmul_info_leaf_error++;
            return;
        }
    }
    cpu_sanitized++;
}

int LLVMFuzzerTestOneInput(const uint32_t *Data, long long Size) {
    uint32_t leaf = 11, subleaf = 4;
    uint32_t values[4];
    //uint32_t temp = values[4];
    int len = Size/sizeof(uint32_t);
    int ret = -1;
    if(Size < 24 || Data == NULL || len < 6) {
        return 0;
    }
    values[0] = Data[0];
    values[1] = Data[1];
    values[2] = Data[2];
    values[3] = Data[3];
    leaf = Data[4];
    subleaf = Data[5];

//    printf("values[0] = 0x%x values[1] = 0x%x values[2] = 0x%x values[3] = 0x%x leaf = 0x%x subleaf = 0x%x\n",
  //  values[0], values[1], values[2], values[3], leaf, subleaf);

   sanitize_cpuid(leaf, subleaf, values);
   add_cpuid_to_cache(leaf, subleaf, values);
   ret = get_cpuid_from_cache(leaf, subleaf, values);
    if (!start_timer){
        time(&start); /* start the timer */
        start_timer = true;
    }
    time(&end);
    elapsed = difftime(end, start);
    if (elapsed >= 1200.0)
        {
               printf("Non-null EDX value in Processor Extended State Enum CPUID leaf hits : %ld\n", non_null_edx);
               printf("Unexpected values in Processor Extended State Enum CPUID leaf hits : %ld\n", ex_state_enum_leaf_error);
               printf("Tile Information CPUID Leaf (subleaf=0x0) error hits : %ld\n", tile_info_subleaf_0x0_error);
               printf("Tile Information CPUID Leaf (subleaf) error hits : %ld\n", tile_info_subleaf_error);
               printf("TMUL Information CPUID Leaf error hits : %ld\n", tmul_info_leaf_error);
               printf("cpuid sanitized hits : %ld\n", cpu_sanitized);
               printf("cpuid is already present hits : %hd\n", is_cpuid_present);
               printf("Added cpuid to the cache hits : %hd\n", add_cpuid_cache);
               printf("Got cpuid from cache hits : %ld\n", get_cpuid_cache);
               time(&start);
        }


   // printf("cpuid is santized\n");
    return 0;
}
