#!/bin/bash

# Usage: ./func.sh source_file.c function_name1 function_name2 ... output_file.c

# Arguments
SOURCE_FILE=$1
shift
OUTPUT_FILE=${!#}  # Last argument is the output file
FUNCTION_NAMES=("$@") # Get all arguments from 2nd to the last
unset 'FUNCTION_NAMES[${#FUNCTION_NAMES[@]}-1]' # Remove the last argument

# Validate arguments
if [ -z "$SOURCE_FILE" ] || [ ! -f "$SOURCE_FILE" ]; then
  echo "Usage: $0 source_file.c function_name1 function_name2 ... output_file.c"
  exit 1
fi

# Ensure the output file is empty or create it if it doesn't exist
: > "$OUTPUT_FILE"

# Harcoded headers
echo "#include <asm/fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include \"cpu.h\"
" >> "$OUTPUT_FILE"

# Extract #define CPUID_CACHE_SIZE from SOURCE_FILE
awk '
  $0 ~ "^#define CPUID_CACHE_SIZE" {
    print
  }
' "$SOURCE_FILE" >> "$OUTPUT_FILE"

# Extract #define IS_IN_RANGE_INCL from api.h and replace false with 0 and true with 1
awk '
  $0 ~ "^#define IS_IN_RANGE_INCL" {
    gsub("false", "0")
    gsub("true", "1")
    print
  }
' "./common/include/api.h" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract g_cpu_extension_offsets and g_cpu_extension_sizes from enclave_xstate.c
awk '
  BEGIN { in_cpu_extension_offsets = 0; in_cpu_extension_sizes = 0 }

  $0 ~ "^const uint32_t g_cpu_extension_offsets" {
    in_cpu_extension_offsets = 1
  }

  $0 ~ "^const uint32_t g_cpu_extension_sizes" {
    in_cpu_extension_sizes = 1
  }

  in_cpu_extension_offsets {
    print
    if ($0 ~ "}") {
      in_cpu_extension_offsets = 0
      print ""
    }
  }

  in_cpu_extension_sizes {
    print
    if ($0 ~ "}") {
      in_cpu_extension_sizes = 0
      print ""
    }
  }

' "./pal/src/host/linux-sgx/enclave_xstate.c" >> "$OUTPUT_FILE"

# Extract static int g_pal_cpuid_cache_top from pal_misc.c
awk '
  $0 ~ "^static int g_pal_cpuid_cache_top" {
    print
  }
' "$SOURCE_FILE" >> "$OUTPUT_FILE"

# Extract struct pal_cpuid, static variable from pal_misc.c
awk '
  BEGIN { in_struct = 0 }

  $0 ~ "^static struct pal_cpuid" {
    in_struct = 1
  }

  in_struct {
    print
    if ($0 ~ "}") {
      in_struct = 0
      print ""
    }
  }

  END {
    if (in_struct) {
      print "Error: Could not find the end of struct pal_cpuid" > "/dev/stderr"
    }
  }
' "$SOURCE_FILE" >> "$OUTPUT_FILE"

# Extract static inline extension_enabled
# static inline uint32_t extension_enabled(uint32_t xfrm, uint32_t bit_idx) {
#     uint32_t feature_bit = 1U << bit_idx;
#     return xfrm & feature_bit;
# }
awk '
  BEGIN { in_func = 0 }

  $0 ~ "^static inline uint32_t extension_enabled" {
    in_func = 1
  }

  in_func {
    print
    if ($0 ~ "}") {
      in_func = 0
      print ""
    }
  }

' "$SOURCE_FILE" >> "$OUTPUT_FILE"

# Process each function name
for FUNCTION_NAME in "${FUNCTION_NAMES[@]}"; do
  echo "Extracting function '$FUNCTION_NAME' from '$SOURCE_FILE' into '$OUTPUT_FILE'"

  awk -v func_name="$FUNCTION_NAME" '
    BEGIN { in_func = 0; brace_count = 0; function_started = 0 }

    # Match the function definition line
    $0 ~ "^.*" func_name "\\s*\\(" {
      if (!function_started) {
        in_func = 1
        brace_count = 0
        function_started = 1
      }
    }

    # If inside the function, start copying lines
    in_func {
      # Skip spinlock functions
      if ($0 ~ "spinlock") {
        next
      }
      # skip empty lines
      if ($0 ~ "^\\s*$") next
      print

      # Count braces
      if ($0 ~ "\\{") brace_count++
      if ($0 ~ "\\}") brace_count--
      if (brace_count == 0 && $0 ~ "\\}") {
        in_func = 0
        print ""
      }
    }

    # Handle case where function is not found
    END {
      if (function_started == 0) {
        print "Function not found or function is empty" > "/dev/stderr"
      }
    }
  ' "$SOURCE_FILE" >> "$OUTPUT_FILE"
done

# Harcoded LLVMFuzzerTestOneInput function for libfuzzer
echo "int LLVMFuzzerTestOneInput(const uint32_t *Data, long long Size) {
    uint32_t leaf = 11, subleaf = 4;
    uint32_t values[4];
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

   sanitize_cpuid(leaf, subleaf, values);
   add_cpuid_to_cache(leaf, subleaf, values);
   ret = get_cpuid_from_cache(leaf, subleaf, values);

    return 0;
}" >> "$OUTPUT_FILE"

# Replace some values with constants
sed -i -e 's/g_pal_linuxsgx_state.enclave_info.attributes.xfrm/231; \/\/ This value is constant 231 on Linux ubuntu/g' \
  -e 's/g_extended_feature_flags_max_supported_sub_leaves/2; \/\/ This value is constant 2 on Linux ubuntu/g' \
  -e 's/_PalProcessExit(1)/return/g' \
  -e 's/log_error/printf/g' \
  -e 's/PAL_ERROR_DENIED/6/g' "$OUTPUT_FILE"

echo "All functions have been copied to '$OUTPUT_FILE'"
