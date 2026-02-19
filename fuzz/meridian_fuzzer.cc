#include <cstdint>
#include <cstdlib>

extern "C" int mdn_fuzz(const uint8_t *data, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mdn_fuzz(data, size);
    return 0;
}
