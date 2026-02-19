/* Local fuzzer driver — not used in build.sh */
#include <stdio.h>
#include <stdlib.h>
#include "meridian.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz <= 0) { fclose(f); continue; }
        uint8_t *buf = malloc((size_t)sz);
        if (!buf) { fclose(f); continue; }
        fread(buf, 1, (size_t)sz, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, (size_t)sz);
        free(buf);
    }
    return 0;
}
