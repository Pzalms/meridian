#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meridian.h"
#include "dump.h"

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static void print_usage(void)
{
    printf("usage: mdntool <command> <file>\n\n");
    printf("commands:\n");
    printf("  check <file>  parse file and verify integrity\n");
    printf("  run   <file>  parse and execute the policy engine\n");
    printf("  dump  <file>  parse and print all sections\n");
    printf("  help          show this message\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) {
        print_usage();
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: mdntool <check|run|dump|help> <file>\n");
        return 1;
    }
    const char *path = argv[2];

    size_t len = 0;
    uint8_t *buf = read_file(path, &len);
    if (!buf) {
        fprintf(stderr, "cannot read %s\n", path);
        return 1;
    }

    mdn_ctx_t *ctx = mdn_load(buf, len);
    free(buf);
    if (!ctx) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    if (strcmp(cmd, "dump") == 0) {
        dump_all(ctx);
    } else if (strcmp(cmd, "run") == 0) {
        int rc = mdn_run(ctx);
        printf("run: %s\n", rc == 0 ? "ok" : "error");
    } else if (strcmp(cmd, "check") == 0) {
        printf("valid\n");
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        mdn_free(ctx);
        return 1;
    }

    mdn_free(ctx);
    return 0;
}
