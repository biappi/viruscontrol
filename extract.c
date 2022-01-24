#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>

void* open_virus_lib() {
    void *h = dlopen("viruscontrol-mod.dylib", RTLD_LAZY);

    if (!h) {
        perror(dlerror());
        return NULL;
    }

    void *func = dlsym(h, "main_macho");
    if (!func) {
        perror(dlerror());
        return NULL;
    }

    Dl_info info;
    if (!dladdr(func, &info)) {
        perror(dlerror());
        return NULL;
    }

    return info.dli_fbase;
}


void *read_file(char *path, int* len) {
    FILE *file = fopen(path, "r");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);

    if ((*len = ftell(file)) == -1) {
        perror("ftell");
        return NULL;
    }

    void *data = malloc(*len);

    if (fseek(file, 0, SEEK_SET) == -1) {
        perror("fseek");
        return NULL;
    }

    if (fread(data, *len, 1, file) != 1) {
        perror("fread");
        return NULL;
    }

    fclose(file);
    return data;
}


int write_chunk(char* outname, char* chunk_name, void *chunk_data, int chunk_len) {
    char out_path[0x512];
    snprintf(out_path, sizeof(out_path), "%s/%s.bin", outname, chunk_name);

    FILE *out = fopen(out_path, "w");
    if (!out) {
        perror("fopen");
        return -1;
    }

    if (fwrite(chunk_data, chunk_len, 1, out) != 1) {
        perror("fwrite");
        return -1;
    }

    fclose(out);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: %s <chunked_file.bin> <out_dir>\n", argv[0]);
        return -1;
    }

    char *filename = argv[1];
    char *outname  = argv[2];

    void *base = open_virus_lib();

    if (!base) {
        printf("cannot open viruscontrol library\n");
        return -1;
    }

    printf("lib base: %p\n", base);
    printf("filename: %s\n", filename);
    printf("out dir:  %s\n", outname);

    int   len  = 0;
    void *data = read_file(filename, &len);

    if (!data) {
        printf("cannot read input file\n");
        return -1;
    }

    void (*chunker_init)(void *chunker, uint8_t *buffer, int len)
        = base + 0x10244c;

    int (*chunker_chunk_count)(void *chunker)
        = base + 0x1024fe;

    int (*chunker_get_data)(void *chunker, char **name, void **data, int idx)
        = base + 0x102488;

    uint8_t chunker[0x100];

    printf("file len: %8d [%08x]\n", len, len);

    chunker_init(&chunker, data, len);

    int count = chunker_chunk_count(&chunker);
    printf("chunks:   %d\n", count);
    printf("\n");

    for (int i = 0; i < count; i++) {
        char *chunk_name = 0;
        void *chunk_data = 0;
        int   chunk_len  = chunker_get_data(&chunker, &chunk_name, &chunk_data, i);

        printf("writing chunk %3d '%s', size = %8d [%08x]\n", i, chunk_name, chunk_len, chunk_len);
        if (write_chunk(outname, chunk_name, chunk_data, chunk_len)) {
            printf("cannot write chunk file\n");
            return -1;
        }
    }

    return 0;
}
