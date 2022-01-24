#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <signal.h>

#include <string>
#include <vector>


uint8_t* open_virus_lib() {
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

    return (uint8_t*)info.dli_fbase;
}

uint8_t *read_file(char *path, int* len) {
    FILE *file = fopen(path, "r");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);

    if ((*len = ftell(file)) == -1) {
        perror("ftell");
        return NULL;
    }

    uint8_t *data = (uint8_t*)malloc(*len);

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


int write_file(char *path, void *chunk_data, int chunk_len) {
    FILE *out = fopen(path, "w");
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

struct astruct_4 {
    char* field0_0x0;
    char* field8_0x8;
    struct astruct_6 * astr_6;
    int32_t * ptr1;
    int32_t * ptr2;
    long field16_0x28;
};

struct VFP_Boh {
    uint8_t _0x10; /* Created by retype action */
    uint8_t _pad_11[63];
};

struct VirusFirmwarePack {
    char ** vtable;
    char * _0x8_dynamic_array;
    struct VFP_Boh field2_0x10;
    struct VFP_Boh _0x50; /* Created by retype action */
    struct VFP_Boh _0x90; /* Created by retype action */
    struct VFP_Boh _0xd0; /* Created by retype action */
    struct VFP_Boh _0x110; /* Created by retype action */
    struct VFP_Boh _0x150; /* Created by retype action */
    struct VFP_Boh _0x190; /* Created by retype action */
    struct VFP_Boh _0x1d0; /* Created by retype action */
    struct VFP_Boh _0x210; /* Created by retype action */
    struct VFP_Boh _0x250; /* Created by retype action */
    char* field12_0x290;
    char* field20_0x298;
    char* field25_0x2a0;
    char* ptr1;
    char* ptr2;
    char* field28_0x2b8;
    struct astruct_4 astr_4;
    std::vector<uint8_t*> chunks;
};

struct astruct_6 {
    uint8_t field0_0x0;
    uint8_t field1_0x1;
    uint8_t field2_0x2;
    uint8_t field3_0x3;
    uint8_t field4_0x4;
    uint8_t field5_0x5;
    uint8_t field6_0x6;
    uint8_t field7_0x7;
    uint8_t field8_0x8;
    uint8_t field9_0x9;
    uint8_t field10_0xa;
    uint8_t field11_0xb;
    uint8_t field12_0xc;
    uint8_t field13_0xd;
    uint8_t field14_0xe;
    uint8_t field15_0xf;
    struct astruct_6 * astr6_ptr1;
    struct astruct_6 * astr6_ptr2;
    std::string string;
};

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: %s <chunked_file.bin> <out_dir>\n", argv[0]);
        return -1;
    }

    char *filename = argv[1];
    char *outname  = argv[2];

    uint8_t *base = open_virus_lib();

    if (!base) {
        printf("cannot open viruscontrol library\n");
        return -1;
    }

    printf("lib base: %p\n", base);
    printf("filename: %s\n", filename);
    printf("out dir:  %s\n", outname);

    /* - */

    void (*chunker_init)(uint8_t *chunker, uint8_t *buffer, int len)
        = (void (*)(uint8_t *, uint8_t *, int))(base + 0x10244c);

    int (*chunker_chunk_count)(uint8_t *chunker)
        = (int (*)(uint8_t *))(base + 0x1024fe);

    int (*chunker_get_data)(uint8_t *chunker, char **name, uint8_t **data, int idx)
        = (int (*)(uint8_t *, char **, uint8_t **, int))(base + 0x102488);

    /* - */

    void (*VFP_Init)(struct VirusFirmwarePack*)
        = (void(*)(struct VirusFirmwarePack*))(base + 0xfe06a);

    int (*does_stuff)(struct VirusFirmwarePack *foobar, int32_t param2, char *chunk_name, uint8_t* chunk_data, int chunk_len)
        = (int(*)(struct VirusFirmwarePack*, int32_t, char*, uint8_t*, int))(base + 0xfe57c);

    /* - */

    int   len  = 0;
    uint8_t *data = read_file(filename, &len);

    if (!data) {
        printf("cannot read input file\n");
        return -1;
    }

    uint8_t chunker[0x100];
    struct VirusFirmwarePack foobar;

    chunker_init(&chunker[0], data, len);
    VFP_Init(&foobar);

    bool success = does_stuff(&foobar, 2, "vti_2.bin", data, len);

    assert(success);
    assert(chunker_chunk_count(&chunker[0]) == foobar.chunks.size());

    for (int i = 0; i < foobar.chunks.size(); i++) {
        char *chunk_name;
        uint8_t *chunk_plain_data;
        uint8_t *chunk_decoded_data;

        uint8_t *chunk_data = foobar.chunks[i];
        int chunk_plain_len = chunker_get_data(&chunker[0], &chunk_name, &chunk_plain_data, i);

        int boh =
            (chunk_name[0] == 'F' || chunk_name[0] == 'P') ? -0x1450 : 
             chunk_name[0] == 'S'                          ? -0x14d0 :
                                                             -0x14d1 ;
        int id
            = (chunk_name[1] * 100) 
            + (chunk_name[2] *  10)
            + (chunk_name[3]      )
            + (boh                );

        printf("chunk %03d - %03d - %s\n", i, id, chunk_name);

        char path[0x500];
        snprintf(path, sizeof(path), "%s/plain-%s.bin", outname, chunk_name);

        if (write_file(path, chunk_data, chunk_plain_len)) {
            printf("cannot write file\n");
            return -1;
        }

        snprintf(path, sizeof(path), "%s/decoded-%s.bin", outname, chunk_name);

        if (write_file(path, chunk_data, 0x8000)) {
            printf("cannot write file\n");
            return -1;
        }
    }

    return 0;
}

