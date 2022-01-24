#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
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
    printf("          p/x $rip - %p\n", base);
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


    int (*does_stuff)(void *foobar, int32_t param2, char *chunk_name, char* chunk_data, int chunk_len)
        = base + 0xfe57c;

    /*
    struct foo {
        uint8_t        pad1[0x290];       // 0x000



        uint64_t       pad2;              // 0x000
        uint64_t       pad2;              // 0x008
        uint64_t       pad2;              // 0x010
        uint8_t        pad2[0x50 - 0x18]; // 0x018
        uint64_t       pad2;              // 0x050
        uint64_t       pad2[0x90 - 0x58]; // 0x058
        uint64_t       pad2;              // 0x090
        uint64_t       pad2[0xd0 - 0x98]; // 0x098
        uint64_t       pad2;              // 0x0d0
        uint64_t       pad2[0x110 - 0xd8]; // 0xd8


        uint64_t       pad2;              // 0x290
        uint64_t       thing;             // 0x298
        void*          thing1;            // 0x2a0
        uint64_t       pad3;              // 0x2a8
        uint64_t       pad4;              // 0x2b0
        uint64_t       pad5;              // 0x2b8
        uint64_t       pad6;              // 0x2c0
        void*          ptr1;              // 0x2c8
        struct venti*  ptr2;              // 0x2d0
        uint64_t       pad9;              // 0x2d8
        uint64_t       pad10;             // 0x2e0
        uint64_t       pad11;             // 0x2e8
        uint64_t       pad12;             // 0x2f0
        char**         new_buf;           // 0x2f8
        uint64_t       field_300;         // 0x300
    };

    assert(sizeof(struct venti) == 0x20);
    assert(sizeof(struct foo)   == 0x308);

    assert(offsetof(struct foo, pad1     ) == 0x000);
    assert(offsetof(struct foo, pad2     ) == 0x290);
    assert(offsetof(struct foo, thing    ) == 0x298);
    assert(offsetof(struct foo, thing1   ) == 0x2a0);
    assert(offsetof(struct foo, pad3     ) == 0x2a8);
    assert(offsetof(struct foo, pad4     ) == 0x2b0);
    assert(offsetof(struct foo, pad5     ) == 0x2b8);
    assert(offsetof(struct foo, pad6     ) == 0x2c0);
    assert(offsetof(struct foo, ptr1     ) == 0x2c8);
    assert(offsetof(struct foo, ptr2     ) == 0x2d0);
    assert(offsetof(struct foo, pad9     ) == 0x2d8);
    assert(offsetof(struct foo, pad10    ) == 0x2e0);
    assert(offsetof(struct foo, pad11    ) == 0x2e8);
    assert(offsetof(struct foo, pad12    ) == 0x2f0);
    assert(offsetof(struct foo, new_buf  ) == 0x2f8);
    assert(offsetof(struct foo, field_300) == 0x300);

*/

struct VFP_Boh {
    uint8_t _0x10; /* Created by retype action */
    uint8_t _pad_11[63];
};

struct VirusFirmwarePack {
    void* vtable;
    char* _0x8;
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

    uint8_t field12_0x290;
    uint8_t field13_0x291;
    uint8_t field14_0x292;
    uint8_t field15_0x293;
    uint8_t field16_0x294;
    uint8_t field17_0x295;
    uint8_t field18_0x296;
    uint8_t field19_0x297;
    uint32_t  _0x298;
    uint8_t field21_0x29c;
    uint8_t field22_0x29d;
    uint8_t field23_0x29e;
    uint8_t field24_0x29f;
    uint64_t _0x2a0;
    uint8_t * _0x2a8;
    uint8_t * _0x2b0;
    uint64_t _0x2b8;
    uint8_t field29_0x2c0;
    uint8_t field30_0x2c1;
    uint8_t field31_0x2c2;
    uint8_t field32_0x2c3;
    uint8_t field33_0x2c4;
    uint8_t field34_0x2c5;
    uint8_t field35_0x2c6;
    uint8_t field36_0x2c7;
    uint32_t _0x2c8;
    uint8_t field38_0x2cc;
    uint8_t field39_0x2cd;
    uint8_t field40_0x2ce;
    uint8_t field41_0x2cf;
    uint64_t _0x2d0;
    uint8_t * _0x2d8;
    uint8_t * _0x2e0;
    uint64_t _0x2e8;
    uint64_t _0x2f0;
    uint8_t * * _0x2f8;
    uint8_t * * _0x300;
};


    assert(sizeof(struct VirusFirmwarePack) == 0x308);

        uint64_t       pad2[0xd0 - 0x90]; // 0x098

    struct VirusFirmwarePack foobar;

    void (*VFP_Init)(struct VirusFirmwarePack*) = base + 0xfe06a;
    VFP_Init(&foobar);

    char x = does_stuff(&foobar, 2, "vti_2.bin", data, len);
    printf("%d\n", x);


    return 0;
}

