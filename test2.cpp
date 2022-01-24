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

extern uint8_t * BASE;

uint8_t * BASE = (uint8_t*)0x1212121212121212;

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

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef struct VirusFirmwarePack VirusFirmwarePack, *PVirusFirmwarePack;

typedef struct VFP_Boh VFP_Boh, *PVFP_Boh;

typedef int int32_t;

typedef longlong int64_t;

typedef struct astruct_4 astruct_4, *Pastruct_4;

typedef uchar uint8_t;

typedef struct astruct_6 astruct_6, *Pastruct_6;

struct astruct_4 {
    char* field0_0x0;
    char* field8_0x8;
    struct astruct_6 * astr_6;
    int32_t * ptr1;
    int32_t * ptr2;
    long field16_0x28;
};

struct VFP_Boh {
    byte _0x10; /* Created by retype action */
    byte _pad_11[63];
};

struct VirusFirmwarePack {
    undefined * * vtable;
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
    char * field20_0x298;
    char*  field25_0x2a0;
    char * ptr1;
    char * ptr2;
    char*  field28_0x2b8;
    struct astruct_4 astr_4;
    std::vector<uint8_t*> chunks;
};

struct astruct_6 {
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
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
    printf("          p/x $rip - %p\n", base);
    printf("          br set -a %p -C \"p *(char**)$rsi\" -C \"p/x $eax\" \n", (base + 0xfe5fd));
    printf("          br set -a %p -C \"p/x $r13\" \n", (base + 0xfe71b));
    printf("filename: %s\n", filename);
    printf("out dir:  %s\n", outname);
    printf("astr6:    %d\n", sizeof(astruct_6));

    //assert(sizeof(astruct_6) == 48);

    BASE = base;

    int   len  = 0;
    uint8_t *data = read_file(filename, &len);

    if (!data) {
        printf("cannot read input file\n");
        return -1;
    }

    printf("file len: %8d [%08x]\n", len, len);

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
    assert(sizeof(struct VirusFirmwarePack) == 0x308);

    struct VirusFirmwarePack foobar;

    void (*VFP_Init)(struct VirusFirmwarePack*)
        = (void(*)(struct VirusFirmwarePack*))(base + 0xfe06a);

    VFP_Init(&foobar);

    // raise(SIGINT);

    void (*chunker_init)(uint8_t *chunker, uint8_t *buffer, int len)
        = (void (*)(uint8_t *, uint8_t *, int))(base + 0x10244c);

    int (*chunker_chunk_count)(uint8_t *chunker)
        = (int (*)(uint8_t *))(base + 0x1024fe);

    int (*chunker_get_data)(uint8_t *chunker, char **name, uint8_t **data, int idx)
        = (int (*)(uint8_t *, char **, uint8_t **, int))(base + 0x102488);

    uint8_t chunker[0x100];


    int (*does_stuff)(struct VirusFirmwarePack *foobar, int32_t param2, char *chunk_name, uint8_t* chunk_data, int chunk_len)
        = (int(*)(struct VirusFirmwarePack*, int32_t, char*, uint8_t*, int))(base + 0xfe57c);

    char x = does_stuff(&foobar, 2, "vti_2.bin", data, len);
    printf("%d\n", x);

    chunker_init(&chunker[0], data, len);

    assert(chunker_chunk_count(&chunker[0]) == foobar.chunks.size());

    for (int i = 0; i < foobar.chunks.size(); i++) {
        char *chunk_name;
        uint8_t *chunk_plain_data;
        uint8_t *chunk_decoded_data;

        uint8_t *chunk_data = foobar.chunks[0];
        chunker_get_data(&chunker[0], &chunk_name, &chunk_plain_data, i);

        int boh =
            (chunk_name[0] == 'F' || chunk_name[0] == 'P') ? -0x1450 : 
            chunk_name[0] == 'S'                           ? -0x14d0 :
                                                             -0x14d1 ;

        int id
            = (chunk_name[1] * 100) 
            + (chunk_name[2] *  10)
            + (chunk_name[3]      )
            + (boh                );

        char path[0x500];
        snprintf(path, sizeof(path), "%s/%s.bin", outname, chunk_name);

        printf("chunk %03d - %03d - %s\n", i, id, chunk_name);

        FILE *out = fopen(path, "w");
        fwrite(chunk_data, 0x8000, 1, out);
        fclose(out);
    }

    return 0;
}

