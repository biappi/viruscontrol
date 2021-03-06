#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>

struct AEffect;

typedef void* (*AEffectDispatcherProc) (struct AEffect* effect, int32_t opcode, int32_t index, void* value, void* ptr, float opt);
typedef void (*AEffectProcessProc) (struct AEffect* effect, float** inputs, float** outputs, int32_t sampleFrames);
typedef void (*AEffectProcessDoubleProc) (struct AEffect* effect, double** inputs, double** outputs, int32_t sampleFrames);
typedef void (*AEffectSetParameterProc) (struct AEffect* effect, int32_t index, float parameter);
typedef float (*AEffectGetParameterProc) (struct AEffect* effect, int32_t index);

struct AEffect {
	int32_t magic;			
	AEffectDispatcherProc dispatcher;
	AEffectProcessProc process;
	AEffectSetParameterProc setParameter;
	AEffectGetParameterProc getParameter;

	int32_t numPrograms;
	int32_t numParams;		
	int32_t numInputs;		
	int32_t numOutputs;	

	int32_t flags;			
	
	void* resvd1;		
	void* resvd2;		
	
	int32_t initialDelay;	
	
	int32_t realQualities;	
	int32_t offQualities;		
	float    ioRatio;			

	void* object;			
	void* user;				

	int32_t uniqueID;		
	int32_t version;		

	AEffectProcessProc processReplacing;

	char future[60];		
};

static intptr_t hostcallback(void *effect, int32_t op, int32_t idx, int32_t v, void* ptr, float opt) {
    char *ptr_char = (char*)ptr;

    printf("    [HOST CALLBACK] %d %d %d %p %f\n", op, idx, v, ptr, opt);
    switch (op) {
        case 1:
            printf("        audio master version\n");
            return 2400;
        case 32:
            printf("        get vendor string\n");
            strcpy(ptr, "vendor");
            return 0;

        case 33:
            printf("        get product string\n");
            strcpy(ptr, "product");
            return 0;
        case 34:
            printf("        get version string\n");
            return 0;
        case 35:
            printf("        audio master vendor specific\n");
            return 0;
        case 37:
            printf("        audio master can do > %s\n", (char*)ptr);
            return 0;
        case 38:
            printf("        get language\n");
            return 0;

        default:
            return 0;
    }
}


static void set_parameter(struct AEffect* effect, int32_t index, float parameter) {
    printf("set parameter: %d %f\n", index, parameter);
}

static float get_parameter(struct AEffect* effect, int32_t index) {
    printf("get parameter: %d\n", index);
    return 0;
}

static void hotpatch(void *target, void *replacement)
{
    void *page = (void *)((uintptr_t)target & ~0xfff);
    mprotect(page, 4096, PROT_WRITE | PROT_EXEC);

    uint32_t rel = (char *)replacement - (char *)target - 5;

    union {
        uint8_t bytes[8];
        uint64_t value;
    } instruction = { {0xe9, rel >> 0, rel >> 8, rel >> 16, rel >> 24} };

    *(uint64_t *)target = instruction.value;
    mprotect(page, 4096, PROT_EXEC);
}

static void loggamelo(char *msg, ...) {
    va_list valist;

    va_start(valist, msg);
    vprintf(msg, valist);
    va_end(valist);
}

void hook_break_firmware() {
    printf("hallo!\n");
}

static void my_path_expand(char *dst, char *src, size_t size) {
    printf("PATH EXPAND: %s\n", src);

    if (strcmp("{COMMON_APPDATA}/Access Music/Virus TI/Common/firmware.bin", src) == 0) {
        printf("RETURNING ./firmware.bin\n");
        strncpy(dst, "./firmware.bin", size);
        hook_break_firmware();
    }
    else {
        strncpy(dst, src, size);
    }
}

static void my_resolve_path(char* src, char* dst) {
    printf("my resolve path %p %p\n", src, dst);
}

int main() {
    printf("opening lib\n");
    void *h = dlopen("viruscontrol-mod.dylib", RTLD_LAZY);
    if (!h) {
        perror(dlerror());
        return 1;
    }

    printf("    library handle: %p\n", h);

    printf("getting symbol\n");
    void *func = dlsym(h, "main_macho");
    if (!func) {
        perror(dlerror());
        return 2;
    }

    printf("    symbol:         %p\n", func);

    Dl_info info;
    if (!dladdr(func, &info)) {
        perror(dlerror());
        return 3;
    }

    printf("    pathname:       %s\n", info.dli_fname);
    printf("    base address:   %p\n", info.dli_fbase);
    printf("    nearest symbol: %s\n", info.dli_sname);
    printf("    symbol address: %p\n", info.dli_saddr);
    printf("    symbol base:    %lx\n", info.dli_saddr - info.dli_fbase);

    void *base = info.dli_fbase;

    printf("patching log func\n");
    hotpatch(base + 0x0f5500, &loggamelo);
    hotpatch(base + 0x101276, &my_path_expand);
    // hotpatch(base + 0x0d7db0, &my_resolve_path);
    
    void (*chunker_init)(void *chunker, uint8_t *buffer, int len)
        = base + 0x10244c;

    int (*chunker_chunk_count)(void *chunker)
        = base + 0x1024fe;

    int (*chunker_chunk_2)(void *chunker, uint8_t **out1, uint8_t **out2, int param4)
        = base + 0x102488;


    struct {
        uint8_t impl[0x100];
        uint32_t canary;
    } chunker = {
        { 0 },
        0xdeadbeef
    };


    char *filename = false ? "real-firmware.bin" : "vti_2.bin";
    FILE *file = fopen(filename, "r");
    fseek(file, 0, SEEK_END);

    int len = ftell(file);
    void *fw = malloc(len);

    fseek(file, 0, SEEK_SET);
    fread(fw, len, 1, file);
    fclose(file);

    printf("firmware len: %d\n", len);

    chunker_init(&chunker, fw, len);

    if (chunker.canary != 0xdeadbeef) {
        printf("M O R T O\n");
        return 0;
    }

    int nrr = chunker_chunk_count(&chunker);
    printf("nr chunks %d\n", nrr);

    if (chunker.canary != 0xdeadbeef) {
        printf("M O R T O\n");
        return 0;
    }

    uint8_t *out1 = 0;
    uint8_t *out2 = 0;

    int chunk_len = chunker_chunk_2(&chunker, &out1, &out2, 0);

    if (chunker.canary != 0xdeadbeef) {
        printf("M O R T O\n");
        return 0;
    }

    printf("chunk len: %d\n", chunk_len);
    printf("out1 %p out2 %p\n", out1, out2);
    printf("out 1: %s\n", out1);
    printf("out 2: ");

    for (int i = 0; i < 0x10; i++)
        printf("%02x ", out2[i]);

    printf("\n");

    return 0;

    printf("getting VSTPluginMain\n");
    void* (*plugin_main)(void *) = dlsym(h, "VSTPluginMain");
    if (!func) {
        perror(dlerror());
        return 4;
    }

    printf("    main:           %p\n", plugin_main);

    printf("instantiating plugin\n");

    struct AEffect *plug = plugin_main(&hostcallback);
    printf("    plugin at:      %p\n", plug);

    plug->setParameter = set_parameter;
    plug->getParameter = get_parameter;

    uintptr_t br = 0x01024fe;
    uintptr_t rebased = br + base;

    printf("\n");
    printf("--------------------------------------------------\n");
    printf("\n");
    printf("  BREAK IN: %p -- %p\n", br, rebased);
    printf("\n");
    printf("    br set -a %p\n", rebased);
    printf("\n");
    printf("--------------------------------------------------\n");
    printf("\n");


    printf("opening plugin\n");
    plug->dispatcher(plug, 0 /* effOpen */, 0, 0, NULL, 0);

    return 0;
}
