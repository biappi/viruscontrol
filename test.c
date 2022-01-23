#include <stdio.h>
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

void loggamelo(char *msg, ...) {
    va_list valist;

    va_start(valist, msg);
    vprintf(msg, valist);
    va_end(valist);
}

void my_path_expand(char *dst, char *src, size_t size) {
    printf("PATH EXPAND: %s\n", src);
    strncpy(dst, src, size);
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

    printf("smoke test, calling path_expand\n");

    void (*path_expand)(char* dst, char* src, size_t size) = 0x00101276 + base;

    char *s1 = "{COMMON_APPDATA}/abc";
    char s2[1024] = {0};
    
    path_expand(s2, s1, 1024);
    printf("    input > '%s' output > ' %s'\n", s1, s2);

    printf("patching log func\n");
    hotpatch(base + 0x0f5500, &loggamelo);
    hotpatch(base + 0x101276, &my_path_expand);

    printf("getting VSTPluginMain\n");
    void* (*plugin_main)(void *) = dlsym(h, "VSTPluginMain");
    if (!func) {
        perror(dlerror());
        return 4;
    }

    printf("    main:           %p\n", plugin_main);

    printf("instantiating plugin\n");

    struct AStruct *plug = plugin_main(&hostcallback);
    printf("    plugin at:      %p\n", plug);

    return 0;
}
