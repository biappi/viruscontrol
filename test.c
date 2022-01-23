#include <stdio.h>
#include <dlfcn.h>

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
    printf("    [HOST CALLBACK] %p %d %d %d %p %f\n", effect, op, idx, v, ptr, opt);
    switch (op) {
        case 1: // audio master version
            return 2400;

        case 35: // audio master vendor specific
            return 0;

        case 37: // audio master can do
            return 0;

        default:
            return 0;
    }
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
