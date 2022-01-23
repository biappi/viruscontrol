#include <cstdlib>
#include <cstdio>
#include <cstring>

struct EReqDirection {
    uint8_t thing;
};

struct EReqLevel {
    uint8_t thing;
};

struct EReqRecipient {
    uint8_t thing;
};

struct EReqRequest {
    uint8_t thing;
};

class E_VC_INT_PARAM {
};

struct VC_DeviceInfo {
    uint16_t field_0x0;
    uint16_t field_0x2;
    uint16_t field_0x4;
    uint16_t field_0x6;
    uint16_t field_0x8;
    
    uint8_t  field_0xa;
    uint8_t  field_0xb;
    uint8_t  field_0xc;
    uint8_t  field_0xd;
    
    uint32_t field_0x10;
    
    char    buf1[0x100];
    char    buf2[0x100];
};

class VirusClient {
public:
    
    virtual void virusAttached(void *device, void *maybeSelf);
    virtual void virusDetached(void *device, void *maybeSelf);
    virtual void virusOther   (void *device, long event, long boh2, long boh3, void *maybeSelf); // events: 1 == other attached; 2 == other detached; 3 == ptstatechange
    
    bool vc_request(EReqDirection, EReqLevel, EReqRecipient, EReqRequest, unsigned short, unsigned short, char*, unsigned short);
    
    void* vc_getDeviceID(unsigned long);
    void  vc_setIntParam(E_VC_INT_PARAM, long);
    void  vc_getLatencies(unsigned long&, unsigned long&);
    void  vc_getBuffersize();
    bool  vc_getDeviceInfo(unsigned long, VC_DeviceInfo&);
    int   vc_getNumDevices();
    unsigned long vc_getSamplerate();
    void  vc_setSamplerate(unsigned long);
    void  vc_isPluginMaster();
    bool  vc_init();
    void  vc_open(void*);
    void  vc_stop();
    void  vc_term();
    void  vc_close();
    void  vc_start(unsigned long);
    void  vc_getConfigStatus() const;
    void  vc_getLibraryVersion() const;
    void  vc_getAudioDriverVersion() const;
    void  vc_getHostInterfaceVersion() const;
};

/*
 some_log:  ___lldb_unnamed_symbol4758$$Virus Control
 sbomba:    ___lldb_unnamed_symbol4952$$Virus Control
 */

#define MIN(x, y) ((x) < (y)) ? (x) : (y)

static uint32_t last_req;

bool VirusClient::vc_request(
    EReqDirection  direction,
    EReqLevel      level,
    EReqRecipient  recipient,
    EReqRequest    request,
    unsigned short usb_req_value,
    unsigned short usb_req_index,
    char*          buffer_data,
    unsigned short buffer_len
) {
    uint8_t usb_req_type = direction.thing | level.thing | recipient.thing;
    
    printf("REQUEST >  %02x - (%02x %02x %02x) %02x %02x %04x  - %04x  --  ",
           usb_req_type,
           direction.thing,
           level.thing,
           recipient.thing,
           request.thing,
           usb_req_value,
           usb_req_index,
           buffer_len);

    if ((usb_req_type == 0xc1) && (request.thing == 0x81) && (usb_req_index == 0x0001)) {
        buffer_data[0] = 0x10;
    }

    if ((usb_req_type == 0x41) && (request.thing == 0x01) && (usb_req_index == 0x0012)) {
        uint8_t *data = (uint8_t *)buffer_data;
        
        last_req =
            (data[0] << 16) |
            (data[1] <<  8) |
            (data[2] <<  0);
    }

    if ((usb_req_type == 0xc1) && (request.thing == 0x81) && (usb_req_index == 0x0030)) {
        if (last_req == 0xff7fa0) {
            uint8_t resp[] = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0xff7fb0) {
            uint8_t resp[] = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0xff7fc0) {
            uint8_t resp[] = {
                0x46, 0x4c, 0x53, 0x48, 0x32, 0x30, 0x30, 0x38,
                0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0xff7fd0) {
            uint8_t resp[] = {
                0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }
        
        if (last_req == 0xff7fe0) {
            uint8_t resp[] = {
                0x07, 0x2a, 0x00, 0x0d, 0x75, 0x1f, 0x3d, 0x73,
                0x21, 0x79, 0x55, 0x0b, 0x07, 0x07, 0xdd, 0x00,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0xff7ff0) {
            uint8_t resp[] = {
                0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800000) {
            uint8_t resp[] = {
                0x02, 0x4e, 0xe8, 0x02, 0x2e, 0x80, 0x0d, 0xc3,
                0xbc, 0x02, 0x05, 0x02, 0x2e, 0xcb, 0x05, 0xcb,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800010) {
            uint8_t resp[] = {
                0x9e, 0x63, 0xff, 0x32, 0x32, 0xe4, 0xd3, 0x22,
                0x7f, 0x0a, 0x90, 0x4a, 0x04, 0x02, 0x04, 0xa4,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800020) {
            uint8_t resp[] = {
                0xff, 0xff, 0xff, 0x02, 0x2c, 0xd9, 0xc2, 0x1f,
                0x22, 0xff, 0xff, 0x02, 0x2d, 0x42, 0x35, 0x2e,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800030) {
            uint8_t resp[] = {
                0x31, 0x2e, 0x37, 0x2e, 0x30, 0x30, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800040) {
            uint8_t resp[] = {
                0x00, 0x00, 0x00, 0x02, 0x1b, 0xdb, 0xc2, 0x60,
                0x22, 0xff, 0xff, 0x02, 0x32, 0x88, 0xff, 0xff,
                
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

        if (last_req == 0x800050) {
            uint8_t resp[] = {
                0x02, 0x4e, 0xe8, 0x02, 0x2e, 0x80, 0x0d, 0xc3,
                0xbc, 0x02, 0x05, 0x02, 0x2e, 0xcb, 0x05, 0xcb,
            };
            
            memcpy(buffer_data, resp, MIN(sizeof(resp), buffer_len));
        }

    }
    
    for (int i = 0; i < buffer_len; i++) {
        printf("%02x ", (uint8_t)buffer_data[i]);
    }
            
    printf("\n");

    return true;
}

void* VirusClient::vc_getDeviceID(unsigned long arg0) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    %lu\n", arg0);
    
    return (void*)0xdddddddddddddddd;
}

void VirusClient::vc_setIntParam(E_VC_INT_PARAM p, long v) {
    printf("%s\n", __PRETTY_FUNCTION__);
//    printf("    p: %d\n", p);
    printf("    v: %ld\n", v);
}

void VirusClient::vc_getLatencies(unsigned long&, unsigned long&) {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_getBuffersize() {
    printf("%s\n", __PRETTY_FUNCTION__);
}

bool VirusClient::vc_getDeviceInfo(unsigned long arg0, VC_DeviceInfo& info) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    %lu\n", arg0);
    
    info.field_0x0 = 0x1111;
    info.field_0x2 = 0x2222;
    info.field_0x4 = 0x3333;
    info.field_0x6 = 0x4444;
    info.field_0x8 = 0x0300; // 0x5555;
    
    info.field_0xa = 0x66;
    info.field_0xb = 0x77;
    info.field_0xc = 0x88;
    info.field_0xd = 0x99;
    
    info.field_0x10 = 0xaaaaaaaa;
    
    memset(&info.buf1, 0xbb, 0x100);
//    memset(&info.buf2, 0xcc, 0x100);
    
    strncpy(info.buf2, "Virus TI", 0x100);
    
    return true;
}

int VirusClient::vc_getNumDevices() {
//    printf("%s\n", __PRETTY_FUNCTION__);
    return 1;
}

unsigned long VirusClient::vc_getSamplerate() {
    printf("%s\n", __PRETTY_FUNCTION__);
    return 44100;
}

void VirusClient::vc_setSamplerate(unsigned long x) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    %ld\n", x);
}

void VirusClient::vc_isPluginMaster() {
    printf("%s\n", __PRETTY_FUNCTION__);
}

bool VirusClient::vc_init() {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    this: %p\n", this);
    
//    uint8_t * AHAH = ((uint8_t *)this) + 8;
//
//    for (int i = 0; i < 0x3000; i++) {
//        AHAH[i] = i;
//    }

    virusAttached((void*)0x1000, (void*)0x2000);
    
    return true;
}

void VirusClient::vc_open(void* x) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    %p\n", x);
}

void VirusClient::vc_stop() {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_term() {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_close() {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_start(unsigned long x) {
    printf("%s\n", __PRETTY_FUNCTION__);
    printf("    %ld\n", x);
}

void VirusClient::vc_getConfigStatus() const {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_getLibraryVersion() const {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_getAudioDriverVersion() const {
    printf("%s\n", __PRETTY_FUNCTION__);
}

void VirusClient::vc_getHostInterfaceVersion() const {
    printf("%s\n", __PRETTY_FUNCTION__);
}

