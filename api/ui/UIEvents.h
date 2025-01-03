#pragma once

#include <types.h>

#ifdef __cplusplus
extern "C" {
#endif
    extern void ( *frontendCapturePacket )( struct Packet* packet, u_char* data );

    void RegisterFrontendCapture(void ( *callback )( struct Packet* packet ));
    void OnPacketCapture(struct Packet* packet);
#ifdef __cplusplus
}
#endif
