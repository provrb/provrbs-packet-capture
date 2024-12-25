#include "ui/UIEvents.h"
#include <windows.h>

void ( *frontendCapturePacket )( struct Packet* packet, u_char* packetData) = NULL;

void RegisterFrontendCapture(void ( *callback )( struct Packet* packet )) {
    frontendCapturePacket = callback;
}

void OnPacketCapture(struct Packet* packet) {
#ifndef _CLI_

    // notify frontend
    if ( frontendCapturePacket )
        frontendCapturePacket(packet, packet->rawData);
    else {
        MessageBoxA(NULL, "No front end callback set.", "Status", MB_OK | MB_ICONERROR);
    }
#endif
}
