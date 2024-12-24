#ifndef _PACKET_OP_H_
#define _PACKET_OP_H_

#include "Types.h"
#include <WinSock2.h>

#ifdef __cplusplus
extern "C" {
#endif

static uint32_t packetCount = 1;

const char*           GetStringTLSVersion(enum TLSVersions tlsv);
BOOL                  FilterPacket(struct Packet* packet);
enum IPVersion        GetIPVersion(struct Packet* packet);
BOOL                  IsIPV6Packet(struct Packet* packet);
BOOL                  IsIPV4Packet(struct Packet* packet);
uint32_t              GetDestPort(struct Packet* packet);
uint32_t              GetSourcePort(struct Packet* packet);
enum InternetProtocol GetPacketProtocol(struct Packet* packet);
uint32_t              HexPortToInt(u_char port[2]);
u_char*               CompressIPV6Address(u_char* address);
u_char*               GetSourceIPAddress(struct Packet* packet);
u_char*               GetDestIPAddress(struct Packet* packet);
struct Packet         ParseRawPacket(u_char* rawData, uint32_t packetSize);
static pcap_handler   HandlePacket(u_char* byteStrHandle, const struct pcap_pkthdr* pacInfo, const u_char* data);
void                  CapturePackets();
const char*           GetStringIPV(enum IPVersion ipv);
const char*           GetStringProtocol(enum InternetProtocol p);

#ifdef __cplusplus
}
#endif

#endif