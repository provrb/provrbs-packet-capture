#include "Packets.h"
#include "CLI.h"
#include <ui/UIEvents.h>

enum IPVersion GetIPVersion(struct Packet* packet) {
    if ( packet->h_ethernet.type[0] == 134 && packet->h_ethernet.type[1] == 221 )
        return kIPV6;

    else if ( packet->h_ethernet.type[0] == 8 && packet->h_ethernet.type[1] == 0 )
        return kIPV4;
    return UnknownIPV;
}

const char* GetStringTLSVersion(enum TLSVersions tlsv) {
    const char* str = "Unknown";
    switch ( tlsv ) {
    case TLS1_0: 
        str = "TLS 1.0";
        break;
    case TLS1_1:
        str = "TLS 1.1";
        break;
    case TLS1_2:
        str = "TLS 1.2";
        break;
    case TLS1_3:
        str = "TLS 1.3";
        break;
    }
    return str;
}

const char* GetStringIPV(enum IPVersion ipv) {
    const char* str = "Unknown";
    switch ( ipv ) {
    case kIPV4:
        str = "IPv4";
        break;
    case kIPV6:
        str = "IPv6";
        break;
    }
    return str;
}

BOOL IsPacketMalformed(struct Packet* packet, uint32_t expectedSize) {
    // todo: 
}

int ParseIPV4Header(struct Packet* packet, int index) {
    if ( index == 14 )                   packet->h_ip.ip4.versionihl = packet->rawData[index];
    else if ( index == 15 )              packet->h_ip.ip4.serviceType = packet->rawData[index];
    else if ( index > 15 && index < 18 ) packet->h_ip.ip4.headerSize[index - 16] = packet->rawData[index];
    else if ( index > 17 && index < 20 ) packet->h_ip.ip4.id[index - 18] = packet->rawData[index];
    else if ( index > 19 && index < 22 ) packet->h_ip.ip4.flags[index - 20] = packet->rawData[index];
    else if ( index == 22 )              packet->h_ip.ip4.ttl = packet->rawData[index];
    else if ( index == 23 )              packet->h_ip.ip4.protocol = packet->rawData[index];
    else if ( index > 23 && index < 26 ) packet->h_ip.ip4.checksum[index - 24] = packet->rawData[index];
    else if ( index > 25 && index < 30 ) packet->h_ip.ip4.sourceIP[index - 26] = packet->rawData[index];
    else                                 packet->h_ip.ip4.destIP[index - 30] = packet->rawData[index];
    
    return ETH_HEADER_SIZE + IP4_HEADER_SIZE;
}

int ParseIPV6Header(struct Packet* packet, int index) {
    if ( index == 14 )                   packet->h_ip.ip6.versionihl = packet->rawData[index];
    else if ( index > 14 && index < 18 ) packet->h_ip.ip6.flowLabel[index - 15] = packet->rawData[index];
    else if ( index > 17 && index < 20 ) packet->h_ip.ip6.payloadLen[index - 18] = packet->rawData[index];
    else if ( index == 20 )              packet->h_ip.ip6.nextHeader = packet->rawData[index];
    else if ( index == 21 )              packet->h_ip.ip6.hopLimit = packet->rawData[index];
    else if ( index > 21 && index < 38 ) packet->h_ip.ip6.sourceAddr[index - 22] = packet->rawData[index];
    else packet->h_ip.ip6.destAddr[index - 38] = packet->rawData[index];

    return ETH_HEADER_SIZE + IP6_HEADER_SIZE;
}

void ParseTCPHeader(struct Packet* packet, int index, uint32_t hdrOffset) {
    if ( index < hdrOffset + 2 ) packet->h_proto.tcp.sourcePort[index - hdrOffset] = packet->rawData[index];
    else if ( index < hdrOffset + 4 )  packet->h_proto.tcp.destPort[index - ( hdrOffset + 2 )] = packet->rawData[index];
    else if ( index < hdrOffset + 8 )  packet->h_proto.tcp.sequenceNum[index - ( hdrOffset + 4 )] = packet->rawData[index];
    else if ( index < hdrOffset + 12 ) packet->h_proto.tcp.ackNum[index - ( hdrOffset + 8 )] = packet->rawData[index];
    else if ( index == hdrOffset + 12 ) {
        packet->h_proto.tcp.len = packet->rawData[index] / 4; // tcp header len
        packet->payloadSize = packet->packetSize - ( packet->h_proto.tcp.len + hdrOffset );
    }
    else if ( index == hdrOffset + 13 ) packet->h_proto.tcp.congWinFlag = packet->rawData[index];
    else if ( index < hdrOffset + 16 && index > hdrOffset + 13 ) packet->h_proto.tcp.window[index - ( hdrOffset + 14 )] = packet->rawData[index];
    else if ( index < hdrOffset + 18 && index > hdrOffset + 15 ) packet->h_proto.tcp.checksum[index - ( hdrOffset + 16 )] = packet->rawData[index];
    else if ( index > hdrOffset + 17 ) packet->h_proto.tcp.urgentPtr[index - ( hdrOffset + 18 )] = packet->rawData[index];
}

void ParseUDPHeader(struct Packet* packet, int index, uint32_t hdrOffset) {
    if ( index < hdrOffset + 2 )      packet->h_proto.udp.sourcePort[index - hdrOffset] = packet->rawData[index];
    else if ( index < hdrOffset + 4 ) packet->h_proto.udp.destPort[index - ( hdrOffset + 2 )] = packet->rawData[index];
    else if ( index < hdrOffset + 6 ) {
        packet->h_proto.udp.len[index - ( hdrOffset + 4 )] = packet->rawData[index]; // udp header len

        if ( index - ( hdrOffset + 4 ) == 1 ) // set payload size
            packet->payloadSize = ( ( packet->h_proto.udp.len[0] << 8 ) | packet->h_proto.udp.len[1] ) - UDP_HEADER_SIZE;
    }
    else packet->h_proto.udp.checksum[index - ( hdrOffset + 6 )] = packet->rawData[index];
}

void ParseICMPHeader(struct Packet* packet, int index, uint32_t hdrOffset) {
    if ( index < hdrOffset + 1 )      packet->h_proto.icmp.type = packet->rawData[index];
    else if ( index < hdrOffset + 2 ) packet->h_proto.icmp.code = packet->rawData[index];
    else if ( index < hdrOffset + 5 ) packet->h_proto.icmp.checksum[index - ( hdrOffset + 2 )] = packet->rawData[index];
    else if ( index < hdrOffset + 9 ) packet->h_proto.icmp.flags[index - ( hdrOffset + 4 )] = packet->rawData[index];
}

void ParseEthernetHeader(struct Packet* packet, int index) {
    if ( index < 6 )       packet->h_ethernet.dest[index - 0] = packet->rawData[index];
    else if ( index < 12 ) packet->h_ethernet.source[index - 6] = packet->rawData[index];
    else {
        packet->h_ethernet.type[index - 12] = packet->rawData[index];
        if ( index - 12 == 1 )
            packet->ipVer = GetIPVersion(packet);
    }
}

void ParsePacketPayload(struct Packet* packet, int index, uint32_t hdrOffset) {
    int payloadStart = 0;
    if ( GetPacketProtocol(packet) == TCP || GetPacketProtocol(packet) == UDP )
        payloadStart = ( GetPacketProtocol(packet) == TCP ) ? hdrOffset + packet->h_proto.tcp.len : hdrOffset + UDP_HEADER_SIZE;
    else if ( GetPacketProtocol(packet) == ICMP )
        payloadStart = hdrOffset + ICMP_HEADER_SIZE;

    if ( IsTLSPayload(packet, payloadStart) ) {
        // save tls info. increment payload start after saving to save the encrypted data
        packet->tls.contentType = packet->rawData[payloadStart];
        if ( index < payloadStart + 3 && index > payloadStart ) {
            packet->tls.tlsVersion[index - ( payloadStart + 1 )] = packet->rawData[index];
            if ( index - ( payloadStart + 1 ) == 1 ) {
                packet->tls.tlsVersionID = (enum TLSVersion)(( packet->tls.tlsVersion[0] << 8 ) | packet->tls.tlsVersion[1]);
            }
        }
        else if ( index < payloadStart + 5 && index > payloadStart + 3 ) {
            packet->tls.encryptedPayloadLen[index - ( payloadStart + 3 )] = packet->rawData[index];
            payloadStart += 6;
        }
        else
            if ( index >= payloadStart )
                packet->payload[index - payloadStart] = packet->rawData;
    }

    if ( packet->payload && index >= payloadStart && packet->tls.usesTLS == FALSE )
        packet->payload[index - payloadStart] = packet->rawData[index];
}

BOOL IsIPV4Header(struct Packet* packet, int index) {
    return ( IsIPV4Packet(packet) && index < ( ETH_HEADER_SIZE + IP4_HEADER_SIZE ) );
}

BOOL IsIPV6Header(struct Packet* packet, int index) {
    return ( IsIPV6Packet(packet) && index < ( ETH_HEADER_SIZE + IP6_HEADER_SIZE ) );
}

BOOL IsTCPHeader(struct Packet* packet, int index, uint32_t offset) {
    return ( GetPacketProtocol(packet) == TCP && index >= offset && index < offset + TCP_MIN_HEADER_SIZE );
}

BOOL IsUDPHeader(struct Packet* packet, int index, uint32_t offset) {
    return ( GetPacketProtocol(packet) == UDP && index >= offset && index < offset + UDP_HEADER_SIZE );
}

BOOL IsICMPHeader(struct Packet* packet, int index, uint32_t offset) {
    return ( GetPacketProtocol(packet) == ICMP && index >= offset && index < offset + ICMP_HEADER_SIZE );
}

const char* GetStringProtocol(enum InternetProtocol p) {
    const char* str = "Unknown";
    switch ( p ) {
    case TCP:
        str = "TCP";
        break;
    case UDP:
        str = "UDP";
        break;
    case ICMP:
        str = "ICMP";
        break;
    case IGMP:
        str = "IGMP";
        break;
    }
    return str;
}

BOOL IsIPV6Packet(struct Packet* packet) {
    return GetIPVersion(packet) == kIPV6;
}

BOOL IsIPV4Packet(struct Packet* packet) {
    return GetIPVersion(packet) == kIPV4;
}

uint32_t GetDestPort(struct Packet* packet) {
    if ( GetPacketProtocol(packet) == UDP )
        return HexPortToInt(packet->h_proto.udp.destPort);
    else if ( GetPacketProtocol(packet) == TCP )
        return HexPortToInt(packet->h_proto.tcp.destPort);
}

uint32_t GetSourcePort(struct Packet* packet) {
    if ( GetPacketProtocol(packet) == UDP )
        return HexPortToInt(packet->h_proto.udp.sourcePort);
    else if ( GetPacketProtocol(packet) == TCP )
        return HexPortToInt(packet->h_proto.tcp.sourcePort);

    return 0;
}

enum InternetProtocol GetPacketProtocol(struct Packet* packet) {
    enum InternetProtocol protocol = UNKNOWN;

    if ( IsIPV4Packet(packet) )      protocol = packet->h_ip.ip4.protocol;
    else if ( IsIPV6Packet(packet) ) protocol = packet->h_ip.ip6.nextHeader;
    else if ( IsIPV6Packet(packet) && packet->h_ip.ip6.nextHeader == ICMPHEADER2 ) protocol = ICMP;

    return protocol;
}

uint32_t HexPortToInt(u_char port[2]) {
    return ( port[0] << 8 ) | port[1];
}

u_char* CompressIPV6Address(u_char* address) {
    WSADATA wsaData;
    if ( WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 ) {
        printf("WSAStartup failed. Error: %d\n", WSAGetLastError());
        return 1;
    }

    char* compressed = (char*)malloc(INET6_ADDRSTRLEN);
    if ( compressed == NULL ) {
        WSACleanup();
        return "";
    }

    if ( inet_ntop(AF_INET6, address, compressed, INET6_ADDRSTRLEN) == NULL ) {
        free(compressed);
        WSACleanup();
        return "";
    }

    WSACleanup();

    return compressed;
}

u_char* GetSourceIPAddress(struct Packet* packet) {
    if ( GetIPVersion(packet) == kIPV4 )
        return packet->h_ip.ip4.sourceIP;
    else if ( GetIPVersion(packet) == kIPV6 )
        return CompressIPV6Address(packet->h_ip.ip6.sourceAddr);

    return "";
}

u_char* GetDestIPAddress(struct Packet* packet) {
    if ( GetIPVersion(packet) == kIPV4 )
        return packet->h_ip.ip4.destIP;
    else if ( GetIPVersion(packet) == kIPV6 )
        return CompressIPV6Address(packet->h_ip.ip6.destAddr);

    return "";
}

BOOL FilterPacket(struct Packet* packet) {
    if ( GetPacketProtocol(packet) == UNKNOWN ||
         GetIPVersion(packet) == UnknownIPV )
        return FALSE;

    return TRUE; // passthrough
}

BOOL IsTLSPayload(struct Packet* packet, int index) {
    if ( packet->protocol == TCP &&
        GetDestPort(packet) == 443 &&
        packet->rawData[index] == 0x17
        ) 
        // start of "payload" after 
    {
        packet->tls.usesTLS = TRUE;
        return TRUE;
    }
    packet->tls.usesTLS = FALSE;
    return FALSE;
}

struct Packet ParseRawPacket(u_char* rawData, uint32_t packetSize) {
    struct Packet packet;
    packet.packetSize   = packetSize;
    packet.payloadSize  = 0;
    packet.payload      = ( u_char* ) malloc(packetSize);
    packet.rawData      = rawData;
    packet.packetNumber = packetCount;
    packet.timestamp    = time(NULL);

    uint32_t protoHeaderOffset = 0;

    for ( int index = 0; index < packetSize; index++ ) {
        if ( index < ETH_HEADER_SIZE )
            ParseEthernetHeader(&packet, index);

        else if ( IsIPV4Header(&packet, index) )
            protoHeaderOffset = ParseIPV4Header(&packet, index);
        
        else if ( IsIPV6Header(&packet, index) )
            protoHeaderOffset = ParseIPV6Header(&packet, index);

        packet.protocol = GetPacketProtocol(&packet);

        if ( IsTCPHeader(&packet, index, protoHeaderOffset) )
            ParseTCPHeader(&packet, index, protoHeaderOffset);

        else if ( IsUDPHeader(&packet, index, protoHeaderOffset) )
            ParseUDPHeader(&packet, index, protoHeaderOffset);

        else if ( IsICMPHeader(&packet, index, protoHeaderOffset) )
            ParseICMPHeader(&packet, index, protoHeaderOffset);
        else
            ParsePacketPayload(&packet, index, protoHeaderOffset);
    }
    return packet;
}

static pcap_handler HandlePacket(u_char* _, const struct pcap_pkthdr* pacInfo, const u_char* data) {
    struct Packet packet = ParseRawPacket(data, pacInfo->len);
    if ( packet.ipVer == UnknownIPV ) {
        // malformed ?
        free(packet.payload);
        return;                                                                                             
    }   

    if ( !FilterPacket(&packet) ) {
        free(packet.payload);
        return;
    }
    
    PrintPacketInfo(&packet);
    PacketHexDump(&packet);

    OnPacketCapture(&packet);
    packetCount++;
    printf("\n\n");
}

void CapturePackets() {
    MessageBoxA(NULL, "Capturing packets", "Status", MB_OK | MB_ICONINFORMATION);
    // error buffers
    char devErrBuff[PCAP_ERRBUF_SIZE];
    char openLiveErrBuff[PCAP_ERRBUF_SIZE];

    BOOL captureAllTraffic = FALSE;
    pcap_if_t* dev;

    if ( pcap_findalldevs(&dev, &devErrBuff) != 0 ) {
        printf("There was an error finding all devices.\n");
        return;
    }

    pcap_if_t* tmp = dev->next;

    while ( tmp->next != NULL )
    {
        pcap_t* handle = pcap_open_live(tmp->name, 262144, captureAllTraffic, 0, &openLiveErrBuff);
        if ( handle ) {
            printf("Opened %s for packet capture.\n", tmp->description);
            if ( strstr(tmp->description, "Realtek") != 0 )
                pcap_loop(handle, 0, HandlePacket, NULL);
        }
        tmp = tmp->next;
    }
}