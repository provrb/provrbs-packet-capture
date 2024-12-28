#include "Packets.h"
#include "CLI.h"
#include <ui/UIEvents.h>

enum IPVersion GetIPVersion(struct Packet* packet) {
    if ( packet->h_ethernet.type[0] == 0x86 && packet->h_ethernet.type[1] == 0xDD )
        return kIPV6;

    else if ( packet->h_ethernet.type[0] == 8 && packet->h_ethernet.type[1] == 0 )
        return kIPV4;

    else if ( packet->h_ethernet.type[0] == 8 && packet->h_ethernet.type[1] == 6 )
        return kARP;

    return UnknownIPV;
}

BOOL IsTCPFlagSet(struct Packet* packet, enum TCPFlags flag)
{
    u_char* tcpHeader = "";
    if ( GetIPVersion(packet) == kIPV6 )
        tcpHeader = packet->rawData + (ETH_HEADER_SIZE + IP6_HEADER_SIZE);
    else if ( GetIPVersion(packet) == kIPV4 )
        tcpHeader = packet->rawData + (ETH_HEADER_SIZE + IP4_HEADER_SIZE);
    else
        return FALSE;

    /* Where to search using & operator for our flags */    
    return ( tcpHeader[13] & flag ) != 0;
}

BOOL IsBroadcastMAC(u_char* mac) {
    return ( mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff );
}

BOOL IncludesLinkLayerAddr(struct Packet* packet) {
    return ( packet->h_proto.icmp.type2 == SourceLinkLayerAddress );
}

BOOL IsARPPacket(struct Packet* packet)
{
    if ( packet->h_ethernet.type[0] == 8 && packet->h_ethernet.type[1] == 6 )
        return TRUE;

    return FALSE;
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
    return ( IsIPV4Packet(packet) && GetPacketProtocol(packet) == ICMP && index >= offset && index < offset + ICMP_HEADER_SIZE );
}

BOOL IsICMP6Header(struct Packet* packet, int index, uint32_t offset) {
    return ( IsIPV6Packet(packet) && GetPacketProtocol(packet) == ICMP6 && index >= offset && index <= offset + ICMP6_HEADER_SIZE );
}

/*
* Check all flags in the TCP packet. If the flag 
* is set, add the acrynoym to a string and return that string
* containing the name of all flags
*/
char* GetStringTCPFlagsSet(struct Packet* packet) {
    if ( GetPacketProtocol(packet) != TCP )
        return "";

    char* flags = (char*)malloc(256);
    if ( flags == NULL )
        return "";

    flags[0] = '\0';

    if ( IsTCPFlagSet(packet, FIN) ) strcat(flags, "FIN 0x01 ");
    if ( IsTCPFlagSet(packet, SYN) ) strcat(flags, "SYN 0x02 ");
    if ( IsTCPFlagSet(packet, RST) ) strcat(flags, "RST 0x04 ");
    if ( IsTCPFlagSet(packet, PSH) ) strcat(flags, "PSH 0x08 ");
    if ( IsTCPFlagSet(packet, ACK) ) strcat(flags, "ACK 0x10 ");
    if ( IsTCPFlagSet(packet, URG) ) strcat(flags, "URG 0x20 ");
    if ( IsTCPFlagSet(packet, ECE) ) strcat(flags, "ECE 0x40 ");
    if ( IsTCPFlagSet(packet, CWR) ) strcat(flags, "CWR 0x80 ");
    if ( IsTCPFlagSet(packet, NS)  ) strcat(flags, "NS 0x100 ");
    
    flags[strlen(flags) + 1] = '\0';

    return flags;
}

BOOL IsSuspectedHTTPRequest(struct Packet* packet) {
    if ( GetPacketProtocol(packet) != TCP )
        return FALSE;

    // make an array of printable ascii characters from the rawData
    // look for 'HTTP', 'GET', 'User-Agent', 'POST', 'Host:', '.com'
    u_char* ascii = (u_char*)malloc(packet->packetSize + 1);
    if ( ascii == NULL )
        return FALSE;

    for ( int i = 0; i < packet->packetSize; i++ ) {
        u_char asciiChar = ( u_char ) packet->rawData[i];
        if ( isprint(asciiChar) )
            ascii[i] = asciiChar;
        else
            ascii[i] = '.';
    }

    // look for common strings. intiai idea whether or not http
    if ( strstr(ascii, "HTTP") != NULL )
        packet->likelyHTTP = TRUE;
    else if ( strstr(ascii, "GET") != NULL )
        packet->likelyHTTP = TRUE;
    else if ( strstr(ascii, "POST") != NULL )
        packet->likelyHTTP = TRUE;
    else if ( strstr(ascii, "Content-Type") != NULL )
        packet->likelyHTTP = TRUE;
    else if ( strstr(ascii, "Host") != NULL )
        packet->likelyHTTP = TRUE;

    if ( !packet->likelyHTTP ) {
        free(ascii);
        return FALSE;
    }

    // look for a version. final idea of whether or not http
    if ( strstr(ascii, "HTTP/1.0") != NULL )
        packet->httpVer = HTTP1_0;
    else if ( strstr(ascii, "HTTP/1.1") != NULL )
        packet->httpVer = HTTP1_1;
    else if ( strstr(ascii, "HTTP/2") != NULL )
        packet->httpVer = HTTP2;
    else if ( strstr(ascii, "HTTP/3") != NULL )
        packet->httpVer = HTTP3;
    else // no version found. likely not http
        packet->likelyHTTP = FALSE;

    free(ascii);
    return packet->likelyHTTP;
}

BOOL IsIPV6Packet(struct Packet* packet) {
    return GetIPVersion(packet) == kIPV6;
}

BOOL IsIPV4Packet(struct Packet* packet) {
    return GetIPVersion(packet) == kIPV4;
}

uint32_t GetDestPort(struct Packet* packet) {
    if ( GetPacketProtocol(packet) == ARP )
        return 0; // no port

    if ( GetPacketProtocol(packet) == UDP )
        return HexPortToInt(packet->h_proto.udp.destPort);
    else if ( GetPacketProtocol(packet) == TCP )
        return HexPortToInt(packet->h_proto.tcp.destPort);
}

uint32_t GetSourcePort(struct Packet* packet) {
    if ( GetPacketProtocol(packet) == ARP )
        return 0; // no port
    else if ( GetPacketProtocol(packet) == UDP )
        return HexPortToInt(packet->h_proto.udp.sourcePort);
    else if ( GetPacketProtocol(packet) == TCP )
        return HexPortToInt(packet->h_proto.tcp.sourcePort);

    return 0;
}

enum InternetProtocol GetPacketProtocol(struct Packet* packet) {
    enum InternetProtocol protocol = UNKNOWN;

    if ( IsARPPacket(packet) )
        return ARP;

    if ( IsIPV4Packet(packet) )      protocol = packet->h_ip.ip4.protocol;
    else if ( IsIPV6Packet(packet) && packet->h_ip.ip6.nextHeader == ICMPHEADER2 ) protocol = ICMP;
    else if ( IsIPV6Packet(packet) && packet->h_ip.ip6.nextHeader == ICMP ) protocol = ICMP6;
    else if ( IsIPV6Packet(packet) ) protocol = packet->h_ip.ip6.nextHeader;

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

BOOL IsDNSQuery(struct Packet* packet) {
    if ( GetSourcePort(packet) == DNS_QUERY_PORT || GetDestPort(packet) == DNS_QUERY_PORT )
        return TRUE;

    return FALSE;
}

BOOL IsKeepAlivePacket(struct Packet* packet) {
    if ( GetPacketProtocol(packet) != TCP )
        return FALSE;

    if ( IsTCPFlagSet(packet, ACK) &&
        !IsTCPFlagSet(packet, PSH) &&
        !IsTCPFlagSet(packet, FIN) &&
        !IsTCPFlagSet(packet, RST) &&
        !IsTCPFlagSet(packet, SYN) &&
        packet->payloadSize == 0
        ) 
        return TRUE;
   
    return FALSE;
}

BOOL FilterPacket(struct Packet* packet) {
    if ( GetIPVersion(packet) == UnknownIPV )
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

void ParseARPPayload(struct Packet* packet, int index) {
    if ( index > ETH_HEADER_SIZE + 6 && index < ETH_HEADER_SIZE + 9 )
        packet->h_proto.arp.opcode[index - ( ETH_HEADER_SIZE + 7 )] = packet->rawData[index];
    else if ( index > ETH_HEADER_SIZE + 14 && index < ETH_HEADER_SIZE + 19 )
        packet->h_proto.arp.senderIP[index - ( ETH_HEADER_SIZE + 15 )] = packet->rawData[index];
    else if ( index > ETH_HEADER_SIZE + 24 )
        packet->h_proto.arp.targetIP[index - ( ETH_HEADER_SIZE + 25 )] = packet->rawData[index];
}

struct Packet ParseRawPacket(u_char* rawData, uint32_t packetSize) {
    struct Packet packet;
    packet.packetSize   = packetSize;
    packet.payloadSize  = 0;
    packet.payload      = ( u_char* ) malloc(packetSize);
    packet.rawData      = rawData;
    packet.packetNumber = g_cPacketCount;

    uint32_t protoHeaderOffset = 0;

    for ( int index = 0; index < packetSize; index++ ) {
        if ( index < ETH_HEADER_SIZE )
            ParseEthernetHeader(&packet, index);

        if ( IsARPPacket(&packet) || GetPacketProtocol(&packet) == kARP ) {
            ParseARPPayload(&packet, index);

            // parsed packet fully nothing else to parse.
            if ( index >= ETH_HEADER_SIZE + ARP_HEADER_SIZE )
                break;
        }

        else if ( IsIPV4Header(&packet, index) )
            protoHeaderOffset = ParseIPV4Header(&packet, index);
        
        else if ( IsIPV6Header(&packet, index) )
            protoHeaderOffset = ParseIPV6Header(&packet, index);

        packet.protocol = GetPacketProtocol(&packet);

        if ( IsTCPHeader(&packet, index, protoHeaderOffset) )
            ParseTCPHeader(&packet, index, protoHeaderOffset);

        else if ( IsUDPHeader(&packet, index, protoHeaderOffset) )
            ParseUDPHeader(&packet, index, protoHeaderOffset);

        else if ( IsICMP6Header(&packet, index, protoHeaderOffset) ) {
            if ( index == protoHeaderOffset )
                packet.h_proto.icmp.type = packet.rawData[index];
            else if ( index == protoHeaderOffset + 1 )
                packet.h_proto.icmp.code = packet.rawData[index];
            else if ( index >= protoHeaderOffset + 2 && index < protoHeaderOffset + 4 )
                packet.h_proto.icmp.checksum[index - ( protoHeaderOffset + 2 )] = packet.rawData[index];
            else if ( index > protoHeaderOffset + 3 && index < protoHeaderOffset + 8 )
                packet.h_proto.icmp.flags[index - ( protoHeaderOffset + 4 )] = packet.rawData[index];
            else if ( index > protoHeaderOffset + 7 && index < protoHeaderOffset + 24 )
                packet.h_proto.icmp.targetAddr[index - ( protoHeaderOffset + 8 )] = packet.rawData[index];
            else if ( index == protoHeaderOffset + 24 ) // includes link layer address
                packet.h_proto.icmp.type2 = packet.rawData[index];
            else if ( IncludesLinkLayerAddr(&packet) && index == protoHeaderOffset + 25 )
                packet.h_proto.icmp.llPayloadSize = packet.rawData[index];
            else if ( IncludesLinkLayerAddr(&packet) && index > protoHeaderOffset + 25 && index < protoHeaderOffset + 25 + 9 )
                packet.h_proto.icmp.lladdress[index - ( protoHeaderOffset + 26 )] = packet.rawData[index];
        }

        else if ( IsICMPHeader(&packet, index, protoHeaderOffset) )
            ParseICMPHeader(&packet, index, protoHeaderOffset);

        else
            ParsePacketPayload(&packet, index, protoHeaderOffset);
    }

    return packet;
}

static pcap_handler HandlePacket(u_char* _, const struct pcap_pkthdr* pacInfo, const u_char* data) {
    if ( g_cCapturePackets == FALSE )
        return;

    struct Packet packet = ParseRawPacket(data, pacInfo->len);
    packet.timestamp = pacInfo->ts;
    packet.packetSize = pacInfo->len;
    packet.capLen = pacInfo->caplen;

    if ( !FilterPacket(&packet) ) {
        free(packet.payload);
        return;
    }
    
    PrintPacketInfo(&packet);
    PacketHexDump(&packet);

    OnPacketCapture(&packet);
    g_cPacketCount++;
    //printf("\n\n");
}

pcap_if_t* GetNICFromIndex(int interfaceIndex) {
    if ( interfaceIndex > GetNumberOfNetworkInterfaces() )
        return NULL;

    char devErrBuff[PCAP_ERRBUF_SIZE];

    pcap_if_t* devList;
    if ( pcap_findalldevs(&devList, &devErrBuff) != 0 ) {
        MessageBoxA(NULL, "Failed to find network devices.", "Error", MB_OK | MB_ICONERROR);
        return NULL;
    }

    int numInterface = 0;
    pcap_if_t* device = devList;

    while ( device != NULL ) {
        if ( numInterface == interfaceIndex )
            break;

        numInterface++;
        device = device->next;
    }

    pcap_freealldevs(devList);

    return device;
}

void CapturePackets(int interfaceIndex) {
    if ( interfaceIndex > GetNumberOfNetworkInterfaces() ) {
        MessageBoxA(NULL, "Failed to capture packets using selected network interface.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    char openLiveErrBuff[PCAP_ERRBUF_SIZE];

    pcap_if_t* device = GetNICFromIndex(interfaceIndex);
    if ( device == NULL )
        return;

    pcap_t* handle = pcap_open_live(device->name, 262144, FALSE, 0, &openLiveErrBuff);
    if ( !handle ) {
        MessageBoxA(NULL, "Failed to open selected network interface.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // malloc
    if ( g_cNumOpenNICHandles == 0 )
        g_cOpenNICHandles = ( pcap_t** ) malloc(1024);            

    // add handle to open NIC handles
    if ( g_cOpenNICHandles != NULL )
        g_cOpenNICHandles[g_cNumOpenNICHandles++] = handle;

    g_cCapturePackets = TRUE;
    pcap_loop(handle, 0, HandlePacket, NULL);
}

int GetNumberOfNetworkInterfaces() {
    pcap_if_t* devList;
    int numberOfNetworkInterfaces = 0;

    char devErrBuff[PCAP_ERRBUF_SIZE];
    if ( pcap_findalldevs(&devList, &devErrBuff) != 0 ) {
        return 0;
    }

    pcap_if_t* device = devList;

    while ( device != NULL ) {
        numberOfNetworkInterfaces++;
        device = device->next;
    }

    pcap_freealldevs(devList);

    return numberOfNetworkInterfaces;
}

char** GetNetworkInterfaceNames()
{
    int networkInterfacesNum = 0;
    char** networkInterfaces = ( char* ) malloc(1024 * sizeof(char*));
    if ( networkInterfaces == NULL )
        return NULL;

    pcap_if_t* devList;
    char devErrBuff[PCAP_ERRBUF_SIZE];

    if ( pcap_findalldevs(&devList, &devErrBuff) != 0 ) {
        free(networkInterfaces);
        return NULL;
    }

    pcap_if_t* device = devList;
    while ( device != NULL) {
        if ( device->description == NULL )
            networkInterfaces[networkInterfacesNum] = "Unknown Interface";
        else
            networkInterfaces[networkInterfacesNum] = _strdup(device->description);
        
        networkInterfacesNum++;
        device = device->next;
    }

    pcap_freealldevs(devList);

    return networkInterfaces;
}

void PausePacketCapture() {
    g_cCapturePackets = FALSE;
}

void ResumePacketCapture() {
    g_cCapturePackets = TRUE;
}

void ResetPacketCount() {
    g_cPacketCount = 1;
}

BOOL ApplyFilter(int interfaceIndex, const char* filter) {
    if ( g_cOpenNICHandles[g_cNumOpenNICHandles - 1] == NULL )
        return FALSE;

    pcap_t* handle = g_cOpenNICHandles[g_cNumOpenNICHandles - 1];
    struct bpf_program fp;

    if ( pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) != 0 )
        return FALSE;

    if ( pcap_setfilter(handle, &fp) != 0 )
        return FALSE;

    return TRUE;
}

BOOL ImportPacketsFromPCAPFile(const char* filePath) {
    char openErrBuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filePath, &openErrBuff);
    if ( handle == NULL )
        return FALSE;

    struct pcap_pkthdr info;
    u_char* rawData;
    
    pcap_loop(handle, 0, HandlePacket, NULL);

    return TRUE;
}

BOOL DumpPacketsToFile(struct Packet** packetArray, int numberOfPackets, const char* filePath) {
    if ( numberOfPackets <= 0 || packetArray[numberOfPackets - 1] == NULL )
        return FALSE;

    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if ( handle == NULL )
        return FALSE;

    pcap_dumper_t* dump = pcap_dump_open(handle, filePath);
    if ( dump == NULL )
        return FALSE;

    for ( int i = 1; i <= numberOfPackets; i++ ) {
        if ( packetArray[i] == NULL )
            continue;

        struct Packet* packet = packetArray[i];

        if ( packet->rawData == NULL || packet->capLen <= 0 || packet->packetSize <= 0 ) {
            continue;
        }

        struct pcap_pkthdr info;
        info.caplen = packet->capLen;
        info.len = packet->packetSize;
        info.ts = packet->timestamp;

        if ( info.caplen > info.len )
            info.caplen = info.len;

        pcap_dump((u_char*)dump, &info, packet->rawData);
    }

    pcap_dump_close(dump);
    pcap_close(handle);

    return TRUE;
}
