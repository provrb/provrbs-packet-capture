#include "Packets.h"

enum IPVersion GetIPVersion(struct Packet* packet) {
    if ( packet->h_ethernet.type[0] == 134 && packet->h_ethernet.type[1] == 221 )
        return kIPV6;
    else if ( packet->h_ethernet.type[0] == 8 && packet->h_ethernet.type[1] == 0 )
        return kIPV4;

    return UnknownIPV;
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

    char compressed[INET6_ADDRSTRLEN];

    PCSTR addr = inet_ntop(AF_INET6, address, compressed, sizeof(compressed));
    if ( addr == NULL )
        return "";

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

struct Packet ParseRawPacket(u_char* rawData, uint32_t packetSize) {
    struct Packet packet;
    packet.payload = ( u_char* ) malloc(packetSize);

    int protoHeaderOffset = 0;

    for ( int index = 0; index < packetSize; index++ ) {
        // parse eth header
        if ( index < 14 ) {
            if ( index < 6 )       packet.h_ethernet.dest[index - 0] = rawData[index];
            else if ( index < 12 ) packet.h_ethernet.source[index - 6] = rawData[index];
            else                   packet.h_ethernet.type[index - 12] = rawData[index];
        }

        packet.ipVer = GetIPVersion(&packet);

        // parse ipv4 header
        if ( index < ( ETH_HEADER_SIZE + IP4_HEADER_SIZE ) && IsIPV4Packet(&packet) ) {
            if ( index == 14 )                   packet.h_ip.ip4.versionihl = rawData[index];
            else if ( index == 15 )              packet.h_ip.ip4.serviceType = rawData[index];
            else if ( index > 15 && index < 18 ) packet.h_ip.ip4.headerSize[index - 16] = rawData[index];
            else if ( index > 17 && index < 20 ) packet.h_ip.ip4.id[index - 18] = rawData[index];
            else if ( index > 19 && index < 22 ) packet.h_ip.ip4.flags[index - 20] = rawData[index];
            else if ( index == 22 )              packet.h_ip.ip4.ttl = rawData[index];
            else if ( index == 23 )              packet.h_ip.ip4.protocol = rawData[index];
            else if ( index > 23 && index < 26 ) packet.h_ip.ip4.checksum[index - 24] = rawData[index];
            else if ( index > 25 && index < 30 ) packet.h_ip.ip4.sourceIP[index - 26] = rawData[index];
            else                                 packet.h_ip.ip4.destIP[index - 30] = rawData[index];
        }

        // parse ipv6 header
        else if ( index < ( ETH_HEADER_SIZE + IP6_HEADER_SIZE ) && IsIPV6Packet(&packet) ) {
            if ( index == 14 )                   packet.h_ip.ip6.versionihl = rawData[index];
            else if ( index > 14 && index < 18 ) packet.h_ip.ip6.flowLabel[index - 15] = rawData[index];
            else if ( index > 17 && index < 20 ) packet.h_ip.ip6.payloadLen[index - 18] = rawData[index];
            else if ( index == 20 )              packet.h_ip.ip6.nextHeader = rawData[index];
            else if ( index == 21 )              packet.h_ip.ip6.hopLimit = rawData[index];
            else if ( index > 21 && index < 38 ) packet.h_ip.ip6.sourceAddr[index - 22] = rawData[index];
            else {
                packet.h_ip.ip6.destAddr[index - 38] = rawData[index];
                protoHeaderOffset = ( IsIPV6Packet(&packet) ) ? ( ETH_HEADER_SIZE + IP6_HEADER_SIZE ) : ( ETH_HEADER_SIZE + IP4_HEADER_SIZE );
            }
        }

        // tcp header
        if ( GetPacketProtocol(&packet) == TCP && index >= protoHeaderOffset && index <= protoHeaderOffset + TCP_MIN_HEADER_SIZE ) {
            if ( index < protoHeaderOffset + 2 )       packet.h_proto.tcp.sourcePort[index - protoHeaderOffset] = rawData[index];
            else if ( index < protoHeaderOffset + 4 )  packet.h_proto.tcp.destPort[index - (protoHeaderOffset + 2)] = rawData[index];
            else if ( index < protoHeaderOffset + 8 )  packet.h_proto.tcp.sequenceNum[index - (protoHeaderOffset + 4)] = rawData[index];
            else if ( index < protoHeaderOffset + 12 ) packet.h_proto.tcp.ackNum[index - (protoHeaderOffset + 8)] = rawData[index];
            else if ( index == protoHeaderOffset + 12 ) {
                packet.h_proto.tcp.len = rawData[index] / 4; // tcp header len
                packet.payloadSize = packetSize - (packet.h_proto.tcp.len + protoHeaderOffset );
            }
        }

        // udp header
        else if ( GetPacketProtocol(&packet) == UDP && index >= protoHeaderOffset && index < protoHeaderOffset + UDP_HEADER_SIZE ) {
            if ( index < protoHeaderOffset + 2 )      packet.h_proto.udp.sourcePort[index - protoHeaderOffset] = rawData[index];
            else if ( index < protoHeaderOffset + 4 ) packet.h_proto.udp.destPort[index - ( protoHeaderOffset + 2 )] = rawData[index];
            else if ( index < protoHeaderOffset + 6 ) {
                packet.h_proto.udp.len[index - ( protoHeaderOffset + 4 )] = rawData[index]; // udp header len

                if ( index - ( protoHeaderOffset + 4 ) == 1 ) // set payload size
                    packet.payloadSize = ((packet.h_proto.udp.len[0] << 8) | packet.h_proto.udp.len[1]) - UDP_HEADER_SIZE;
            }
            else packet.h_proto.udp.checksum[index - ( protoHeaderOffset - 6 )] = rawData[index];
        } 

        // icmp header
        else if ( GetPacketProtocol(&packet) == ICMP && index >= protoHeaderOffset && index <= protoHeaderOffset + ICMP_HEADER_SIZE ) {
            if ( index < protoHeaderOffset )  packet.h_proto.icmp.type = rawData[index];
            else if ( index < protoHeaderOffset + 1 ) packet.h_proto.icmp.code = rawData[index];
            else if ( index < protoHeaderOffset + 3 ) packet.h_proto.icmp.checksum[index - ( protoHeaderOffset + 3 )] = rawData[index];
            else if ( index < protoHeaderOffset + 5 ) packet.h_proto.icmp.flags[index - ( protoHeaderOffset + 5 )] = rawData[index];
        }

        // payload
        else {
            int payloadStart = ( GetPacketProtocol(&packet) == TCP ) ? protoHeaderOffset + packet.h_proto.tcp.len : protoHeaderOffset + UDP_HEADER_SIZE;

            if ( packet.payload && index >= payloadStart )
                packet.payload[index - payloadStart] = rawData[index];
        }
    }

    return packet;
}

static pcap_handler HandlePacket(u_char* byteStrHandle, const struct pcap_pkthdr* pacInfo, const u_char* data) {
    if ( pacInfo->len > 400 )
        return;

    // parse headers

    // todo. add IPV6 support as IPV4 is only supported 
    struct Packet packet = ParseRawPacket(data, pacInfo->len);
    if ( packet.ipVer == UnknownIPV )
        return;

    if ( GetPacketProtocol(&packet) == UDP || GetPacketProtocol(&packet) == UNKNOWN || IsIPV4Packet(&packet) )
        return;

    if ( IsIPV4Packet(&packet) ) {
        printf("Source IP:        %d.%d.%d.%d\n", packet.h_ip.ip4.sourceIP[0], packet.h_ip.ip4.sourceIP[1], packet.h_ip.ip4.sourceIP[2], packet.h_ip.ip4.sourceIP[3]);
        printf("Destination IP:   %d.%d.%d.%d\n", packet.h_ip.ip4.destIP[0], packet.h_ip.ip4.destIP[1], packet.h_ip.ip4.destIP[2], packet.h_ip.ip4.destIP[3]);
    }
    else if ( IsIPV6Packet(&packet) ) {
        printf("Source IP:        %s\n", CompressIPV6Address(packet.h_ip.ip6.sourceAddr));
        printf("Destination IP:   %s\n", CompressIPV6Address(packet.h_ip.ip6.destAddr));
    } 
    else if ( GetPacketProtocol(&packet) == ICMP ) {
        printf("Type:             %d", packet.h_proto.icmp.type);
        printf("Code:             %d", packet.h_proto.icmp.code);
    }

    printf("Source Port:      %d\n", GetSourcePort(&packet));
    printf("Destination Port: %d\n", GetDestPort(&packet));
    printf("Protocol:         %d\n", GetPacketProtocol(&packet));
    printf("Payload size:     %d\n", packet.payloadSize);

    // print raw data
    for ( int i = 0; i < pacInfo->len; i++ ) {
        if ( i % 16 == 0 ) printf("\n");
        printf("%02X ", data[i]);
    }

    free(packet.payload);

    printf("\n\n");
}

void CapturePackets() {
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
