#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <npcap/pcap.h>
#include "Hexdump.h"

struct Packet {
    struct {
        u_char dest[6];
        u_char source[6];
        u_char type[2];
    } h_ethernet; // 14 bytes

    struct {
        u_char versionihl;
        u_char serviceType;
        u_char headerSize[2];
        u_char id[2];
        u_char flags[2];
        u_char ttl;
        u_char protocol;
        u_char checksum[2];
        u_char sourceIP[4];
        u_char destIP[4];
    } h_ip; // 20 bytes

    struct {
        u_char sourcePort[2];
        u_char destPort[2];
        u_char len[2];
        u_char checksum[2];
    } h_udp; // 8 bytes

    struct {
        u_char sourcePort[2];
        u_char destPort[2];
        u_char sequenceNum[4];
        u_char ackNum[4];
        u_char len;
        u_char congWinFlag;
        u_char window[2];
        u_char checksum[2];
        u_char urgentPtr[2];
    } h_tcp; // unknown size 20-60 bytes

    int payloadSize; // h_udp.len - 8 bytes
    u_char* payload; // malloc packet len - size of all headers
};

const char* GetPacketProtocol(struct Packet* packet) {
    const char* protocol = "";

    if ( packet->h_ethernet.type[0] == 134 && packet->h_ethernet.type[1] == 221 ) {
        printf("IPV6!!!");
        protocol = "IPV6";
        return protocol;
    }

    switch ( packet->h_ip.protocol ) 
    {
    case 6:
        protocol = "TCP";
        break;
    case 1:
        protocol = "ICMP";
        break;
    case 2:
        protocol = "IGMP";
        break;
    case 17:
        protocol = "UDP";
        break;
    default:
        break;
    }
    return protocol;
}

uint32_t HexPortToInt(u_char port[2]) {
    return ( port[0] << 8 ) | port[1];
}

struct Packet ParseRawPacket(u_char* rawData, uint32_t packetSize) {
    struct Packet packet;
    packet.payload = (u_char*)malloc(packetSize);

    for ( int index = 0; index < packetSize; index++ ) {
        // parse eth header
        if ( index < 14 ) {
            if ( index < 6 )       packet.h_ethernet.dest[index - 0] = rawData[index];
            else if ( index < 12 ) packet.h_ethernet.source[index - 6] = rawData[index];
            else                   packet.h_ethernet.type[index - 12] = rawData[index];
        }
        // parse ip header
        else if ( index < 34 ) {
            if ( index == 14 )                   packet.h_ip.versionihl = rawData[index];
            else if ( index == 15 )              packet.h_ip.serviceType = rawData[index];
            else if ( index > 15 && index < 18 ) packet.h_ip.headerSize[index - 16] = rawData[index];            
            else if ( index > 17 && index < 20 ) packet.h_ip.id[index - 18] = rawData[index];
            else if ( index > 19 && index < 22 ) packet.h_ip.flags[index - 20] = rawData[index];
            else if ( index == 22 )              packet.h_ip.ttl = rawData[index];
            else if ( index == 23 )              packet.h_ip.protocol = rawData[index];
            else if ( index > 23 && index < 26 ) packet.h_ip.checksum[index - 24] = rawData[index];
            else if ( index > 25 && index < 30 ) packet.h_ip.sourceIP[index - 26] = rawData[index];
            else                                 packet.h_ip.destIP[index - 30] = rawData[index];
        }

        // tcp header
        if ( strcmp(GetPacketProtocol(&packet), "TCP") == 0 && index < 47 ) {
            printf("Parsing TCP header. %d\n", index);
            if ( index > 33 && index < 36 )
                packet.h_tcp.sourcePort[index - 34] = rawData[index];
            else if ( index > 35 && index < 38 )
                packet.h_tcp.destPort[index - 36] = rawData[index];
            else if ( index > 37 && index < 42 )
                packet.h_tcp.sequenceNum[index - 38] = rawData[index];
            else if ( index > 41 && index < 46 )
                packet.h_tcp.ackNum[index - 42] = rawData[index];
            else if ( index == 46 ) {
                printf("Got TCP Header Length %d, %d\n", index, rawData[index]);
                packet.h_tcp.len = rawData[index]; // tcp header len
                packet.payloadSize = packetSize - ( ( ( int ) packet.h_tcp.len ) + 20 + 14 );
            }
        } else if ( index < 42 ) {
            // udp header
            if ( index > 33 && index < 36 )
                packet.h_udp.sourcePort[index - 34] = rawData[index];
            else if ( index > 35 && index < 38 )
                packet.h_udp.destPort[index - 36] = rawData[index];
            else if ( index > 37 && index < 40 ) {
                packet.h_udp.len[index - 38] = rawData[index]; // udp header len
                if ( ( index - 38 ) == 1 ) // set payload size
                    packet.payloadSize = ( packet.h_udp.len[0] << 8 ) | packet.h_udp.len[1];
            }
            else {
                packet.h_udp.checksum[index - 40] = rawData[index];
            }
        }

        // payload
        else {
            if ( strcmp(GetPacketProtocol(&packet), "TCP") == 0 ) {
                printf("Payload\n");
                // tcp payload
                int payloadStart = 20 + 14 + ((int)packet.h_tcp.len);
                if ( index >= payloadStart ) {
                    packet.payload[index - payloadStart] = rawData[index];
                }
            }
            else {
                if ( packet.payload )
                    packet.payload[index - 42] = rawData[index];
            }
        }
    } 
    
    return packet;
}

static pcap_handler HandlePacket(u_char* byteStrHandle, const struct pcap_pkthdr* pacInfo, const u_char* data) {
    if ( pacInfo->len > 400 )
        return;    

    // parse headers
    struct Packet packet = ParseRawPacket(data, pacInfo->len);
    if ( strcmp(GetPacketProtocol(&packet), "TCP") != 0 )
        return;

    printf("Source IP:        %d.%d.%d.%d\n", packet.h_ip.sourceIP[0], packet.h_ip.sourceIP[1], packet.h_ip.sourceIP[2], packet.h_ip.sourceIP[3]);
    printf("Destination IP:   %d.%d.%d.%d\n", packet.h_ip.destIP[0], packet.h_ip.destIP[1], packet.h_ip.destIP[2], packet.h_ip.destIP[3]);
    printf("Source Port:      %d\n", HexPortToInt(packet.h_udp.sourcePort));
    printf("Destination Port: %d\n", HexPortToInt(packet.h_udp.destPort));
    printf("Protocol:         %s\n", GetPacketProtocol(&packet) );
    printf("Payload size:     %d\n", packet.payloadSize);

    // print raw data
    hexdump(data, pacInfo->len);

    free(packet.payload);

    printf("\n\n");
}

int main() {
    // error buffers
    char devErrBuff[PCAP_ERRBUF_SIZE];
    char openLiveErrBuff[PCAP_ERRBUF_SIZE];

    BOOL captureAllTraffic = FALSE;
    pcap_if_t* dev;

    if ( pcap_findalldevs(&dev, &devErrBuff) != 0 ) {
        printf("There was an error finding all devices.\n");
        return -1;
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

    return 0;
}
