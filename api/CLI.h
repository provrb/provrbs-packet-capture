#pragma once

#include <time.h>
#include <Packets.h>

char* GetTimeAsString() {
    char formatted[30];
    time_t timer = time(NULL);
    struct tm* time_info = localtime(&timer);

    strftime(formatted, 30, "%H:%M:%S", time_info);
    return formatted;
}

void PrintPacketInfo(struct Packet* packet) {
    printf("Packet captured at %s. (%d bytes.)\n", GetTimeAsString(), packet->packetSize);
    printf("Packet Details\n");
    if ( IsIPV4Packet(&packet) ) {
        printf("Source IP        : %d.%d.%d.%d\n", packet->h_ip.ip4.sourceIP[0], packet->h_ip.ip4.sourceIP[1], packet->h_ip.ip4.sourceIP[2], packet->h_ip.ip4.sourceIP[3]);
        printf("Destination IP   : %d.%d.%d.%d\n", packet->h_ip.ip4.destIP[0], packet->h_ip.ip4.destIP[1], packet->h_ip.ip4.destIP[2], packet->h_ip.ip4.destIP[3]);
    }
    else if ( IsIPV6Packet(&packet) ) {
        printf("Source IP        : %s\n", CompressIPV6Address(packet->h_ip.ip6.sourceAddr));
        printf("Destination IP   : %s\n", CompressIPV6Address(packet->h_ip.ip6.destAddr));
    }

    if ( GetPacketProtocol(&packet) == ICMP ) {
        printf("Type             : %d\n", packet->h_proto.icmp.type);
        printf("Code             : %d\n", packet->h_proto.icmp.code);
        printf("Checksum         : 0x%02x%02x\n", packet->h_proto.icmp.checksum[0], packet->h_proto.icmp.checksum[1]);
        printf("Flags            : 0x%02x%02x%02x%02x\n", packet->h_proto.icmp.flags[0], packet->h_proto.icmp.flags[1], packet->h_proto.icmp.flags[2], packet->h_proto.icmp.flags[3]);
    }

    printf("Source Port      : %d\n", GetSourcePort(&packet));
    printf("Destination Port : %d\n", GetDestPort(&packet));
    printf("IP Version       : %s\n", GetStringIPV(GetIPVersion(&packet)));
    printf("Protocol         : %s\n", GetStringProtocol(GetPacketProtocol(&packet)));
    printf("Payload size     : %d\n", packet->payloadSize);

    printf("\nDumped Contents (Hex)");
}

void PacketHexDump(struct Packet* packet) {
    // print raw data
    u_char ascii[17];
    int chars = 0;
    for ( int i = 0; i < packet->packetSize; i++ ) {
        // find ascii. check if its printable. if so add.
        u_char asciiChar = ( u_char ) packet->payload[i];
        if ( isprint(asciiChar) )
            ascii[chars] = asciiChar;
        else
            ascii[chars] = '.';

        if ( i % 16 == 0 && i != 0 ) // end of the line 
        {
            printf(" ");
            printf("%s", ascii);
            printf("\n0x%07X: ", i);
            chars = 0;
        }
        else if ( i == 0 ) {
            printf("\n0x%07X: ", i);
        }
        else if ( i % 8 == 0 ) // middle of the line
            printf(" ");


        printf("%02X ", packet->payload[i]);
        chars++;
    }
}
