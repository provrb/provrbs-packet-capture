#ifndef _CLI_H_
#define _CLI_H_

#include <time.h>

char* GetTimeAsString() {
    char formatted[30];
    time_t timer = time(NULL);
    struct tm* time_info = localtime(&timer);

    strftime(formatted, 30, "%Y-%m-%d %H:%M:%S", time_info);
    return formatted;
}

void PrintPacketInfo(struct Packet* packet) {
    printf("Packet %d captured @ %s : %d bytes\n", packetCount, GetTimeAsString(), packet->packetSize);
    printf("Packet Details\n");
    if ( IsIPV4Packet(packet) ) {
        printf("Source IP        : %d.%d.%d.%d\n", packet->h_ip.ip4.sourceIP[0], packet->h_ip.ip4.sourceIP[1], packet->h_ip.ip4.sourceIP[2], packet->h_ip.ip4.sourceIP[3]);
        printf("Destination IP   : %d.%d.%d.%d\n", packet->h_ip.ip4.destIP[0], packet->h_ip.ip4.destIP[1], packet->h_ip.ip4.destIP[2], packet->h_ip.ip4.destIP[3]);
    }
    else if ( IsIPV6Packet(packet) ) {
        printf("Source IP        : %s\n", CompressIPV6Address(packet->h_ip.ip6.sourceAddr));
        printf("Destination IP   : %s\n", CompressIPV6Address(packet->h_ip.ip6.destAddr));
    }
     
    if ( GetPacketProtocol(packet) == ICMP ) {
        printf("Type             : %d\n", packet->h_proto.icmp.type);
        printf("Code             : %d\n", packet->h_proto.icmp.code);
        printf("Checksum         : 0x%02x%02x\n", packet->h_proto.icmp.checksum[0], packet->h_proto.icmp.checksum[1]);
        printf("Flags            : 0x%02x%02x%02x%02x\n", packet->h_proto.icmp.flags[0], packet->h_proto.icmp.flags[1], packet->h_proto.icmp.flags[2], packet->h_proto.icmp.flags[3]);
    }
    else if ( GetPacketProtocol(packet) == TCP ) {
        char* flags = GetStringTCPFlagsSet(packet);
        if ( flags != NULL ) {
            printf("Flags set        : %s\n", flags);
            free(flags);
        }

        printf("Checksum         : 0x%02x%02x\n", packet->h_proto.tcp.checksum[0], packet->h_proto.tcp.checksum[1]);
        printf("Window           : %d\n", ( packet->h_proto.tcp.window[0] << 8 ) | packet->h_proto.tcp.window[1]);
        printf("Urgent Pointer   : %d\n", ( packet->h_proto.tcp.urgentPtr[0] << 8 ) | packet->h_proto.tcp.urgentPtr[1]);
        
    }

    if ( packet->tls.usesTLS ) {
        enum TLSVersions ver = packet->tls.tlsVersionID;
        printf("TLS Encrypted.\n");
        printf("TLS Version      : %s\n", GetStringTLSVersion(ver));
        printf("TLS Length       : %02x%02x\n", packet->tls.encryptedPayloadLen[0], packet->tls.encryptedPayloadLen[1]);
        printf("Content Type     : %d\n", packet->tls.contentType);
    }

    printf("Source MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n", 
        packet->h_ethernet.source[0],
        packet->h_ethernet.source[1],
        packet->h_ethernet.source[2],
        packet->h_ethernet.source[3],
        packet->h_ethernet.source[4],
        packet->h_ethernet.source[5]
    );

    printf("Destination MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet->h_ethernet.dest[0],
        packet->h_ethernet.dest[1],
        packet->h_ethernet.dest[2],
        packet->h_ethernet.dest[3],
        packet->h_ethernet.dest[4],
        packet->h_ethernet.dest[5]
    );

    if ( !IsARPPacket(packet) ) {
        printf("Source Port      : %d\n", GetSourcePort(packet));
        printf("Destination Port : %d\n", GetDestPort(packet));
    }
    
    
    printf("IP Version       : %s\n", GetStringIPV(GetIPVersion(packet)));
    printf("Protocol         : %s\n", GetStringProtocol(GetPacketProtocol(packet)));
    printf("Payload size     : %d\n", packet->payloadSize);

    printf("\nDumped Contents (Hex)");

}

void PacketHexDump(struct Packet* packet) {
    // print raw data
    u_char ascii[17];
    int chars = 0;
    for ( int i = 0; i < packet->packetSize; i++ ) {
        // find ascii. check if its printable. if so add.
        u_char asciiChar = ( u_char ) packet->rawData[i];
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


        printf("%02X ", packet->rawData[i]);
        chars++;
    }
}

#endif