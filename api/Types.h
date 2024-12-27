#pragma once

#define _CRT_SECURE_NO_WARNINGS 1

#define ETH_HEADER_SIZE 14
#define IP6_HEADER_SIZE 40
#define IP4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define TCP_MIN_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8
#define ARP_HEADER_SIZE 27
#define ICMP6_HEADER_SIZE 31
#define DNS_QUERY_PORT 53

#define APP_NAME "ProCapture"

#include <ctype.h>
#include <npcap/pcap.h>

enum IPVersion {
    UnknownIPV = -1,
    kIPV4 = 1,
    kIPV6,
    kARP = 0x806 // 'type' in eth header if is arp packet
};

enum TLSVersions {
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303,
    TLS1_3 = 0x0304
};

enum TCPFlags {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0X20,
    ECE = 0x40,
    CWR = 0x80,
    NS = 0x100,
};

enum TLSContentType {
    ApplicationData = 0x17,
};

enum HTTPVersions {
    HTTP1_0 = 0x0100,
    HTTP1_1 = 0x0101,
    HTTP2   = 0x0200,
    HTTP3   = 0x0300
};

enum ICMPTypes {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    RedirectMessage = 137
};

enum ICMP6Type2 {
    SourceLinkLayerAddress = 1
};

enum InternetProtocol {
    ICMPHEADER2 = 0,
    UNKNOWN = -1,
    ICMP4 = 1, // icmp is 1 in ipv4 headers 'protocol'
    ICMP6 = 49,
    ICMP = 58, // icmp is 58 in ipv6 headers 'next header'
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ARP = 99,
    HTTP
};

/**
 * Packet struct represents a network packet. 
 * Encapsulates various headers (Ethernet, IP, UDP, TCP) 
 * and associated metadata,
 * including the payload and protocol information.
 */
struct Packet 
{
    enum IPVersion ipVer; // ip version the packet contains
    enum InternetProtocol protocol; // internet protocol used
    
    int payloadSize; // h_udp.len - 8 bytes
    u_char* payload; // malloc packet len - size of all headers
    uint32_t packetSize; // full packet size including all headers and payload
    uint32_t capLen; // length of portion
    struct timeval timestamp;
    u_char* rawData;
    uint32_t packetNumber;

    BOOL likelyHTTP; // if the packet is suspected to be an http request based off string comparisons
    enum HTTPVersions httpVer; // if 'likelyHTTP', the http version in the packet

    struct {
        BOOL usesTLS;
        u_char contentType;
        u_char tlsVersion[2];
        enum TLSVersions tlsVersionID;
        u_char encryptedPayloadLen[2];
    } tls;

    /**
     * Parsed packet Ethernet header.
     * Contains destination MAC address, source MAC address, and type.
     */
    struct 
    {
        u_char dest[6];
        u_char source[6];
        u_char type[2];
    } h_ethernet; // 14 bytes

    /**
     * Parsed IP headers.
     * Only 1, either IPV4 or IPV6  will be present.
     */
    union {
        /**
         * Parsed packet IPV4 header.
         * Only present on IPV4 packets.
         *
         * Contains version, header size, service type, id, flags, time to live in hops,
         * protocol, checksum, source IP (ipv4 addr), and destination IP (ipv4 addr).
         */
        struct
        {
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
        } ip4; // 20 bytes

        /**
         * Parsed packet IPV6 header.
         * Only present on packets using IPV6.
         *
         * Contains version, flow label, payload length, next header, hop limit, source IP (ipv6 addr), and destination IP (ipv6 addr).
         */
        struct
        {
            u_char versionihl;
            u_char flowLabel[3];
            u_char payloadLen[2];
            u_char nextHeader; // enum InternetProtocol
            u_char hopLimit;
            u_char sourceAddr[16];
            u_char destAddr[16];
        } ip6; // 40 bytes
    } h_ip;

    /**
     * Parsed protocol headers.
     */
    union {
        struct {
            u_char opcode[2];
            u_char senderIP[4];
            u_char targetIP[4];
        } arp; // only includes important info

        struct
        {
            u_char sourcePort[2];
            u_char destPort[2];
            u_char len[2];
            u_char checksum[2];
        } udp; // 8 bytes

        struct
        {
            u_char sourcePort[2];
            u_char destPort[2];
            u_char sequenceNum[4];
            u_char ackNum[4];
            u_char len;
            u_char congWinFlag;
            u_char window[2];
            u_char checksum[2];
            u_char urgentPtr[2];
        } tcp; // unknown size 20-60 bytes

        struct {
            u_char type;
            u_char code;
            u_char targetAddr[16];
            u_char checksum[2];
            u_char flags[4];
            u_char type2; // only for icmpv6
            u_char llPayloadSize; // link layer payload size only for icmpv6
            u_char lladdress[6]; // link layer address only for icmpv6
        } icmp;
    } h_proto;
};