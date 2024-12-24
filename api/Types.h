#pragma once

#define _CRT_SECURE_NO_WARNINGS 1

#define ETH_HEADER_SIZE 14
#define IP6_HEADER_SIZE 40
#define IP4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define TCP_MIN_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8

#include <ctype.h>
#include <npcap/pcap.h>

enum IPVersion 
{
    UnknownIPV = -1,
    kIPV4 = 1,
    kIPV6,
};

enum InternetProtocol 
{
    ICMPHEADER2 = 0,
    UNKNOWN = -1,
    TCP = 6,
    ICMP = 58,
    UDP = 17,
    IGMP = 2,
};

enum Events 
{
    EVT_PACKET_RECEIVED = 0x40,
};

/**
 * Packet struct represents a network packet. 
 * Encapsulates various headers (Ethernet, IP, UDP, TCP) 
 * and associated metadata,
 * including the payload and protocol information.
 */
struct Packet 
{
    enum IPVersion ipVer;
    enum InternetProtocol protocol;
    int payloadSize; // h_udp.len - 8 bytes
    u_char* payload; // malloc packet len - size of all headers
    uint32_t packetSize;
    u_char* rawData;
    uint32_t packetNumber;
    time_t timestamp;

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
     * Contains either UDP or TCP header information.
     */
    union {
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
            u_char checksum[2];
            u_char flags[4];
        } icmp;
    } h_proto;
};