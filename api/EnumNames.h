#pragma once

#include <unordered_map>
#include <types.h>

#define ENUM_NAMES_FOR(e) static std::unordered_map<e, const char*>

template <typename _Enum>
const char* GetEnumName(ENUM_NAMES_FOR(_Enum) names, _Enum e) {
    try {
        return names.at(e);
    }
    catch ( ... ) {
        return "";
    }
}

ENUM_NAMES_FOR(IPVersion) IPVersionNames 
{
    {UnknownIPV, "Unknown" },
    {kIPV4, "IPv4"},
    {kIPV6, "IPv6"},
    {kARP, "ARP"}
};

ENUM_NAMES_FOR(InternetProtocol) InternetProtocolNames 
{
    {ICMPHEADER2, "ICMP"},
    {UNKNOWN, "Unknown"},
    {IGMP, "IGMP"},
    {TCP, "TCP"},
    {UDP, "UDP"},
    {ICMP4, "ICMP"}, // 1 is icmp in protoocl for ipv4 headers
    {ICMP, "ICMP"},
    {ICMP6, "ICMPv6"},
    {ARP, "ARP"},
    {HTTP, "HTTP"}
};

ENUM_NAMES_FOR(HTTPVersions) HTTPVersionNames 
{
    {HTTP1_0, "HTTP/1.0"},
    {HTTP1_1, "HTTP/1.1"},
    {HTTP2, "HTTP/2"},
    {HTTP3, "HTTP/3"}
};

ENUM_NAMES_FOR(TLSVersions) TLSVersionNames 
{
    {TLS1_0, "TLS 1.0"},
    {TLS1_1, "TLS 1.1"},
    {TLS1_2, "TLS 1.2"},
    {TLS1_3, "TLS 1.3"}
};

ENUM_NAMES_FOR(TLSContentType) TLSContentTypeNames
{
    {ApplicationData, "Application Data"}
};

ENUM_NAMES_FOR(ICMPTypes) ICMPTypeNames
{
    { DestinationUnreachable, "Destination Unreachable" },
    { PacketTooBig, "Packet exceeds MTU" },
    { TimeExceeded, "Packet hop limit exceeded" },
    { ParameterProblem, "Malformed Parameter" },
    { EchoRequest, "Echo Request" },
    { EchoReply, "Echo Reply" },
    { RouterSolicitation, "Router Solicitation" },
    { RouterAdvertisement, "Router Advertisement" },
    { NeighborSolicitation, "Neighbor Solicitation" },
    { NeighborAdvertisement, "Neighbor Advertisement" },
    { RedirectMessage, "Redirect Message" }
};
