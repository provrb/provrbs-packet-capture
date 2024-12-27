#ifndef _PACKET_OP_H_
#define _PACKET_OP_H_

#include <types.h>
#include <WinSock2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Global C variables. */
static uint32_t g_cPacketCount = 1;
static BOOL     g_cCapturePackets = TRUE;
static uint32_t g_cNumOpenNICHandles = 0;
static pcap_t** g_cOpenNICHandles = NULL; // must be malloc'd before using

/**
* Get a string representation of the TCP flags set in the packet.
* @param packet Pointer to the Packet structure.
* @return char* String representation of the TCP flags.
*/
char* GetStringTCPFlagsSet(struct Packet* packet);

/**
* Check if the packet is suspected to be an HTTP request.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if suspected to be an HTTP request, FALSE otherwise.
*/
BOOL IsSuspectedHTTPRequest(struct Packet* packet);

/**
* Check if the packet is a keep-alive packet.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it is a keep-alive packet, FALSE otherwise.
*/
BOOL IsKeepAlivePacket(struct Packet* packet);

/**
* Check if the packet is a DNS query.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it is a DNS query, FALSE otherwise.
*/
BOOL IsDNSQuery(struct Packet* packet);

/**
* Check if a specific TCP flag is set in the packet.
* @param packet Pointer to the Packet structure.
* @param flag TCP flag to check.
* @return BOOL TRUE if the flag is set, FALSE otherwise.
*/
BOOL IsTCPFlagSet(struct Packet* packet, enum TCPFlags flag);

/**
* Check if the packet is an ARP packet.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it is an ARP packet, FALSE otherwise.
*/
BOOL IsARPPacket(struct Packet* packet);

/**
* Check if the MAC address is a broadcast address.
* @param mac Pointer to the MAC address.
* @return BOOL TRUE if it is a broadcast address, FALSE otherwise.
*/
BOOL IsBroadcastMAC(u_char* mac);

/**
* Check if the packet includes a link-layer address.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it includes a link-layer address, FALSE otherwise.
*/
BOOL IncludesLinkLayerAddr(struct Packet* packet);

/**
* Filter the packet based on predefined criteria.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if the packet passes the filter, FALSE otherwise.
*/
BOOL FilterPacket(struct Packet* packet);

/**
* Get the IP version of the packet.
* @param packet Pointer to the Packet structure.
* @return enum IPVersion IP version of the packet.
*/
enum IPVersion GetIPVersion(struct Packet* packet);

/**
* Check if the packet is an IPv6 packet.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it is an IPv6 packet, FALSE otherwise.
*/
BOOL IsIPV6Packet(struct Packet* packet);

/**
* Check if the packet is an IPv4 packet.
* @param packet Pointer to the Packet structure.
* @return BOOL TRUE if it is an IPv4 packet, FALSE otherwise.
*/
BOOL IsIPV4Packet(struct Packet* packet);

/**
* Get the destination port of the packet.
* @param packet Pointer to the Packet structure.
* @return uint32_t Destination port of the packet.
*/
uint32_t GetDestPort(struct Packet* packet);

/**
* Get the source port of the packet.
* @param packet Pointer to the Packet structure.
* @return uint32_t Source port of the packet.
*/
uint32_t GetSourcePort(struct Packet* packet);

/**
* Get the protocol of the packet.
* @param packet Pointer to the Packet structure.
* @return enum InternetProtocol Protocol of the packet.
*/
enum InternetProtocol GetPacketProtocol(struct Packet* packet);

/**
* Convert a hexadecimal port to an integer.
* @param port Array containing the hexadecimal port.
* @return uint32_t Integer representation of the port.
*/
uint32_t HexPortToInt(u_char port[2]);

/**
* Compress an IPv6 address.
* @param address Pointer to the IPv6 address.
* @return u_char* Compressed IPv6 address.
*/
u_char* CompressIPV6Address(u_char* address);

/**
* Get the source IP address of the packet.
* @param packet Pointer to the Packet structure.
* @return u_char* Source IP address of the packet.
*/
u_char* GetSourceIPAddress(struct Packet* packet);

/**
* Get the destination IP address of the packet.
* @param packet Pointer to the Packet structure.
* @return u_char* Destination IP address of the packet.
*/
u_char* GetDestIPAddress(struct Packet* packet);

/**
* Parse raw packet data into a Packet structure.
* @param rawData Pointer to the raw packet data.
* @param packetSize Size of the packet data.
* @return struct Packet Parsed Packet structure.
*/
struct Packet ParseRawPacket(u_char* rawData, uint32_t packetSize);

/**
* Handle a captured packet.
* @param byteStrHandle Pointer to the byte string handle.
* @param pacInfo Pointer to the pcap packet header.
* @param data Pointer to the packet data.
*/
static pcap_handler HandlePacket(u_char* byteStrHandle, const struct pcap_pkthdr* pacInfo, const u_char* data);

/**
* Capture packets on a specified network interface.
* @param interfaceIndex Index of the network interface.
*/
void CapturePackets(int interfaceIndex);

/**
* Get the number of network interfaces available.
* @return int Number of network interfaces.
*/
int GetNumberOfNetworkInterfaces();

/**
* Get the names of the network interfaces available.
* @return char** Array of network interface names.
*/
char** GetNetworkInterfaceNames();

/**
* Pause packet capture.
*/
void PausePacketCapture();

/**
* Resume packet capture.
*/
void ResumePacketCapture();

/**
* Reset the packet count.
*/
void ResetPacketCount();

/**
* Get the network interface from its index.
* @param interfaceIndex Index of the network interface.
* @return pcap_if_t* Pointer to the network interface.
*/
pcap_if_t* GetNICFromIndex(int interfaceIndex);

/**
* Apply a filter to the packet capture on a specified network interface.
* @param interfaceIndex Index of the network interface.
* @param filter Filter expression to apply.
* @return BOOL TRUE if the filter was successfully applied, FALSE otherwise.
*/
BOOL ApplyFilter(int interfaceIndex, const char* filter);

BOOL DumpPacketsToFile(struct Packet** packetArray, int numberOfPackets, const char* filePath);

#ifdef __cplusplus
}
#endif
#endif
