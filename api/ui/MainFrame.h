#pragma once

#ifndef _CLI_

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <packets.h>
#include <unordered_map>
#include <wx/clipbrd.h>
#include <enumnames.h>

enum Windows {
    kPacketListPanel = 0x832,
    kPacketInfoPanel = 0x30,
    kHexDumpTextPane = 0x92,
};

enum Menus {
    kClearAllPackets = 0x9128,
    kDeleteAllPackets = 5,
    kSelectNetworkInterface = 6,
    kStartCapturingPackets = 8,
    KStopPacketCapture = 10,
};

enum SortOrder {
    Ascending = 231,
    Descending = 492,
};

struct SortData {
    wxListView* listView;
    int column;
    bool ascending;
};

class MainFrame : public wxFrame
{
public:
    MainFrame(const wxString& title);
    
    /*
    * Functions for writing data to the packet
    * info panel such as ARP or TCP header data
    */
    void WriteARPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void WriteTCPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void WriteEthernetHeader(wxTextCtrl* packetInfoText, Packet packet);
    void WriteIPV4Header(wxTextCtrl* packetInfoText, Packet packet);
    void WriteIPV6Header(wxTextCtrl* packetInfoText, Packet packet);
    void WriteICMPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void WriteUDPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void WritePacketInfoFooter(wxTextCtrl* packetInfoText, Packet packet); // write a quick summary/recap at the bottom with all the protocols

    /*
    * Display all respective information about a packet
    * when a packet in the list view is clicked
    */
    void ShowPacketInformation(wxCommandEvent& event);

    void InsertPacket(
        const wxString& packetNo,
        const wxString& ipv,
        const wxString& srcAddr, 
        const wxString& destAddr, 
        const wxString& protocol, 
        const wxString& srcPort, 
        const wxString& destPort, 
        const wxString& packetSize,
        const wxString& description
    );

    /*
    * Events handling 
    */
    void OnHeaderClicked(wxListEvent& event);
    void HexDumpRightClicked(wxCommandEvent& event);
    
    static int wxCALLBACK SortItem(wxIntPtr item1Index, wxIntPtr item2Index, wxIntPtr data);

    /*
    * Formatting for front end
    */
    static wxString MakeReadableIPV4Address(u_char* ipv4Addr);
    static wxString MakeReadableMACAddress(u_char* mac);

    /*
    * Commands called usually from events.
    * for example, clear packets can be called from clicking
    * File -> Clear 
    */
    void ClearPackets(wxCommandEvent& event);
    void DeleteAllPackets(wxCommandEvent& event);
    void CopyRawHex(wxCommandEvent& event);

    Packet GetSelectedPacketInfo();

    std::unordered_map<long, Packet> packets;
    bool sortAscending = false;
    long shownPacketIndex = -1; // the packet index that is being display in packet info panel
    std::vector<int> selectedNicIndexes = {};
    bool capturingPackets = false;
    bool endedPacketCapture = false;
    uint32_t displayedPacketCount = 0;
};

#endif
