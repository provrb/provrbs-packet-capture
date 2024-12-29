#pragma once

#ifndef _CLI_

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <packets.h>
#include <unordered_map>
#include <wx/clipbrd.h>
#include <wx/filedlg.h>
#include <enumnames.h>

// menu wx ids
#define MENU_AUTO_SCROLL 5821

enum Windows {
    kPacketListPanel = 0x832,
    kPacketInfoPanel = 0x30,
    kHexDumpTextPane = 0x92,
    kFilterTextBox = 0x39,
};

enum Menus {
    kClearAllPackets = 0x9128,
    kDeleteAllPackets = 19238,
    kSelectNetworkInterface = 4812,
    kStartCapturingPackets = 482,
    KStopPacketCapture = 10,
    kPausePacketCapture = 492,
    kResumePacketCapture = 921,
    kEnablePromMode = 5122,
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
    * Display all respective information about a packet
    * when a packet in the list view is clicked
    */
    void ShowPacketInformation(wxCommandEvent& event);

    /*
    * Insert a packet in the packet list view.
    * Include info about ipv, src and dest addr, etc
    * 
    * Can be clicked to show more information about the packet
    * on the right hand side.
    */
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
    
    /* Not used */
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
    void     ClearPackets(wxCommandEvent& event);
    void     DeleteAllPackets(wxCommandEvent& event);
    void     CopyRawHex(wxCommandEvent& event);
    Packet   GetSelectedPacketInfo();
    void     OnHeaderClicked(wxListEvent& event);
    void     HexDumpRightClicked(wxCommandEvent& event);
    void     OnOpen(wxCommandEvent& event);
    void     OnSaveAs(wxCommandEvent& event);
    void     OnSave(wxCommandEvent& event);
    void     OnClose(wxCommandEvent& event);

private:
    /*
    * Functions for writing data to the packet
    * info panel such as ARP or TCP header data
    */
    void     WriteARPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteTCPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteEthernetHeader(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteIPV4Header(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteIPV6Header(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteICMPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void     WriteUDPHeader(wxTextCtrl* packetInfoText, Packet packet);
    void     WritePacketInfoFooter(wxTextCtrl* packetInfoText, Packet packet); // write a quick summary/recap at the bottom with all the protocols

    std::vector<int> selectedNicIndexes = {};
    uint32_t displayedPacketCount = 0;
    bool     sortAscending      = false;
    long     shownPacketIndex   = -1;    // the packet index that is being display in packet info panel
    bool     endedPacketCapture = false;
    bool     autoScroll         = false;
    wxString openedFilePath = ""; // if 'isFileOpened' is true this will contain the open file path

public:
    std::unordered_map<long, Packet> packets = {};
    bool     isFileOpened     = false; // are we based off a pcap file?
    bool     capturingPackets = false;
    bool     importingPackets = false;
};

#endif
