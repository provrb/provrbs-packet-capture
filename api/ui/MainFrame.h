#pragma once

#ifndef _CLI_

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <packets.h>
#include <unordered_map>

enum Windows {
    kPacketListPanel = 3,
    kPacketInfoPanel = 0x30,
};

enum SortOrder {
    Ascending = 231,
    Descending = 492,
};

struct SortData {
    wxListView* listView;
    int column;
    bool ascending;
    std::vector<long>* itemIndices;
};

class MainFrame : public wxFrame
{
public:
    MainFrame(const wxString& title);
    void ShowPacketInformation(wxCommandEvent& event);
    void InsertPacket(
        const wxString& packetNo,
        const wxString& ipv,
        const wxString& srcAddr, 
        const wxString& destAddr, 
        const wxString& protocol, 
        const wxString& srcPort, 
        const wxString& destPort, 
        const wxString& packetSize
    );

    void OnHeaderClicked(wxListEvent& event);
    static int wxCALLBACK SortItem(wxIntPtr item1Index, wxIntPtr item2Index, wxIntPtr data);
    static wxString MakeReadableIPV4Address(u_char* ipv4Addr);
    static wxString MakeReadableMACAddress(u_char* mac);

    std::unordered_map<long, Packet> packets;
    bool sortAscending = false;
};

#endif
