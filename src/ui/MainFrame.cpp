#ifndef _CLI_

#include "ui/MainFrame.h"
#include <wx/listctrl.h>
#include <thread>
extern "C" {
#include <packets.h>
}

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title), sortAscending(true)
{
    wxMenu* menuFile = new wxMenu;
    menuFile->Append(wxID_NEW);
    menuFile->AppendSubMenu(new wxMenu, "&Open Recent");
    menuFile->AppendSubMenu(new wxMenu, "&Import from Hex Dump");
    menuFile->Append(wxID_OPEN);
    menuFile->Append(wxID_CLOSE);
    menuFile->AppendSeparator();

    menuFile->Append(wxID_SAVE);
    menuFile->Append(wxID_SAVEAS);

    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);

    wxMenu* menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);

    wxMenuBar* menuBar = new wxMenuBar;
    menuBar->Append(menuFile, "&File");
    menuBar->Append(menuHelp, "&Help");

    SetMenuBar(menuBar);

    CreateStatusBar();
    SetStatusText("Not capturing packets");

    // panels
    wxPanel* panel = new wxPanel(this, wxID_ANY);

    // packet list panel
    wxPanel* packetListPanel = new wxPanel(panel, wxID_ANY, wxDefaultPosition);

    wxListView* packetListView = new wxListView(packetListPanel, kPacketListPanel, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
    packetListView->AppendColumn("Packet No.", wxLIST_FORMAT_LEFT, 80);
    packetListView->AppendColumn("IP Version", wxLIST_FORMAT_LEFT, 120);
    packetListView->AppendColumn("Source Address", wxLIST_FORMAT_LEFT, 155);
    packetListView->AppendColumn("Dest. Address", wxLIST_FORMAT_LEFT, 155);
    packetListView->AppendColumn("Protocol", wxLIST_FORMAT_LEFT, 75);
    packetListView->AppendColumn("Src. Port", wxLIST_FORMAT_LEFT, 80);
    packetListView->AppendColumn("Dest. Port", wxLIST_FORMAT_LEFT, 80);
    packetListView->AppendColumn("Packet Size", wxLIST_FORMAT_LEFT, 200);
    //packetListView->Bind(wxEVT_LIST_COL_CLICK, &MainFrame::OnHeaderClicked, this);

    // packet information panel
    wxPanel* packetInfoPanel = new wxPanel(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize);
    wxTextCtrl* packetInfoText = new wxTextCtrl(packetInfoPanel, kPacketInfoPanel, "", wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);

    // hex dump panel
    wxPanel* hexDumpPanel = new wxPanel(packetInfoPanel, wxID_ANY, wxDefaultPosition, wxDefaultSize);
    wxTextCtrl* hexDumpText = new wxTextCtrl(hexDumpPanel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);

    // Set hexDumpText to fill the hexDumpPanel
    wxBoxSizer* hexDumpSizer = new wxBoxSizer(wxVERTICAL);
    hexDumpSizer->Add(hexDumpText, 1, wxEXPAND | wxALL, 0);
    hexDumpPanel->SetSizer(hexDumpSizer);

    // sizers
    wxBoxSizer* mainSizer = new wxBoxSizer(wxHORIZONTAL);
    wxBoxSizer* leftSizer = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer* rightSizer = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer* packetInfoSizer = new wxBoxSizer(wxVERTICAL);

    leftSizer->Add(packetListPanel, 1, wxEXPAND | wxALL, 5);

    packetInfoSizer->Add(new wxStaticText(packetInfoPanel, wxID_ANY, "Packet Info"), 0, wxEXPAND | wxALL, 5); // Add label
    packetInfoSizer->Add(packetInfoText, 1, wxEXPAND | wxALL, 5);
    packetInfoSizer->Add(new wxStaticText(packetInfoPanel, wxID_ANY, "Hex Dump", wxDefaultPosition, wxDefaultSize, wxALIGN_BOTTOM), 0, wxEXPAND | wxALL, 5); // Add label
    packetInfoSizer->Add(hexDumpPanel, 1, wxEXPAND | wxALL, 5);
    packetInfoPanel->SetSizer(packetInfoSizer);

    rightSizer->Add(packetInfoPanel, 1, wxEXPAND | wxALL, 5);

    mainSizer->Add(leftSizer, 4, wxEXPAND);
    mainSizer->Add(rightSizer, 4, wxEXPAND);

    panel->SetSizer(mainSizer);
    mainSizer->SetSizeHints(this);

    // Set packetListView to fill the packetListPanel
    wxBoxSizer* packetListSizer = new wxBoxSizer(wxVERTICAL);
    packetListSizer->Add(packetListView, 1, wxEXPAND | wxALL, 0);
    packetListPanel->SetSizer(packetListSizer);
}

void MainFrame::OnHeaderClicked(wxListEvent& event)
{
    sortAscending = !sortAscending;

    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);

    SortData data;
    data.ascending = sortAscending;
    data.column = event.GetColumn();
    data.listView = packetListView;

    for ( long i = 0; i < packetListView->GetItemCount(); ++i ) {
        packetListView->SetItemData(i, i);
    }

    packetListView->SortItems(SortItem, ( wxIntPtr )&data);
    packetListView->Refresh();
}

int wxCALLBACK MainFrame::SortItem(wxIntPtr item1Index, wxIntPtr item2Index, wxIntPtr data) {
    SortData* sortData = ( SortData* ) data;
    wxListView* listView = sortData->listView;


    long item1Data = listView->FindItem(-1, item1Index);
    long item2Data = listView->FindItem(-1, item2Index);

    wxString text1 = listView->GetItemText(item1Data, sortData->column);
    wxString text2 = listView->GetItemText(item2Data, sortData->column);

    int result = text1.Cmp(text2);

    return sortData->ascending ? result : -result;
}

wxColour GetColorFromProtocol(const wxString& protocol) {
    if ( protocol == "TCP" )
        return wxColour{ 255, 252, 180 };
    else if ( protocol == "UDP" )
        return wxColour{ 219, 253, 219 };
    else if ( protocol == "ICMP" )
        return wxColour{ 180, 180, 255 };
    else if ( protocol == "IGMP" )
        return wxColour{ 255, 180, 180 };

    return wxColour{ 255, 255, 255 };
}

void MainFrame::ShowPacketInformation(wxCommandEvent& e) {
    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);

    long itemIndex = packetListView->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);

    wxString index = packetListView->GetItemText(itemIndex, 0); // get packet no
    long lIndex = std::stol(index.c_str().AsChar());
    if ( !this->packets.contains(lIndex) ) {
        wxLogMessage("Packet not found in saved packets");
        return;
    }

    Packet packet = this->packets.at(lIndex);

    // show top right packet info
    wxTextCtrl* packetInfoText = ( wxTextCtrl* ) FindWindow(kPacketInfoPanel);

    wxFont font(12, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, "Consolas");
    packetInfoText->SetFont(font);

    packetInfoText->Clear();
    packetInfoText->WriteText("");
    packetInfoText->Refresh();

    wxTextAttr defaultStyle;
    defaultStyle.SetBackgroundColour(packetInfoText->GetBackgroundColour());
    defaultStyle.SetTextColour(*wxBLACK);

    wxTextAttr headerStyle;
    headerStyle.SetBackgroundColour(*wxLIGHT_GREY);
    headerStyle.SetTextColour(*wxBLACK);

    packetInfoText->SetDefaultStyle(headerStyle);
    packetInfoText->AppendText("Ethernet II header,\n");
    packetInfoText->SetDefaultStyle(defaultStyle);

    wxString ethDest = "Destionation MAC: " + MakeReadableMACAddress(packet.h_ethernet.dest);
    wxString ethSrc = "Source MAC: " + MakeReadableMACAddress(packet.h_ethernet.source);
    wxString ethType = "Type: " + std::string(GetStringIPV(GetIPVersion(&packet)));

    packetInfoText->AppendText(ethSrc + "\n");
    packetInfoText->AppendText(ethDest + "\n");
    packetInfoText->AppendText(ethType + "\n");

    packetInfoText->SetDefaultStyle(headerStyle);
    packetInfoText->AppendText("\nIP Header (" + std::string(GetStringIPV(GetIPVersion(&packet)) + std::string("),\n")));
    packetInfoText->SetDefaultStyle(defaultStyle);

    if ( IsIPV4Packet(&packet) ) {
        packetInfoText->AppendText("Source IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.sourceIP)));
        packetInfoText->AppendText("\nDestination IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.destIP)));
        packetInfoText->AppendText("\nIdentification: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.id[0], packet.h_ip.ip4.id[1]));
        packetInfoText->AppendText("\nTime to live (hops): " + wxString::Format("%d", packet.h_ip.ip4.ttl));
        packetInfoText->AppendText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.checksum[0], packet.h_ip.ip4.checksum[1]));
        packetInfoText->AppendText("\nFlags: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.flags[0], packet.h_ip.ip4.flags[1]));
        packetInfoText->AppendText("\nService Type: 0x" + wxString::Format("%02x", packet.h_ip.ip4.serviceType));
    }
    else if ( IsIPV6Packet(&packet) ) {
        packetInfoText->AppendText("Source IPv6: " + std::string(( char* ) GetSourceIPAddress(&packet)));
        packetInfoText->AppendText("\nDestination IPv6: " + std::string(( char* ) GetDestIPAddress(&packet)));
        packetInfoText->AppendText("\nFlow label: 0x" + wxString::Format("%02x%02x%02x", packet.h_ip.ip6.flowLabel[0], packet.h_ip.ip6.flowLabel[1], packet.h_ip.ip6.flowLabel[2]));
        packetInfoText->AppendText("\nNext header: " + wxString::Format("%d", packet.h_ip.ip6.nextHeader));
        packetInfoText->AppendText("\nHop limit: " + wxString::Format("%d", packet.h_ip.ip6.hopLimit));
    }

    if ( GetPacketProtocol(&packet) == TCP ) {
        // print tcp header
        packetInfoText->AppendText("\nTCP Header");
        packetInfoText->AppendText("\nSource Port: " + wxString::Format("%d", GetSourcePort(&packet)));
        packetInfoText->AppendText("\nDestination Port: " + wxString::Format("%d", GetDestPort(&packet)));
        packetInfoText->AppendText("\nSequence Number: 0x" + 
            wxString::Format("%02x%02x%02x%02x", 
                packet.h_proto.tcp.sequenceNum[0], packet.h_proto.tcp.sequenceNum[1], 
                packet.h_proto.tcp.sequenceNum[2], packet.h_proto.tcp.sequenceNum[3])
        );
        
        packetInfoText->AppendText("\nAcknowledgement Number: 0x" +
            wxString::Format("%02x%02x%02x%02x", 
                packet.h_proto.tcp.ackNum[0], packet.h_proto.tcp.ackNum[1], 
                packet.h_proto.tcp.ackNum[2], packet.h_proto.tcp.ackNum[3])
        );

        packetInfoText->AppendText("\nHeader length: " + wxString::Format("%d", packet.h_proto.tcp.len));
        packetInfoText->AppendText("\nCongestion Window Reduced: " + wxString::Format("%d", packet.h_proto.tcp.congWinFlag));
        packetInfoText->AppendText("\nWindow: " + wxString::Format("%d", HexPortToInt(packet.h_proto.tcp.window)));
        packetInfoText->AppendText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_proto.tcp.checksum[0], packet.h_proto.tcp.checksum[1]));
        packetInfoText->AppendText("\nUrgent Pointer: " + wxString::Format("%d", (packet.h_proto.tcp.urgentPtr[0] << 8) | packet.h_proto.tcp.urgentPtr[1]));

    }
}

void MainFrame::InsertPacket(const wxString& packetNo, const wxString& ipv, const wxString& srcAddr, const wxString& destAddr, const wxString& protocol, const wxString& srcPort, const wxString& destPort, const wxString& packetSize)
{
    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);

    long index = packetListView->InsertItem(packetListView->GetItemCount(), packetNo);

    wxListItem item;
    item.SetId(index);
    item.SetColumn(0);
    item.SetText(packetNo);
    item.SetBackgroundColour(GetColorFromProtocol(protocol));

    packetListView->Bind(wxEVT_LIST_ITEM_SELECTED, &MainFrame::ShowPacketInformation, this);

    packetListView->SetItem(item);
    packetListView->SetItem(index, 1, ipv);
    packetListView->SetItem(index, 2, srcAddr);
    packetListView->SetItem(index, 3, destAddr);
    packetListView->SetItem(index, 4, protocol);
    packetListView->SetItem(index, 5, srcPort);
    packetListView->SetItem(index, 6, destPort);
    packetListView->SetItem(index, 7, packetSize + " bytes");
}

wxString MainFrame::MakeReadableIPV4Address(u_char* ipv4Addr)
{
    wxString strAddr = "";

    for ( int i = 0; i < 4; i++ ) {
        strAddr += std::to_string(( int ) ipv4Addr[i]);
        if ( i < 3 ) {
            strAddr += ".";
        }
    }

    return strAddr;
}

wxString MainFrame::MakeReadableMACAddress(u_char* mac) {
    wxString macAddr = "";

    for ( int i = 0; i < 6; i++ ) {
        macAddr += wxString::Format("%02x", mac[i]);
        if ( i != 5 )
            macAddr += ":";
    }

    return macAddr;
}

#endif
