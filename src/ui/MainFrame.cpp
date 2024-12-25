#ifndef _CLI_

#include "ui/MainFrame.h"
#include <wx/listctrl.h>
#include <thread>
extern "C" {
#include <packets.h>
}

wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_MENU(kClearAllPackets, MainFrame::ClearPackets)
wxEND_EVENT_TABLE()

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

    wxMenuItem* clearItem = new wxMenuItem(NULL, kClearAllPackets, "Clear All Packets");
    menuFile->Append(clearItem);

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
    packetListView->AppendColumn("No.", wxLIST_FORMAT_LEFT, 50);
    packetListView->AppendColumn("IP Vers.", wxLIST_FORMAT_LEFT, 70);
    packetListView->AppendColumn("Src. Address", wxLIST_FORMAT_LEFT, 130);
    packetListView->AppendColumn("Dest. Address", wxLIST_FORMAT_LEFT, 130);
    packetListView->AppendColumn("Protocol", wxLIST_FORMAT_LEFT, 75);
    packetListView->AppendColumn("Src. Port", wxLIST_FORMAT_LEFT, 70);
    packetListView->AppendColumn("Dest. Port", wxLIST_FORMAT_LEFT, 70);
    packetListView->AppendColumn("Packet Size", wxLIST_FORMAT_LEFT, 90);
    packetListView->AppendColumn("Description", wxLIST_FORMAT_LEFT, 260);

    // packet information panel
    wxPanel* packetInfoPanel = new wxPanel(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize);
    wxTextCtrl* packetInfoText = new wxTextCtrl(packetInfoPanel, kPacketInfoPanel, "", wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);

    // hex dump panel
    wxPanel* hexDumpPanel = new wxPanel(packetInfoPanel, wxID_ANY, wxDefaultPosition, wxDefaultSize);
    wxTextCtrl* hexDumpText = new wxTextCtrl(hexDumpPanel, kHexDumpTextPane, "", wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);

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
    if ( itemIndex == this->shownPacketIndex ) // already shown
        return;
    
    this->shownPacketIndex = itemIndex;

    wxString index = packetListView->GetItemText(itemIndex, 0); // get packet no
    long lIndex = std::stol(index.c_str().AsChar());
    if ( !this->packets.contains(lIndex) ) {
        wxLogMessage("Packet not found in saved packets");
        return;
    }

    Packet packet = this->packets.at(lIndex);

    // show top right packet info
    wxTextCtrl* packetInfoText = ( wxTextCtrl* ) FindWindow(kPacketInfoPanel);
    wxTextCtrl* hexDumpText = ( wxTextCtrl* ) FindWindow(kHexDumpTextPane);

    wxFont font(12, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, "Consolas");
    font.Scale(.9);
    packetInfoText->SetFont(font);
    hexDumpText->SetFont(font);

    hexDumpText->Clear();
    hexDumpText->Freeze();
    packetInfoText->Clear();
    packetInfoText->Freeze();

    wxTextAttr defaultStyle;
    defaultStyle.SetBackgroundColour(packetInfoText->GetBackgroundColour());
    defaultStyle.SetTextColour(*wxBLACK);

    wxTextAttr headerStyle;
    headerStyle.SetBackgroundColour(*wxLIGHT_GREY);
    headerStyle.SetTextColour(*wxBLACK);

    packetInfoText->SetDefaultStyle(headerStyle);
    packetInfoText->WriteText("Ethernet II header,\n");
    packetInfoText->SetDefaultStyle(defaultStyle);

    wxString ethDest = "Destionation MAC: " + MakeReadableMACAddress(packet.h_ethernet.dest);
    wxString ethSrc  = "Source MAC: " + MakeReadableMACAddress(packet.h_ethernet.source);
    wxString ethType = "Type: " + std::string(GetStringIPV(GetIPVersion(&packet)));

    packetInfoText->WriteText(ethSrc + "\n");
    packetInfoText->WriteText(ethDest + "\n");
    packetInfoText->WriteText(ethType + "\n");

    packetInfoText->SetDefaultStyle(headerStyle);
    packetInfoText->WriteText("\nInternet Protocol Header (" + std::string(GetStringIPV(GetIPVersion(&packet)) + std::string("),\n")));
    packetInfoText->SetDefaultStyle(defaultStyle);

    if ( IsIPV4Packet(&packet) ) {
        packetInfoText->WriteText("Source IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.sourceIP)));
        packetInfoText->WriteText("\nDestination IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.destIP)));
        packetInfoText->WriteText("\nIdentification: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.id[0], packet.h_ip.ip4.id[1]));
        packetInfoText->WriteText("\nTime to live (hops): " + wxString::Format("%d", packet.h_ip.ip4.ttl));
        packetInfoText->WriteText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.checksum[0], packet.h_ip.ip4.checksum[1]));
        packetInfoText->WriteText("\nFlags: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.flags[0], packet.h_ip.ip4.flags[1]));
        packetInfoText->WriteText("\nService Type: 0x" + wxString::Format("%02x", packet.h_ip.ip4.serviceType));
    }
    else if ( IsIPV6Packet(&packet) ) {
        packetInfoText->WriteText("Source IPv6: " + std::string(( char* ) GetSourceIPAddress(&packet)));
        packetInfoText->WriteText("\nDestination IPv6: " + std::string(( char* ) GetDestIPAddress(&packet)));
        packetInfoText->WriteText("\nFlow label: 0x" + wxString::Format("%02x%02x%02x", packet.h_ip.ip6.flowLabel[0], packet.h_ip.ip6.flowLabel[1], packet.h_ip.ip6.flowLabel[2]));
        packetInfoText->WriteText("\nNext header: " + wxString::Format("%d", packet.h_ip.ip6.nextHeader));
        packetInfoText->WriteText("\nHop limit: " + wxString::Format("%d", packet.h_ip.ip6.hopLimit));
    }

    if ( GetPacketProtocol(&packet) == TCP ) {
        // print tcp header
        packetInfoText->WriteText("\n\nTransmission Control Protocol Header,");
        packetInfoText->WriteText("\nSource Port: " + wxString::Format("%d", GetSourcePort(&packet)));
        packetInfoText->WriteText("\nDestination Port: " + wxString::Format("%d", GetDestPort(&packet)));
       
        char* flags = GetStringTCPFlagsSet(&packet);
        if ( flags != NULL ) {
            packetInfoText->WriteText("\nFlags Set: " + wxString::Format("%s", flags));
            free(flags);
        }
        
        packetInfoText->WriteText("\nSequence Number: 0x" + 
            wxString::Format("%02x%02x%02x%02x", 
                packet.h_proto.tcp.sequenceNum[0], packet.h_proto.tcp.sequenceNum[1], 
                packet.h_proto.tcp.sequenceNum[2], packet.h_proto.tcp.sequenceNum[3])
        );
        
        packetInfoText->WriteText("\nAcknowledgement Number: 0x" +
            wxString::Format("%02x%02x%02x%02x", 
                packet.h_proto.tcp.ackNum[0], packet.h_proto.tcp.ackNum[1], 
                packet.h_proto.tcp.ackNum[2], packet.h_proto.tcp.ackNum[3])
        );

        packetInfoText->WriteText("\nHeader length: " + wxString::Format("%d", packet.h_proto.tcp.len));
        packetInfoText->WriteText("\nCongestion Window Reduced: " + wxString::Format("%d", packet.h_proto.tcp.congWinFlag));
        packetInfoText->WriteText("\nWindow: " + wxString::Format("%d", HexPortToInt(packet.h_proto.tcp.window)));
        packetInfoText->WriteText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_proto.tcp.checksum[0], packet.h_proto.tcp.checksum[1]));
        packetInfoText->WriteText("\nUrgent Pointer: " + wxString::Format("%d", (packet.h_proto.tcp.urgentPtr[0] << 8) | packet.h_proto.tcp.urgentPtr[1]));
    }

    if ( packet.tls.usesTLS ) {
        packetInfoText->WriteText("\n\nTransport Layer Security Details,");
        packetInfoText->WriteText("\nPayload is encrypted using TLS.");
        packetInfoText->WriteText("\nTLS Content Type: " + wxString::Format("%d", packet.tls.contentType));
        packetInfoText->WriteText("\nTLS Version: " + std::string(GetStringTLSVersion(packet.tls.tlsVersionID)));
        packetInfoText->WriteText("\nTLS Encrypted Payload Length: " + wxString::Format("%d", ( packet.tls.encryptedPayloadLen[0] << 8 ) | packet.tls.encryptedPayloadLen[1]));
    }

    if ( packet.likelyHTTP ) {
        packetInfoText->WriteText("\n\nHypertext Transfer Protocol,");
        packetInfoText->WriteText("\nHTTP Version: " + wxString::Format("%s", GetStringHTTPVersion(packet.httpVer)));
        packetInfoText->WriteText("\nCheck Hex Dump For More");
    }

    // simple. print at bottom
    if ( IsIPV4Packet(&packet) ) {
        packetInfoText->WriteText("\n\nIPV4 ");
        packetInfoText->WriteText(MakeReadableIPV4Address(packet.h_ip.ip4.sourceIP));
        packetInfoText->WriteText(" > ");
        packetInfoText->WriteText(MakeReadableIPV4Address(packet.h_ip.ip4.destIP));
    }
    else if ( IsIPV6Packet(&packet) ) {
        packetInfoText->WriteText("\n\nIPV6 ");
        packetInfoText->WriteText(GetSourceIPAddress(&packet));
        packetInfoText->WriteText(" > ");
        packetInfoText->WriteText(GetDestIPAddress(&packet));
    }

    if ( GetPacketProtocol(&packet) == TCP )
        packetInfoText->WriteText("\nTransmission Control Protocol (TCP)");
    else if ( GetPacketProtocol(&packet) == UDP )
        packetInfoText->WriteText("\nUser Datagram Protocol (UDP)");

    if ( packet.tls.usesTLS )
        packetInfoText->WriteText("\nTransport Layer Security (TLS) Encrypted Payload");

    std::string ascii = "";  
    std::string hex = "";    

    for ( int i = 0; i < packet.packetSize; i++ ) {
        u_char asciiChar = ( u_char ) packet.rawData[i];

        if ( isprint(asciiChar) )
            ascii += asciiChar;
        else
            ascii += ".";

        hex += wxString::Format("%02X ", packet.rawData[i]);

        if ( ( i + 1 ) % 16 == 0 || i == packet.packetSize - 1 ) {
            hexDumpText->WriteText(wxString::Format("0x%04X  %-49s  %s\n", i - ( i % 16 ), hex, ascii));

            ascii = "";
            hex = "";
            ascii.clear();
            hex.clear();
        }
        else if ( (i + 1) % 8 == 0 ) {
            hex += " ";
        }
    }

    hexDumpText->Thaw();
    packetInfoText->Thaw();
}

void MainFrame::InsertPacket(
    const wxString& packetNo, 
    const wxString& ipv, 
    const wxString& srcAddr, 
    const wxString& destAddr, 
    const wxString& protocol, 
    const wxString& srcPort,
    const wxString& destPort,
    const wxString& packetSize,
    const wxString& description
)
{
    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);

    long index = packetListView->InsertItem(packetListView->GetItemCount(), packetNo);

    wxListItem item;
    item.SetId(index);
    item.SetColumn(0);
    item.SetText(packetNo);

    wxColour colour = GetColorFromProtocol(protocol);
    if ( protocol.Contains("TLS") ) // tls takes priority with colour
        colour = wxColour(193, 234, 245);
    else if ( protocol.Contains("ARP") )
        colour = wxColour(255, 177, 61);

    if ( description.Contains("HTTP") )
        colour = wxColour(76, 245, 169);


    item.SetBackgroundColour(colour);

    packetListView->Bind(wxEVT_LIST_ITEM_SELECTED, &MainFrame::ShowPacketInformation, this);

    packetListView->SetItem(item);
    packetListView->SetItem(index, 1, ipv);
    packetListView->SetItem(index, 2, srcAddr);
    packetListView->SetItem(index, 3, destAddr);
    packetListView->SetItem(index, 4, protocol);
    packetListView->SetItem(index, 5, srcPort);
    packetListView->SetItem(index, 6, destPort);
    packetListView->SetItem(index, 7, packetSize + " bytes");
    packetListView->SetItem(index, 8, description);
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

/*
    Clear packets from the screen
*/
void MainFrame::ClearPackets(wxCommandEvent& event)
{
    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);
    packetListView->DeleteAllItems();
}

void MainFrame::DeleteAllPackets(wxCommandEvent& event) {
    int confirmation = MessageBoxA(NULL, "Delete all logged packets?", "Confirmation", MB_ICONWARNING | MB_YESNOCANCEL);
    if ( confirmation != IDYES )
        return;

    this->ClearPackets(event);
    this->packets.clear();
}

#endif
