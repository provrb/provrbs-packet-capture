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
    CreateStatusBar();

    wxMenu* menuFile = new wxMenu;
    menuFile->Append(wxID_NEW);
    menuFile->AppendSubMenu(new wxMenu, "&Open Recent");
    menuFile->AppendSubMenu(new wxMenu, "&Import from Hex Dump");
    menuFile->Append(wxID_OPEN);
    menuFile->Append(wxID_CLOSE);
    menuFile->AppendSeparator();

    wxMenuItem* clearItem = new wxMenuItem(NULL, wxID_CLEAR, "Clear All Packets");
    menuFile->Append(clearItem);
        
    menuFile->Append(wxID_SAVE);
    menuFile->Append(wxID_SAVEAS);

    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);

    wxMenu* menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);

    wxMenu* menuCapture = new wxMenu;

    wxMenu* selectNic = new wxMenu;
    menuCapture->AppendSubMenu(selectNic, "&Select Network Interfaces");

    menuCapture->AppendSeparator();
    char** networkInterfaceNames = GetNetworkInterfaceNames();

    wxMenuItem* startCapturePacketsOption = new wxMenuItem(NULL, kStartCapturingPackets, "Start Capturing Packets");
    wxMenuItem* stopCapturePacketsOption = new wxMenuItem(NULL, KStopPacketCapture, "End Packet Capture");
    wxMenuItem* pausePacketCapture = new wxMenuItem(NULL, kPausePacketCapture, "Pause Packet Capture");
    wxMenuItem* resumePacketCapture = new wxMenuItem(NULL, kResumePacketCapture, "Resume Packet Capture");

    stopCapturePacketsOption->Enable(false);
    startCapturePacketsOption->Enable(false);
    pausePacketCapture->Enable(false);
    resumePacketCapture->Enable(false);

    // append network interfaces
    for ( int i = 0; i < GetNumberOfNetworkInterfaces(); i++ ) {

        wxMenuItem* checkItem = new wxMenuItem(selectNic, i, networkInterfaceNames[i], "", wxITEM_CHECK);
        selectNic->Append(checkItem);

        Bind(wxEVT_MENU, [this, i, selectNic, checkItem, networkInterfaceNames, startCapturePacketsOption](wxCommandEvent& evemt)
            {
                if ( capturingPackets ) // cant select more network devices when already capturing
                {
                    MessageBoxA(NULL,
                        "You cannot select another Network Interface while already capturing packets. Stop capturing packets first.",
                        networkInterfaceNames[i],
                        MB_OK | MB_ICONINFORMATION
                    );

                    return;
                }


                auto itemIndex = std::find(selectedNicIndexes.begin(), selectedNicIndexes.end(), i);
                if ( itemIndex != selectedNicIndexes.end() ) {
                    // i is already selected
                    checkItem->Check(false);
                    selectedNicIndexes.erase(itemIndex);
                }
                else {
                    // i not selected
                    checkItem->Check(true);
                    selectedNicIndexes.push_back(i);
                }

                if ( !endedPacketCapture )
                    startCapturePacketsOption->Enable(true);
            },
            i
        );
    }

    /* 
    * Start capturing packets button was clicked.
    */
    Bind(wxEVT_MENU, [this, startCapturePacketsOption, stopCapturePacketsOption, pausePacketCapture, resumePacketCapture](wxCommandEvent& event)
        {
            if ( capturingPackets ) {
                MessageBoxA(NULL, "Cannot capture packets. Already capturing packets.", "Information", MB_OK | MB_ICONINFORMATION);
                return;
            }

            for ( int selectedNicIndex : selectedNicIndexes ) {
                std::thread capture(CapturePackets, selectedNicIndex);
                capture.detach();
            }

            capturingPackets = true;
            startCapturePacketsOption->Enable(false);
            stopCapturePacketsOption->Enable(true);
            // enable pause
            pausePacketCapture->Enable(true);
            resumePacketCapture->Enable(false);
        },
        kStartCapturingPackets
    );

    Bind(wxEVT_MENU, [this, startCapturePacketsOption, stopCapturePacketsOption, pausePacketCapture, resumePacketCapture](wxCommandEvent& event)
        {
            if ( !capturingPackets ) {
                MessageBoxA(NULL, "Not currently capturing packets. Cannot stop.", "Information", MB_OK | MB_ICONINFORMATION);
                return;
            }

            int userOpt = MessageBoxA(NULL, "End packet capturing? To resume, you must start a new " APP_NAME " session.", "Are you sure", MB_YESNOCANCEL | MB_ICONINFORMATION);
            if ( userOpt != IDYES )
                return;

            SetStatusText(wxString::Format("Ended packet capture. Captured %d packets.", packets.size()));
            PausePacketCapture();
            
            capturingPackets = false;
            endedPacketCapture = true;
            this->packets.clear();
            this->displayedPacketCount = 0;

            ResetPacketCount();

            startCapturePacketsOption->Enable(false);
            stopCapturePacketsOption->Enable(false);

            // remove pause and resume
            pausePacketCapture->Enable(false);
            resumePacketCapture->Enable(false);
        },
        KStopPacketCapture
    );

    Bind(wxEVT_MENU, [this, startCapturePacketsOption, stopCapturePacketsOption, pausePacketCapture, resumePacketCapture](wxCommandEvent& event)
        {
            SetStatusText(wxString::Format("Paused packet capture"));
            pausePacketCapture->Enable(false);
            resumePacketCapture->Enable(true);

            // pause packet
            PausePacketCapture();

            startCapturePacketsOption->Enable(false);
            stopCapturePacketsOption->Enable(false);
        },
        kPausePacketCapture
    );

    Bind(wxEVT_MENU, [this, startCapturePacketsOption, stopCapturePacketsOption, pausePacketCapture, resumePacketCapture](wxCommandEvent& event)
        {
            SetStatusText(wxString::Format("Resumed packet capture"));

            pausePacketCapture->Enable(true);
            resumePacketCapture->Enable(false);

            // resume packet
            ResumePacketCapture();

            startCapturePacketsOption->Enable(false);
            stopCapturePacketsOption->Enable(true);
        },
        kResumePacketCapture
    );

    menuCapture->Append(startCapturePacketsOption);
    menuCapture->Append(stopCapturePacketsOption);
    menuCapture->AppendSeparator();
    menuCapture->Append(pausePacketCapture);
    menuCapture->Append(resumePacketCapture);

    wxMenuBar* menuBar = new wxMenuBar;
    menuBar->Append(menuFile, "&File");
    menuBar->Append(menuCapture, "&Capture");
    menuBar->Append(menuHelp, "&Help");
    

    SetMenuBar(menuBar);

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

    hexDumpText->Bind(wxEVT_CONTEXT_MENU, &MainFrame::HexDumpRightClicked, this);
    menuFile->Bind(wxEVT_MENU, &MainFrame::ClearPackets, this, wxID_CLEAR);

    wxFont font(12, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false, "Consolas");
    font.Scale(.9);

    packetInfoText->SetFont(font);
    hexDumpText->SetFont(font);

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

void MainFrame::HexDumpRightClicked(wxCommandEvent& event) {
    wxMenu menu;
    menu.Append(wxID_COPY, "&Copy Raw Hex");
    menu.Bind(wxEVT_MENU, &MainFrame::CopyRawHex, this, wxID_COPY);
    
    PopupMenu(&menu);
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
    else if ( protocol == "ICMP" || protocol == "ICMPv6" )
        return wxColour{ 180, 180, 255 };
    else if ( protocol == "IGMP" )
        return wxColour{ 255, 180, 180 };

    return wxColour{ 255, 255, 255 };
}

void MainFrame::WriteARPHeader(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("\n\nAddress Resolution Protocol");
    packetInfoText->WriteText("\nOpcode: " + wxString::Format("0x%02x%02x", packet.h_proto.arp.opcode[0], packet.h_proto.arp.opcode[1]));
    packetInfoText->WriteText("\nSender MAC Address: " + MakeReadableMACAddress(packet.h_ethernet.source));
    packetInfoText->WriteText("\nDestination MAC Address: " + MakeReadableMACAddress(packet.h_ethernet.dest));
    packetInfoText->WriteText("\nSender IP Address: " + std::string(MakeReadableIPV4Address(packet.h_proto.arp.senderIP)));
    packetInfoText->WriteText("\nDestination IP Address: " + std::string(MakeReadableIPV4Address(packet.h_proto.arp.targetIP)));
}

void MainFrame::WriteTCPHeader(wxTextCtrl* packetInfoText, Packet packet) {
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
    packetInfoText->WriteText("\nUrgent Pointer: " + wxString::Format("%d", ( packet.h_proto.tcp.urgentPtr[0] << 8 ) | packet.h_proto.tcp.urgentPtr[1]));
}

void MainFrame::WriteEthernetHeader(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("Ethernet II header,");
    packetInfoText->WriteText("\nDestionation MAC: " + MakeReadableMACAddress(packet.h_ethernet.dest));
    packetInfoText->WriteText("\nSource MAC: " + MakeReadableMACAddress(packet.h_ethernet.source));
    packetInfoText->WriteText("\nType: " + std::string(GetEnumName<IPVersion>(IPVersionNames, GetIPVersion(&packet))));
}

void MainFrame::WriteIPV4Header(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("\n\nInternet Protocol Header 4,");
    packetInfoText->WriteText("\nSource IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.sourceIP)));
    packetInfoText->WriteText("\nDestination IPv4: " + std::string(MakeReadableIPV4Address(packet.h_ip.ip4.destIP)));
    packetInfoText->WriteText("\nIdentification: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.id[0], packet.h_ip.ip4.id[1]));
    packetInfoText->WriteText("\nTime to live (hops): " + wxString::Format("%d", packet.h_ip.ip4.ttl));
    packetInfoText->WriteText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.checksum[0], packet.h_ip.ip4.checksum[1]));
    packetInfoText->WriteText("\nFlags: 0x" + wxString::Format("%02x%02x", packet.h_ip.ip4.flags[0], packet.h_ip.ip4.flags[1]));
    packetInfoText->WriteText("\nService Type: 0x" + wxString::Format("%02x", packet.h_ip.ip4.serviceType));
}

void MainFrame::WriteIPV6Header(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("\n\nInternet Protocol Header 6,");
    packetInfoText->WriteText("\nSource IPv6: " + std::string(( char* ) GetSourceIPAddress(&packet)));
    packetInfoText->WriteText("\nDestination IPv6: " + std::string(( char* ) GetDestIPAddress(&packet)));
    packetInfoText->WriteText("\nFlow label: 0x" + wxString::Format("%02x%02x%02x", packet.h_ip.ip6.flowLabel[0], packet.h_ip.ip6.flowLabel[1], packet.h_ip.ip6.flowLabel[2]));
    packetInfoText->WriteText("\nNext header: " + wxString::Format("%d", packet.h_ip.ip6.nextHeader));
    packetInfoText->WriteText("\nHop limit: " + wxString::Format("%d", packet.h_ip.ip6.hopLimit));
}

void MainFrame::WriteICMPHeader(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("\n\nInternet Control Message Protocol Header,");

    if ( GetPacketProtocol(&packet) == ICMP6 ) {
        packetInfoText->WriteText("\nTarget Address: " + std::string((char*)CompressIPV6Address(packet.h_proto.icmp.targetAddr)));
        packetInfoText->WriteText("\nLink-layer Address: " +
            wxString::Format("%02x:%02x:%02x:%02x:%02x:%02x", 
                packet.h_proto.icmp.lladdress[0], packet.h_proto.icmp.lladdress[1],
                packet.h_proto.icmp.lladdress[2], packet.h_proto.icmp.lladdress[3], 
                packet.h_proto.icmp.lladdress[4], packet.h_proto.icmp.lladdress[5]));
    }
    
    packetInfoText->WriteText("\nChecksum: " + wxString::Format("0x%02x%02x", packet.h_proto.icmp.checksum[0], packet.h_proto.icmp.checksum[1]));
    
    packetInfoText->WriteText("\nType: " + wxString::Format("%d (%s)", packet.h_proto.icmp.type,
        GetEnumName<ICMPTypes>(ICMPTypeNames, (ICMPTypes)packet.h_proto.icmp.type))
    );

    packetInfoText->WriteText("\nCode: " + wxString::Format("%d", packet.h_proto.icmp.code));
    packetInfoText->WriteText("\nFlags: 0x" + wxString::Format("%02x%02x%02x%02x",
        packet.h_proto.icmp.flags[0],
        packet.h_proto.icmp.flags[1],
        packet.h_proto.icmp.flags[2],
        packet.h_proto.icmp.flags[3]
    ));
}

void MainFrame::WriteUDPHeader(wxTextCtrl* packetInfoText, Packet packet) {
    packetInfoText->WriteText("\n\nUser Datagram Protocol,");
    packetInfoText->WriteText("\nSource Port: " + std::to_string(GetSourcePort(&packet)));
    packetInfoText->WriteText("\nDestination Port: " + std::to_string(GetDestPort(&packet)));
    packetInfoText->WriteText("\nChecksum: 0x" + wxString::Format("%02x%02x", packet.h_proto.udp.checksum[0], packet.h_proto.udp.checksum[1]));
}

void MainFrame::WritePacketInfoFooter(wxTextCtrl* packetInfoText, Packet packet) {
    if ( IsIPV4Packet(&packet) ) { // "IPV4 000.000.000.000 > 000.000.000.000"
        packetInfoText->WriteText("\n\nIPV4 ");
        packetInfoText->WriteText(MakeReadableIPV4Address(packet.h_ip.ip4.sourceIP));
        packetInfoText->WriteText(" > ");
        packetInfoText->WriteText(MakeReadableIPV4Address(packet.h_ip.ip4.destIP));
    }
    else if ( IsIPV6Packet(&packet) ) { // "IPV6 d::d::d::d:: > d::d::d::d::"
        packetInfoText->WriteText("\n\nIPV6 ");
        packetInfoText->WriteText(GetSourceIPAddress(&packet));
        packetInfoText->WriteText(" > ");
        packetInfoText->WriteText(GetDestIPAddress(&packet));
    }
    else if ( IsARPPacket(&packet) ) // "ARP Who has 000.000.000.000? Tell 000.000.000.000"
        packetInfoText->WriteText("\n\nARP Who has " + MakeReadableIPV4Address(packet.h_proto.arp.senderIP) + "? Tell " + MakeReadableIPV4Address(packet.h_proto.arp.targetIP));

    // Protocols
    if ( GetPacketProtocol(&packet) == TCP ) packetInfoText->WriteText("\nTransmission Control Protocol (TCP)");
    else if ( GetPacketProtocol(&packet) == UDP ) packetInfoText->WriteText("\nUser Datagram Protocol (UDP)");
    else if ( GetPacketProtocol(&packet) == ICMP ) packetInfoText->WriteText("\nInternet Control Message Protocol (ICMP)");
    else if ( GetPacketProtocol(&packet) == HTTP ) packetInfoText->WriteText("\nHypertext Transfer Protocol (HTTP)");
    else if ( GetPacketProtocol(&packet) == ARP ) packetInfoText->WriteText("\nAddress Resolution Protocol (ARP)");
    else if ( GetPacketProtocol(&packet) == IGMP ) packetInfoText->WriteText("\nInternet Group Management Protocol (IGMP)");

    // "Transport Layer Security (TLS) Encrypted Payload"
    if ( packet.tls.usesTLS ) packetInfoText->WriteText("\nTransport Layer Security (TLS) Encrypted Payload");
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
    wxTextCtrl* hexDumpText    = ( wxTextCtrl* ) FindWindow(kHexDumpTextPane);

    // clear and freeze text to get ready to write
    hexDumpText->Clear();  packetInfoText->Clear();
    hexDumpText->Freeze(); packetInfoText->Freeze();

    WriteEthernetHeader(packetInfoText, packet);

    // Printing ip headers or ARP if it exists
    if ( IsARPPacket(&packet) )       WriteARPHeader(packetInfoText, packet);
    if ( IsIPV4Packet(&packet) )      WriteIPV4Header(packetInfoText, packet);
    else if ( IsIPV6Packet(&packet) ) WriteIPV6Header(packetInfoText, packet);

    // Printing protocol headers
    if ( GetPacketProtocol(&packet) == TCP ) WriteTCPHeader(packetInfoText, packet);
    else if ( GetPacketProtocol(&packet) == ICMP || GetPacketProtocol(&packet) == ICMP6 ) WriteICMPHeader(packetInfoText, packet);
    else if ( GetPacketProtocol(&packet) == UDP ) WriteUDPHeader(packetInfoText, packet);

    if ( packet.tls.usesTLS ) {
        packetInfoText->WriteText("\n\nTransport Layer Security Details,");
        packetInfoText->WriteText("\nPayload is encrypted using TLS.");
        packetInfoText->WriteText("\nTLS Content Type: " + wxString::Format("%d (%s)", packet.tls.contentType, GetEnumName<TLSContentType>(TLSContentTypeNames, (TLSContentType)packet.tls.contentType)));
        packetInfoText->WriteText("\nTLS Version: " + std::string(GetEnumName<TLSVersions>(TLSVersionNames, packet.tls.tlsVersionID)));
        packetInfoText->WriteText("\nTLS Encrypted Payload Length: " + wxString::Format("%d", ( packet.tls.encryptedPayloadLen[0] << 8 ) | packet.tls.encryptedPayloadLen[1]));
    }

    if ( packet.likelyHTTP ) {
        packetInfoText->WriteText("\n\nHypertext Transfer Protocol,");
        packetInfoText->WriteText("\nHTTP Version: " + wxString::Format("%s", HTTPVersionNames.at(packet.httpVer)));
        packetInfoText->WriteText("\nCheck Hex Dump For More");
    }

    WritePacketInfoFooter(packetInfoText, packet);

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
    if ( packetListView == NULL ) {
        wxLogMessage("Error getting packet list view?");
        return;
    }

    wxColour colour = GetColorFromProtocol(protocol);
    if ( protocol.Contains("TLS") ) // tls takes priority with colour
        colour = wxColour(193, 234, 245);

    else if ( protocol.Contains("ARP") )
        colour = wxColour(255, 177, 61);

    if ( description.Contains("HTTP") )
        colour = wxColour(76, 245, 169);

    wxListItem item;
    item.SetId(packetListView->GetItemCount());
    item.SetBackgroundColour(colour);

    packetListView->InsertItem(item);
    packetListView->SetItem(item.GetId(), 0, packetNo);
    packetListView->SetItem(item.GetId(), 1, ipv);
    packetListView->SetItem(item.GetId(), 2, srcAddr);
    packetListView->SetItem(item.GetId(), 3, destAddr);
    packetListView->SetItem(item.GetId(), 4, protocol);
    packetListView->SetItem(item.GetId(), 5, srcPort);
    packetListView->SetItem(item.GetId(), 6, destPort);
    packetListView->SetItem(item.GetId(), 7, packetSize + " bytes");
    packetListView->SetItem(item.GetId(), 8, description);
    packetListView->Bind(wxEVT_LIST_ITEM_SELECTED, &MainFrame::ShowPacketInformation, this);

    this->displayedPacketCount++;
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
    shownPacketIndex = -1;
}


void MainFrame::CopyRawHex(wxCommandEvent& event)
{
    Packet packet = GetSelectedPacketInfo();
    if ( wxTheClipboard->Open() ) {        
        wxString hex = "";
        for ( int i = 0; i < packet.packetSize; i++ )
            hex += wxString::Format("%02X ", packet.rawData[i]);

        wxTheClipboard->SetData(new wxTextDataObject(hex));
        wxTheClipboard->Close();
    }
}

Packet MainFrame::GetSelectedPacketInfo() {
    wxListView* packetListView = ( wxListView* ) FindWindow(kPacketListPanel);
    wxString index = packetListView->GetItemText(this->shownPacketIndex, 0); // get packet no
    long lIndex = std::stol(index.c_str().AsChar());
    if ( !this->packets.contains(lIndex) ) {
        wxLogMessage("Packet not found in saved packets");
        return {};
    }

    Packet packet = this->packets.at(lIndex);

    return packet;
}

#endif
