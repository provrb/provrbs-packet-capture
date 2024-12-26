#ifndef _CLI_

#include <ui/app.h>
#include <ui/MainFrame.h>
#include <wx/display.h>
#include <ui/UIEvents.h>
#include <thread>

#include <Packets.h>

wxIMPLEMENT_APP(App);

Packet MakePacketDeepCopy(struct Packet* original) {
    Packet copied;
    
    copied.rawData  = new u_char[original->packetSize];
    memcpy(copied.rawData, original->rawData, original->packetSize);

    copied.httpVer = original->httpVer;
    copied.h_ethernet = original->h_ethernet;
    copied.h_ip = original->h_ip;
    copied.h_proto = original->h_proto;
    copied.ipVer = original->ipVer;
    copied.likelyHTTP = original->likelyHTTP;
    copied.packetNumber = original->packetNumber;
    copied.packetSize = original->packetSize;
    copied.payload = original->payload;
    copied.payloadSize = original->payloadSize;
    copied.protocol = original->protocol;
    copied.timestamp = original->timestamp;
    copied.tls = original->tls;

    return copied;
}

void FrontendReceivePacket(struct Packet* packet, u_char* packetData) {
    MainFrame* mainFrame = wxDynamicCast(wxTheApp->GetTopWindow(), MainFrame);
    if ( !mainFrame ) {
        MessageBoxA(NULL, "Error", "Error getting main frame", MB_OK);
        return;
    }

    wxString srcAddr = "";
    wxString destAddr = "";
    wxString protocol = GetEnumName<InternetProtocol>(InternetProtocolNames, packet->protocol);
    wxString info = "";

    if ( IsIPV6Packet(packet) ) {
        srcAddr = wxString::FromUTF8(std::string(( char* ) GetSourceIPAddress(packet)));
        destAddr = wxString::FromUTF8(std::string(( char* ) GetDestIPAddress(packet)));
    }
    else if ( IsIPV4Packet(packet) ) {
        srcAddr = mainFrame->MakeReadableIPV4Address(packet->h_ip.ip4.sourceIP);
        destAddr = mainFrame->MakeReadableIPV4Address(packet->h_ip.ip4.destIP);
    }
    else if ( IsARPPacket(packet) ) {
        // src and dest will be mac addresses
        ( IsBroadcastMAC(packet->h_ethernet.source) ) ? srcAddr = "Broadcast" : srcAddr = mainFrame->MakeReadableMACAddress(packet->h_ethernet.source);
        ( IsBroadcastMAC(packet->h_ethernet.dest) ) ? destAddr = "Broadcast" : destAddr = mainFrame->MakeReadableMACAddress(packet->h_ethernet.dest);
    }

    if ( packet->tls.usesTLS ) {
        protocol = "TCP/TLS";
        if ( packet->tls.contentType == ApplicationData )
            info += "Application Data ";
    } 
    
    if ( IsSuspectedHTTPRequest(packet) )
        info += "HTTP Payload Suspected " + wxString::Format("%s", GetEnumName<HTTPVersions>(HTTPVersionNames, packet->httpVer)) + " ";
    else if ( IsKeepAlivePacket(packet) )
        info += "Keep-Alive Packet ";
    else if ( IsDNSQuery(packet) )
        info += "DNS Standard Query";
    else if ( GetPacketProtocol(packet) == ICMP6 || GetPacketProtocol(packet) == ICMP )
        info += GetEnumName<ICMPTypes>(ICMPTypeNames, (ICMPTypes)packet->h_proto.icmp.type);

    if ( IsARPPacket(packet) )
        info = "Who has " + mainFrame->MakeReadableIPV4Address(packet->h_proto.arp.senderIP) + "? Tell " + mainFrame->MakeReadableIPV4Address(packet->h_proto.arp.targetIP);

    packet->rawData = packetData;
    Packet copied = MakePacketDeepCopy(packet);

    mainFrame->packets.insert({copied.packetNumber, copied});

    mainFrame->InsertPacket(
        std::to_string(copied.packetNumber),
        GetEnumName<IPVersion>(IPVersionNames, copied.ipVer),
        srcAddr,
        destAddr,
        protocol,
        std::to_string(GetSourcePort(&copied)),
        std::to_string(GetDestPort(&copied)),
        std::to_string(copied.packetSize),
        info
    );
}

bool App::OnInit()
{
    frontendCapturePacket = &FrontendReceivePacket;
    MainFrame* mainFrame = new MainFrame("Provrbs Packet Capture");
    mainFrame->Show(true);

    wxDisplay display(wxDisplay::GetFromWindow(mainFrame));
    wxRect dimensions = display.GetClientArea();

    mainFrame->Maximize();
    mainFrame->SetClientSize(dimensions.GetWidth(), dimensions.GetHeight());
    mainFrame->SetMinClientSize(wxSize(800, 600));

    std::thread capturer(CapturePackets);
    capturer.detach();

    return true;
}

#endif