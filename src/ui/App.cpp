#ifndef _CLI_

#include <ui/app.h>
#include <ui/MainFrame.h>
#include <wx/display.h>
#include <ui/UIEvents.h>
#include <thread>

#include <Packets.h>

wxIMPLEMENT_APP(App);

void FrontendReceivePacket(struct Packet* packet) {
    MainFrame* mainFrame = wxDynamicCast(wxTheApp->GetTopWindow(), MainFrame);
    if ( !mainFrame ) {
        MessageBoxA(NULL, "Error", "Error getting main frame", MB_OK);
        return;
    }

    wxString srcAddr = "";
    wxString destAddr = "";

    if ( IsIPV6Packet(packet) ) {
        srcAddr = wxString::FromUTF8(std::string((char*)GetSourceIPAddress(packet)));
        destAddr = wxString::FromUTF8(std::string((char*)GetDestIPAddress(packet)));
    }
    else if ( IsIPV4Packet(packet) ) {
        srcAddr = mainFrame->MakeReadableIPV4Address(packet->h_ip.ip4.sourceIP);
        destAddr = mainFrame->MakeReadableIPV4Address(packet->h_ip.ip4.destIP);
    }

    mainFrame->InsertPacket(
        std::to_string(packet->packetNumber),
        GetStringIPV(packet->ipVer),
        srcAddr,
        destAddr,
        GetStringProtocol(packet->protocol),
        std::to_string(GetSourcePort(packet)),
        std::to_string(GetDestPort(packet)),
        std::to_string(packet->packetSize)
    );

    mainFrame->packets.insert({ packet->packetNumber, *packet });
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