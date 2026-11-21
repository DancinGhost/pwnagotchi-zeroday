// Qt6 entry point for the pwnagotchi-zeroday Linux desktop GUI.
//
// Usage: zd-gui [--iface wlan0]
// Monitor mode and deauth require root (CAP_NET_RAW/CAP_NET_ADMIN); recon (active scan)
// works unprivileged via NetworkManager. The offensive panel stays disabled until the
// operator explicitly confirms authorization and allow-lists a target.

#include <cstdio>
#include <string>

#include <QApplication>

#include "../app/controller.hpp"
#include "main_window.hpp"

int main(int argc, char** argv) {
    QApplication qapp(argc, argv);

    std::string iface = "wlan0";
    std::string replayFile;
    std::string recordFile;
    std::string pcapFile;
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (s == "--help" || s == "-h") {
            std::printf("Usage: zd-gui [--iface wlan0] [--replay FILE] [--record FILE] [--pcap FILE]\n");
            return 0;
        } else if (s == "--iface" && i + 1 < argc) {
            iface = argv[++i];
        } else if (s == "--replay" && i + 1 < argc) {
            replayFile = argv[++i];
        } else if (s == "--record" && i + 1 < argc) {
            recordFile = argv[++i];
        } else if (s == "--pcap" && i + 1 < argc) {
            pcapFile = argv[++i];
        } else {
            std::fprintf(stderr, "unknown or incomplete option '%s'\n", s.c_str());
            return 2;
        }
    }

    if (!zd::sec::isValidIfaceName(iface)) {
        std::fprintf(stderr, "invalid wireless interface name '%s'\n", iface.c_str());
        return 2;
    }
    zd::linux_app::AppController controller(iface);
    if (!pcapFile.empty()) {
        controller.setPcapDumpPath(pcapFile);
    }
    controller.boot();
    if (!replayFile.empty()) {
        const auto r = controller.loadSession(replayFile);
        if (!r.ok) {
            std::fprintf(stderr, "[replay] %s\n", r.message.c_str());
            return 1;
        }
    }
    if (!recordFile.empty()) {
        const auto r = controller.startRecording(recordFile);
        if (!r.ok) {
            std::fprintf(stderr, "[record] %s\n", r.message.c_str());
            return 1;
        }
    }

    zd::linux_gui::MainWindow window(controller);
    window.show();
    return qapp.exec();
}
