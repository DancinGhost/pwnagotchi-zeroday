// pwnagotchi-zeroday — Linux desktop CLI / TUI shell.
//
// Two front-ends over the shared AppController:
//   * an interactive ncurses dashboard (pet face + live network table + defensive alerts),
//   * scriptable subcommands for headless use / automation.
//
// OFFENSIVE SAFETY: transmit (deauth) is refused unless BOTH --i-am-authorized is given
// AND the target BSSID is explicitly allow-listed (via --allow or the TUI). Every decision
// is written to the audit log. Only use the active features on networks you own or are
// explicitly authorized to test.
//
// Usage:
//   zd-linux [--iface wlan0] [--record FILE] [--replay FILE] tui
//   zd-linux scan [--record FILE]
//   zd-linux watch [--channel N] [--record FILE]
//   zd-linux replay <FILE>
//   zd-linux deauth <BSSID> [--client <MAC>] [--count N] --i-am-authorized --allow <BSSID>
//   zd-linux --help

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#include <ncurses.h>

#include "zd/hal.hpp"
#include "zd/theme.hpp"
#include "zd/ui_model.hpp"
#include "../app/controller.hpp"

namespace {

using zd::linux_app::AppController;
using zd::linux_app::nowMs;

std::atomic<bool> g_stop{false};
void onSignal(int) { g_stop.store(true); }

struct Args {
    std::string iface = "wlan0";
    std::string command;  // tui | scan | watch | replay | deauth | help
    std::string bssid;    // positional target for deauth (or file for replay)
    std::string client;
    std::string recordFile;
    std::string replayFile;
    std::string pcapFile;
    uint32_t count = 16;
    int channel = 0;
    bool authorized = false;
    std::vector<std::string> allow;
};

bool parseStrictIntRange(const std::string& raw, int minVal, int maxVal, int& out) {
    if (raw.empty()) {
        return false;
    }
    for (unsigned char c : raw) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    const uint32_t v = zd::sec::detail::parseU32(raw);
    if (v < static_cast<uint32_t>(minVal) || v > static_cast<uint32_t>(maxVal)) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (s == "--iface" && i + 1 < argc) {
            a.iface = argv[++i];
        } else if (s == "--client" && i + 1 < argc) {
            a.client = argv[++i];
        } else if (s == "--record" && i + 1 < argc) {
            a.recordFile = argv[++i];
        } else if (s == "--replay" && i + 1 < argc) {
            a.replayFile = argv[++i];
        } else if (s == "--pcap" && i + 1 < argc) {
            a.pcapFile = argv[++i];
        } else if (s == "--count" && i + 1 < argc) {
            const std::string rawCount = argv[++i];
            int parsed = 0;
            if (!parseStrictIntRange(rawCount, 1, 1000, parsed)) {
                std::fprintf(stderr, "invalid --count '%s' (must be 1..1000)\n", rawCount.c_str());
                std::exit(2);
            }
            a.count = static_cast<uint32_t>(parsed);
        } else if (s == "--channel" && i + 1 < argc) {
            const std::string rawCh = argv[++i];
            if (!parseStrictIntRange(rawCh, 1, 177, a.channel)) {
                std::fprintf(stderr, "invalid --channel '%s' (must be 1..177)\n", rawCh.c_str());
                std::exit(2);
            }
        } else if (s == "--i-am-authorized") {
            a.authorized = true;
        } else if (s == "--allow" && i + 1 < argc) {
            a.allow.push_back(argv[++i]);
        } else if (s == "--help" || s == "-h") {
            a.command = "help";
        } else if (!s.empty() && s[0] == '-') {
            std::fprintf(stderr, "unknown or incomplete option '%s'\n", s.c_str());
            std::exit(2);
        } else if (a.command.empty()) {
            a.command = s;
        } else if (a.bssid.empty()) {
            a.bssid = s;  // positional target for deauth or file for replay
        } else {
            std::fprintf(stderr, "unexpected argument '%s'\n", s.c_str());
            std::exit(2);
        }
    }
    if (a.command == "replay" && a.replayFile.empty() && !a.bssid.empty()) {
        a.replayFile = a.bssid;
    }
    return a;
}

const char* encLabel(zd::sec::Encryption e) { return zd::sec::encryptionLabel(e); }

// AppController's monitor-start/stop and deauth are always async now (they shell out to
// airmon-ng/aireplay-ng, which can take a while, and must never block an interactive UI
// loop). These one-shot, non-interactive subcommands aren't driving a UI loop, so it's
// fine for them to spin here until the in-flight action finishes.
zd::linux_app::ActionResult waitForAsyncResult(AppController& app) {
    for (int i = 0; i < 150 && app.asyncBusy(); ++i) {
        app.step();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Always step once after the worker finishes so pollAsyncJobs() collects its outcome
    // even when the job completed before or between asyncBusy() checks.
    app.step();
    if (auto r = app.takeLastAsyncResult()) {
        return *r;
    }
    return {false, "action timed out"};
}

void printHelp() {
    std::cout <<
        "pwnagotchi-zeroday Linux CLI/TUI\n"
        "  zd-linux [--iface wlan0] [--record FILE] [--replay FILE] [--pcap FILE] tui\n"
        "  zd-linux scan [--record FILE]           One active scan, print table\n"
        "  zd-linux watch [--channel N] [--record FILE] [--pcap FILE]\n"
        "                                          Monitor mode; stream defensive alerts\n"
        "  zd-linux replay <FILE>                  Replay recorded session & print summary\n"
        "  zd-linux deauth <BSSID> [--client MAC] [--count N] --i-am-authorized --allow <BSSID>\n"
        "\nSafety: deauth requires --i-am-authorized AND --allow <that BSSID>. All transmit\n"
        "decisions are logged. Only test networks you own or are authorized to assess.\n";
}

std::string joinProbedSsids(const std::vector<std::string>& ssids, std::size_t maxChars = 36) {
    if (ssids.empty()) {
        return "<wildcard>";
    }
    std::string out;
    for (std::size_t i = 0; i < ssids.size(); ++i) {
        if (i != 0u) {
            out += ", ";
        }
        out += ssids[i];
    }
    if (out.size() > maxChars) {
        out = out.substr(0, maxChars - 1) + "~";
    }
    return out;
}

// --- Headless subcommands ------------------------------------------------------------

void printSecSummary(const zd::sec::SecState& secState, uint32_t now) {
    const auto targets = zd::sec::targetsByStrength(secState);
    const auto stations = zd::sec::stationsByActivity(secState);
    const auto sm = zd::sec::deriveSecMood(secState, now);

    std::printf("=== Networks (%zu) | Security Status: %s ===\n",
                targets.size(), zd::sec::secMoodLabel(sm));
    std::printf("%-18s %-24s %4s %6s %-6s %-4s %4s %-4s\n",
                "BSSID", "SSID", "CH", "dBm", "ENC", "WPS", "CLI", "CAP");
    for (const auto& t : targets) {
        const std::string cleanSsid = zd::sec::sanitizePrintableText(t.ssid, 24u);
        std::printf("%-18s %-24s %4d %6d %-6s %-4s %4u %-4s\n", t.bssid.c_str(),
                    (cleanSsid.empty() ? "<hidden>" : cleanSsid.c_str()), t.channel,
                    t.rssi, encLabel(t.enc), t.wps ? "WPS" : "-", t.clientCount,
                    t.handshake ? "HS" : (t.pmkid ? "PMK" : "-"));
    }

    if (!stations.empty()) {
        std::printf("\n=== Stations / Probe Requests (%zu) ===\n", stations.size());
        std::printf("%-18s %-18s %6s %-6s %s\n",
                    "STATION MAC", "ASSOC BSSID", "PROBES", "RISK", "PROBED SSIDS");
        for (const auto& st : stations) {
            std::printf("%-18s %-18s %6u %-6s %s\n",
                        st.mac.c_str(),
                        st.lastBssid.empty() ? "-" : st.lastBssid.c_str(),
                        st.probeCount,
                        zd::sec::hasWeakOrDefaultProbe(st) ? "WEAK!" : "-",
                        zd::sec::sanitizePrintableText(joinProbedSsids(st.probedSsids, 44), 44u).c_str());
        }
    }

    if (!secState.bleTargets.empty()) {
        std::printf("\n=== BLE Devices / Trackers (%zu) ===\n", secState.bleTargets.size());
        std::printf("%-18s %-20s %5s %-10s %5s\n", "MAC", "NAME", "RSSI", "THREAT", "SEEN");
        for (const auto& bt : secState.bleTargets) {
            const std::string cleanName = zd::sec::sanitizePrintableText(bt.name, 20u);
            std::printf("%-18s %-20s %5d %-10s %5u\n", bt.mac.c_str(),
                        cleanName.empty() ? "-" : cleanName.c_str(), bt.rssi,
                        zd::bleThreatLabel(bt.threat), bt.seenCount);
        }
    }

    if (!secState.subGhzCaptures.empty()) {
        std::printf("\n=== Sub-GHz Captures (%zu) ===\n", secState.subGhzCaptures.size());
        std::printf("%-12s %6s %-16s %6s %-9s\n", "FREQ", "RSSI", "PROTOCOL", "BURST", "STATUS");
        for (const auto& sc : secState.subGhzCaptures) {
            const std::string cleanProto = zd::sec::sanitizePrintableText(sc.protocol, 16u);
            const std::string status =
                sc.continuousCarrier ? "JAMMING!" : (sc.burstCount >= 5u ? "REPLAY!" : "OK");
            std::printf("%-12s %6d %-16s %6u %-9s\n",
                        zd::formatFreqMhz(sc.freqKhz).c_str(), sc.rssi,
                        cleanProto.empty() ? "-" : cleanProto.c_str(), sc.burstCount,
                        status.c_str());
        }
    }

    if (!secState.alerts.empty()) {
        std::printf("\n=== Defensive Alerts (%zu retained, %u total) ===\n",
                    secState.alerts.size(), secState.totalAlertsEmitted);
        for (const auto& al : secState.alerts) {
            const std::string cleanMsg = zd::sec::sanitizePrintableText(al.message, 160u);
            std::printf("[%8u ms] %-14s %-17s %s\n", al.nowMs,
                        zd::sec::alertKindLabel(al.kind), al.bssid.c_str(), cleanMsg.c_str());
        }
    }
}

int runScan(AppController& app) {
    app.requestScan();
    // Drive the controller until the scan completes (bounded).
    for (int i = 0; i < 100 && !app.petState().hasScannedOnce; ++i) {
        app.step();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // One extra settle so results propagate into the security engine.
    for (int i = 0; i < 5; ++i) {
        app.step();
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
    printSecSummary(app.secState(), nowMs());
    return 0;
}

int runReplay(AppController& app, const std::string& path) {
    if (path.empty()) {
        std::fprintf(stderr, "replay: missing session file path\n");
        return 2;
    }
    const auto res = app.loadSession(path);
    std::fprintf(stderr, "[replay] %s\n", res.message.c_str());
    if (!res.ok) {
        return 1;
    }
    printSecSummary(app.secState(), app.secState().lastEventMs);
    return 0;
}

int runWatch(AppController& app, const Args& a) {
    const auto kick = app.startMonitor();
    std::fprintf(stderr, "[monitor] %s\n", kick.message.c_str());
    if (!kick.ok) {
        return 1;
    }
    const auto res = waitForAsyncResult(app);
    std::fprintf(stderr, "[monitor] %s\n", res.message.c_str());
    if (!res.ok) {
        return 1;
    }
    if (a.channel > 0) {
        const auto chKick = app.setChannel(a.channel);
        if (chKick.ok) {
            waitForAsyncResult(app);
        }
    }
    std::fprintf(stderr, "[watch] streaming defensive alerts (Ctrl-C to stop)...\n");
    std::uint32_t printedTotal = 0;
    while (!g_stop.load()) {
        app.step();
        const auto& sec = app.secState();
        const auto& alerts = sec.alerts;
        if (sec.totalAlertsEmitted > printedTotal && !alerts.empty()) {
            const std::uint32_t unseen = sec.totalAlertsEmitted - printedTotal;
            const std::size_t count = (unseen < alerts.size()) ? static_cast<std::size_t>(unseen)
                                                               : alerts.size();
            const std::size_t start = alerts.size() - count;
            for (std::size_t i = start; i < alerts.size(); ++i) {
                const auto& al = alerts[i];
                const auto sm = zd::sec::deriveSecMood(sec, al.nowMs);
                const std::string cleanMsg = zd::sec::sanitizePrintableText(al.message, 160u);
                std::printf("[%8u ms] [%-8s] %-14s %-17s %s\n", al.nowMs,
                            zd::sec::secMoodLabel(sm), zd::sec::alertKindLabel(al.kind),
                            al.bssid.c_str(), cleanMsg.c_str());
                std::fflush(stdout);
            }
            printedTotal = sec.totalAlertsEmitted;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    app.shutdown();
    return 0;
}

int runDeauth(AppController& app, const Args& a) {
    if (a.bssid.empty()) {
        std::fprintf(stderr, "deauth: missing target BSSID\n");
        return 2;
    }
    if (!zd::sec::isValidMac(a.bssid) || zd::sec::isMulticastMac(a.bssid)) {
        std::fprintf(stderr, "deauth: invalid target BSSID '%s'\n", a.bssid.c_str());
        return 2;
    }
    if (!zd::sec::isValidClientTarget(a.client)) {
        std::fprintf(stderr, "deauth: invalid --client MAC '%s'\n", a.client.c_str());
        return 2;
    }
    for (const std::string& b : a.allow) {
        if (!zd::sec::isValidMac(b) || zd::sec::isMulticastMac(b)) {
            std::fprintf(stderr, "deauth: invalid --allow BSSID '%s'\n", b.c_str());
            return 2;
        }
    }
    app.confirmAuthorization(a.authorized);
    for (const std::string& b : a.allow) {
        app.allowBssid(b);
    }
    // Pre-check authorization BEFORE enabling monitor mode so unauthorized requests never
    // disrupt active networking (or trigger airmon-ng check kill).
    const zd::sec::AuthDecision preflight = app.preflightDeauth(a.bssid, a.client, a.count);
    if (preflight != zd::sec::AuthDecision::Allowed) {
        std::fprintf(stderr, "[deauth] deauth refused: %s\n",
                     zd::sec::authDecisionLabel(preflight));
        std::fprintf(stderr, "[audit ] see %s\n", app.auditPath().c_str());
        return 1;
    }
    const auto kickMon = app.startMonitor();
    std::fprintf(stderr, "[monitor] %s\n", kickMon.message.c_str());
    if (!kickMon.ok) {
        return 1;
    }
    const auto mon = waitForAsyncResult(app);
    std::fprintf(stderr, "[monitor] %s\n", mon.message.c_str());
    if (!mon.ok) {
        return 1;
    }
    if (a.channel > 0) {
        const auto chKick = app.setChannel(a.channel);
        if (chKick.ok) {
            waitForAsyncResult(app);
        }
    }
    const auto kickDeauth = app.requestDeauth(a.bssid, a.client, a.count);
    std::fprintf(stderr, "[deauth] %s\n", kickDeauth.message.c_str());
    if (!kickDeauth.ok) {
        app.shutdown();
        return 1;
    }
    const auto r = waitForAsyncResult(app);
    std::fprintf(stderr, "[deauth] %s\n", r.message.c_str());
    std::fprintf(stderr, "[audit ] see %s\n", app.auditPath().c_str());
    app.shutdown();
    return r.ok ? 0 : 1;
}

// --- ncurses dashboard ---------------------------------------------------------------

struct TuiCache {
    uint64_t revision = UINT64_MAX;
    std::vector<zd::sec::WifiTarget> targets;
    std::vector<zd::sec::Station> stations;
    std::vector<zd::sec::ChannelCount> channels;

    void sync(const zd::sec::SecState& s) {
        if (revision == s.revision) {
            return;
        }
        revision = s.revision;
        targets = zd::sec::targetsByStrength(s);
        stations = zd::sec::stationsByActivity(s);
        channels = zd::sec::channelDistribution(s);
    }
};

void drawDashboard(AppController& app, const TuiCache& cache, int selected, int scrollOffset,
                   bool showStations, bool showHelp, const std::string& lastActionMsg, bool busy) {
    erase();
    int maxy = 0;
    int maxx = 0;
    getmaxyx(stdscr, maxy, maxx);
    if (maxy < 14 || maxx < 60) {
        mvprintw(maxy / 2, (maxx > 42) ? (maxx - 42) / 2 : 0,
                 "Terminal too small (%dx%d). Need >= 60x14.", maxx, maxy);
        refresh();
        return;
    }

    // Header: pet face + status + SecMood + optional REC badge.
    const zd::AppState& ps = app.petState();
    const zd::sec::SecMood sm = app.secMood();
    const int secColor = (sm == zd::sec::SecMood::Alarmed)
                             ? 1
                             : (sm == zd::sec::SecMood::Watchful ? 3 : 2);
    attron(A_BOLD);
    mvprintw(0, 1, "pwnagotchi-zeroday %s [%s|%s] Lv.%u(HI:%u) mood:%s batt:%d%% engine:%s",
             zd::faceForMood(ps.mood).asciiFace,
             zd::themeSpec(ps.theme).name, zd::opsModeLabel(ps.opsMode), ps.level, ps.highScore,
             zd::faceForMood(ps.mood).moodLabel, ps.batteryPercent,
             app.monitoring() ? app.engineLabel().c_str() : "idle (scan only)");
    attroff(A_BOLD);
    attron(COLOR_PAIR(secColor) | A_BOLD);
    printw("  sec:%s", zd::sec::secMoodLabel(sm));
    attroff(COLOR_PAIR(secColor) | A_BOLD);
    if (app.recording()) {
        attron(COLOR_PAIR(1) | A_BOLD);
        printw("  [REC]");
        attroff(COLOR_PAIR(1) | A_BOLD);
    }
    const std::string cleanPhrase = zd::sec::sanitizePrintableText(ps.phrase, 120u);
    mvprintw(1, 1, "\"%s\"", cleanPhrase.c_str());

    // Authorization banner + table mode tabs.
    const auto& auth = app.authorization();
    const bool armed = auth.operatorConfirmed;
    attron(armed ? (COLOR_PAIR(1) | A_BOLD) : COLOR_PAIR(2));
    mvprintw(2, 1, " AUTH: %s  allow-list:%zu%s ", armed ? "ARMED (TX CONFIRMED)" : "SAFE (passive)",
             auth.allowedBssids.size(), auth.allowAll ? " (ALL!)" : "");
    attroff(armed ? (COLOR_PAIR(1) | A_BOLD) : COLOR_PAIR(2));
    printw("   [p] Table: %s (%zu APs | %zu Stations)",
           showStations ? "STATIONS / PROBES" : "NETWORKS (APs)",
           cache.targets.size(), cache.stations.size());

    // Channel distribution across both bands.
    {
        std::string band24;
        std::string band5;
        for (const auto& c : cache.channels) {
            const std::string part =
                "ch" + std::to_string(c.channel) + "x" + std::to_string(c.count) + " ";
            if (c.band == zd::sec::Band::Band24GHz) {
                band24 += part;
            } else if (c.band == zd::sec::Band::Band5GHz) {
                band5 += part;
            }
        }
        mvprintw(3, 1, "2.4GHz: %-28s 5GHz: %s", band24.empty() ? "-" : band24.c_str(),
                 band5.empty() ? "-" : band5.c_str());
        clrtoeol();
    }

    int row = 4;
    const int tableRows = (maxy - row - 8 > 0) ? (maxy - row - 8) : 4;
    if (!showStations) {
        attron(A_UNDERLINE);
        mvprintw(row++, 1, "%-18s %-20s %3s %5s %-5s %-4s %4s %-4s %-3s", "BSSID", "SSID", "CH",
                 "dBm", "ENC", "WPS", "CLI", "CAP", "ALW");
        attroff(A_UNDERLINE);
        const int total = static_cast<int>(cache.targets.size());
        for (int vis = 0; vis < tableRows && (scrollOffset + vis) < total; ++vis) {
            const int idx = scrollOffset + vis;
            const auto& t = cache.targets[static_cast<std::size_t>(idx)];
            const bool sel = (idx == selected);
            const std::string cleanSsid = zd::sec::sanitizePrintableText(t.ssid, 20u);
            if (sel) {
                attron(A_REVERSE);
            }
            mvprintw(row + vis, 1, "%-18s %-20s %3d %5d %-5s %-4s %4u %-4s %-3s", t.bssid.c_str(),
                     (cleanSsid.empty() ? "<hidden>" : cleanSsid.c_str()), t.channel,
                     t.rssi, encLabel(t.enc), t.wps ? "WPS*" : "-", t.clientCount,
                     t.handshake ? "HS" : (t.pmkid ? "PMK" : "-"),
                     auth.isAllowed(t.bssid) ? "YES" : "-");
            if (sel) {
                attroff(A_REVERSE);
            }
        }
    } else {
        attron(A_UNDERLINE);
        mvprintw(row++, 1, "%-18s %-18s %6s %-6s %s", "STATION MAC", "ASSOC BSSID", "PROBES",
                 "RISK", "PROBED SSIDS");
        attroff(A_UNDERLINE);
        const std::size_t maxProbedWidth =
            (maxx > 56) ? static_cast<std::size_t>(maxx - 56) : 20u;
        const int total = static_cast<int>(cache.stations.size());
        for (int vis = 0; vis < tableRows && (scrollOffset + vis) < total; ++vis) {
            const int idx = scrollOffset + vis;
            const auto& st = cache.stations[static_cast<std::size_t>(idx)];
            const bool sel = (idx == selected);
            const bool weak = zd::sec::hasWeakOrDefaultProbe(st);
            const std::string cleanProbes =
                zd::sec::sanitizePrintableText(joinProbedSsids(st.probedSsids, maxProbedWidth),
                                               maxProbedWidth);
            if (sel) {
                attron(A_REVERSE);
            } else if (weak) {
                attron(COLOR_PAIR(3));
            }
            mvprintw(row + vis, 1, "%-18s %-18s %6u %-6s %s", st.mac.c_str(),
                     st.lastBssid.empty() ? "-" : st.lastBssid.c_str(), st.probeCount,
                     weak ? "WEAK!" : "-", cleanProbes.c_str());
            if (sel) {
                attroff(A_REVERSE);
            } else if (weak) {
                attroff(COLOR_PAIR(3));
            }
        }
    }

    // Alerts (defensive) pane.
    const auto& alerts = app.secState().alerts;
    int aRow = maxy - 7;
    attron(A_BOLD);
    mvprintw(aRow++, 1, "Defensive alerts (%u total):", app.secState().totalAlertsEmitted);
    attroff(A_BOLD);
    const int shown = 4;
    const int start = (static_cast<int>(alerts.size()) > shown)
                          ? static_cast<int>(alerts.size()) - shown
                          : 0;
    for (int i = start; i < static_cast<int>(alerts.size()); ++i) {
        const auto& al = alerts[i];
        const int cp = (al.severity == zd::sec::Severity::Critical) ? 1 : 3;
        const std::size_t maxMsg = (maxx > 36) ? static_cast<std::size_t>(maxx - 36) : 0u;
        const std::string cleanMsg = zd::sec::sanitizePrintableText(al.message, maxMsg);
        attron(COLOR_PAIR(cp));
        mvprintw(aRow++, 2, "%-14s %-17s %s", zd::sec::alertKindLabel(al.kind), al.bssid.c_str(),
                 cleanMsg.c_str());
        attroff(COLOR_PAIR(cp));
    }

    // Last background action result.
    if (busy || !lastActionMsg.empty()) {
        const std::string cleanAction = zd::sec::sanitizePrintableText(lastActionMsg, 120u);
        attron(A_BOLD);
        mvprintw(maxy - 2, 1, "%s", busy ? "working..." : cleanAction.c_str());
        clrtoeol();
        attroff(A_BOLD);
    }

    // Key help.
    mvprintw(maxy - 1, 1,
             "[s]can [m]on [c]h [o]ps [v/1-4]view [p]robes [[/]/t]heme [A]uth [l/L]allow [x]deauth [w]save [r]load [?]help [q]uit");
    if (showHelp) {
        const int r0 = 4;
        mvprintw(r0 + 0, 4, "+----------------------------------------------------------+");
        mvprintw(r0 + 1, 4, "| Keys: s=scan  m=monitor  c=channel  o=ops-mode           |");
        mvprintw(r0 + 2, 4, "|       v/1-4=pet-view  p/Tab=APs/Stations  [/]/t/T=theme  |");
        mvprintw(r0 + 3, 4, "|       j/k/Arrows/PgUp/PgDn=select  A=confirm TX auth     |");
        mvprintw(r0 + 4, 4, "|       l/L=allow-list BSSID  x=deauth  w=save  r=load     |");
        mvprintw(r0 + 5, 4, "|       ?=toggle help  q=quit                              |");
        mvprintw(r0 + 6, 4, "+----------------------------------------------------------+");
    }
    refresh();
}

std::string resolveSelectedBssid(const TuiCache& cache, bool showStations, int selected) {
    if (selected < 0) {
        return {};
    }
    if (!showStations) {
        if (selected < static_cast<int>(cache.targets.size())) {
            return cache.targets[static_cast<std::size_t>(selected)].bssid;
        }
        return {};
    }
    if (selected < static_cast<int>(cache.stations.size())) {
        const std::string& assoc = cache.stations[static_cast<std::size_t>(selected)].lastBssid;
        if (!assoc.empty() && zd::sec::isValidMac(assoc)) {
            return assoc;
        }
    }
    return {};
}

std::string promptLine(const char* label, bool* outCancelled = nullptr) {
    nodelay(stdscr, FALSE);
    echo();
    curs_set(1);
    int maxy = 0;
    int maxx = 0;
    getmaxyx(stdscr, maxy, maxx);
    (void)maxx;
    mvprintw(maxy - 2, 1, "%s", label);
    clrtoeol();
    refresh();
    char buf[128] = {0};
    const int rc = getnstr(buf, sizeof(buf) - 1);
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);
    if (outCancelled != nullptr) {
        *outCancelled = (rc == ERR);
    }
    return (rc == ERR) ? std::string{} : std::string(buf);
}

int runTui(AppController& app) {
    if (!isatty(STDOUT_FILENO)) {
        std::fprintf(stderr, "tui: stdout is not a terminal; use 'scan' or 'watch'.\n");
        return 2;
    }
    initscr();
    noecho();
    cbreak();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_RED, -1);     // critical / blocked
        init_pair(2, COLOR_GREEN, -1);   // armed / ok
        init_pair(3, COLOR_YELLOW, -1);  // warning
    }

    if (app.secState().targets.empty()) {
        app.requestScan();
    }
    int selected = 0;
    int scrollOffset = 0;
    bool showStations = false;
    bool showHelp = false;
    uint32_t lastStep = 0;
    std::string lastActionMsg;
    TuiCache cache;
    bool dirty = true;
    uint64_t lastDrawnRevision = UINT64_MAX;
    uint32_t lastDrawnUptimeSec = UINT32_MAX;
    bool lastBusy = false;

    while (!g_stop.load()) {
        const uint32_t now = nowMs();
        if (now - lastStep >= 100u) {
            app.step();
            lastStep = now;
            if (auto r = app.takeLastAsyncResult()) {
                lastActionMsg = r->message;
                dirty = true;
            }
        }
        cache.sync(app.secState());
        const int rowCount = showStations ? static_cast<int>(cache.stations.size())
                                          : static_cast<int>(cache.targets.size());
        if (rowCount == 0) {
            selected = 0;
            scrollOffset = 0;
        } else {
            if (selected >= rowCount) {
                selected = rowCount - 1;
            }
            if (selected < 0) {
                selected = 0;
            }
            int maxy = 0, maxx = 0;
            getmaxyx(stdscr, maxy, maxx);
            (void)maxx;
            const int tableRows = (maxy - 4 - 8 > 0) ? (maxy - 4 - 8) : 4;
            if (selected < scrollOffset) {
                scrollOffset = selected;
            } else if (selected >= scrollOffset + tableRows) {
                scrollOffset = selected - tableRows + 1;
            }
        }

        const bool busy = app.asyncBusy();
        const uint32_t uptimeSec = app.petState().uptimeMs / 1000u;
        if (dirty || cache.revision != lastDrawnRevision || uptimeSec != lastDrawnUptimeSec ||
            busy != lastBusy) {
            drawDashboard(app, cache, selected, scrollOffset, showStations, showHelp, lastActionMsg,
                          busy);
            lastDrawnRevision = cache.revision;
            lastDrawnUptimeSec = uptimeSec;
            lastBusy = busy;
            dirty = false;
        }

        const int ch = getch();
        if (ch == ERR) {
            napms(30);
            continue;
        }
        dirty = true;
        if (ch == KEY_RESIZE) {
            // Re-render cleanly at updated dimensions.
        } else if (ch == '?') {
            showHelp = !showHelp;
        } else if (ch == 'q') {
            break;
        } else if (ch == 's') {
            app.requestScan();
        } else if (ch == 'p' || ch == '\t') {
            showStations = !showStations;
            selected = 0;
            scrollOffset = 0;
        } else if (ch == 't' || ch == ']') {
            app.dispatchPet(zd::CycleThemeEvent{nowMs(), +1});
        } else if (ch == 'T' || ch == '[') {
            app.dispatchPet(zd::CycleThemeEvent{nowMs(), -1});
        } else if (ch == 'o') {
            app.cycleOpsMode();
            lastActionMsg = std::string("ops mode: ") + zd::opsModeLabel(app.petState().opsMode);
        } else if (ch == 'v') {
            app.dispatchPet(zd::CyclePageEvent{nowMs(), +1});
        } else if (ch == '1') {
            app.dispatchPet(zd::SetPageEvent{nowMs(), zd::ScreenPage::PetFace});
        } else if (ch == '2') {
            app.dispatchPet(zd::SetPageEvent{nowMs(), zd::ScreenPage::NearbyRadar});
        } else if (ch == '3') {
            app.dispatchPet(zd::SetPageEvent{nowMs(), zd::ScreenPage::ChannelSpectrum});
        } else if (ch == '4') {
            app.dispatchPet(zd::SetPageEvent{nowMs(), zd::ScreenPage::RfGuard});
        } else if (ch == KEY_DOWN || ch == 'j') {
            if (rowCount > 0) {
                selected = (selected + 1) % rowCount;
            }
        } else if (ch == KEY_UP || ch == 'k') {
            if (rowCount > 0) {
                selected = (selected + rowCount - 1) % rowCount;
            }
        } else if (ch == KEY_NPAGE) {
            if (rowCount > 0) {
                int my = 0, mx = 0;
                getmaxyx(stdscr, my, mx);
                (void)mx;
                const int step = (my - 12 > 1) ? (my - 12) : 4;
                selected = (std::min)(rowCount - 1, selected + step);
            }
        } else if (ch == KEY_PPAGE) {
            if (rowCount > 0) {
                int my = 0, mx = 0;
                getmaxyx(stdscr, my, mx);
                (void)mx;
                const int step = (my - 12 > 1) ? (my - 12) : 4;
                selected = (std::max)(0, selected - step);
            }
        } else if (ch == KEY_HOME) {
            if (rowCount > 0) {
                selected = 0;
            }
        } else if (ch == KEY_END) {
            if (rowCount > 0) {
                selected = rowCount - 1;
            }
        } else if (ch == 'm') {
            const auto r = app.monitoring() ? app.stopMonitor() : app.startMonitor();
            lastActionMsg = r.message;
        } else if (ch == 'A') {
            if (app.authorization().operatorConfirmed) {
                app.confirmAuthorization(false);
                lastActionMsg = "authorization revoked (passive/safe mode)";
            } else {
                bool cancelled = false;
                const std::string confirm =
                    promptLine("Type YES to confirm transmit authorization (audit-logged): ",
                               &cancelled);
                if (!cancelled && confirm == "YES") {
                    app.confirmAuthorization(true);
                    lastActionMsg =
                        "authorization CONFIRMED (transmit gate armed for allow-list)";
                } else {
                    lastActionMsg = "authorization not confirmed";
                }
            }
        } else if (ch == 'l' || ch == 'L') {
            const std::string bssid = resolveSelectedBssid(cache, showStations, selected);
            if (bssid.empty()) {
                lastActionMsg = showStations
                                    ? "select an associated station or switch to APs [p]"
                                    : "no target selected";
            } else {
                const bool added = app.toggleAllowBssid(bssid);
                lastActionMsg = added ? ("allow-listed " + bssid)
                                      : ("removed " + bssid + " from allow-list");
            }
        } else if (ch == 'x') {
            const std::string bssid = resolveSelectedBssid(cache, showStations, selected);
            if (bssid.empty()) {
                lastActionMsg = showStations
                                    ? "deauth skipped: select an associated station or switch to APs [p]"
                                    : "deauth skipped: no target selected";
            } else {
                const auto decision = zd::sec::authorize(app.authorization(), bssid);
                if (decision != zd::sec::AuthDecision::Allowed) {
                    lastActionMsg = std::string("deauth refused: ") +
                                    zd::sec::authDecisionLabel(decision) +
                                    " (press A to confirm & L to allow-list)";
                } else if (!app.monitoring()) {
                    lastActionMsg = "deauth refused: start monitor mode first (press m)";
                } else {
                    bool cancelled = false;
                    const std::string cnt = promptLine(
                        ("deauth count for " + bssid + " (1-1000, or empty to cancel): ").c_str(),
                        &cancelled);
                    if (cancelled || cnt.empty()) {
                        lastActionMsg = "deauth cancelled";
                    } else {
                        const uint32_t count = zd::sec::detail::parseU32(cnt);
                        if (count < 1u || count > 1000u) {
                            lastActionMsg = "deauth cancelled: count must be 1..1000";
                        } else {
                            const auto r = app.requestDeauth(bssid, "", count);
                            lastActionMsg = "deauth: " + r.message;
                        }
                    }
                }
            }
        } else if (ch == 'c') {
            const std::string c = promptLine("set channel (1-177, empty to cancel): ");
            if (!c.empty()) {
                int chNum = 0;
                if (!parseStrictIntRange(c, 1, 177, chNum)) {
                    lastActionMsg = "invalid channel (must be 1..177)";
                } else {
                    lastActionMsg = app.setChannel(chNum).message;
                }
            }
        } else if (ch == 'w') {
            const std::string p = promptLine("save session to file: ");
            if (!p.empty()) {
                lastActionMsg = app.saveSession(p).message;
            }
        } else if (ch == 'r') {
            const std::string p = promptLine("load session from file: ");
            if (!p.empty()) {
                lastActionMsg = app.loadSession(p).message;
                selected = 0;
                scrollOffset = 0;
            }
        }
        napms(30);
    }
    app.shutdown();
    endwin();
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    const Args a = parseArgs(argc, argv);

    if (a.command == "help") {
        printHelp();
        return 0;
    }

    if (!zd::sec::isValidIfaceName(a.iface)) {
        std::fprintf(stderr, "invalid wireless interface name '%s'\n", a.iface.c_str());
        return 2;
    }

    AppController app(a.iface);
    if (!a.pcapFile.empty()) {
        app.setPcapDumpPath(a.pcapFile);
    }
    app.boot();

    if (!a.replayFile.empty() && a.command != "replay") {
        const auto r = app.loadSession(a.replayFile);
        std::fprintf(stderr, "[replay] %s\n", r.message.c_str());
        if (!r.ok) {
            return 1;
        }
    }
    if (!a.recordFile.empty()) {
        const auto r = app.startRecording(a.recordFile);
        std::fprintf(stderr, "[record] %s\n", r.message.c_str());
        if (!r.ok) {
            return 1;
        }
    }

    std::string cmd = a.command;
    if (cmd.empty()) {
        if (!a.replayFile.empty() && !isatty(STDOUT_FILENO)) {
            printSecSummary(app.secState(), nowMs());
            return 0;
        }
        cmd = isatty(STDOUT_FILENO) ? "tui" : "scan";
    }

    if (cmd == "tui") {
        return runTui(app);
    }
    if (cmd == "scan") {
        return runScan(app);
    }
    if (cmd == "watch") {
        return runWatch(app, a);
    }
    if (cmd == "replay") {
        return runReplay(app, a.replayFile);
    }
    if (cmd == "deauth") {
        return runDeauth(app, a);
    }
    std::fprintf(stderr, "unknown command '%s'\n", cmd.c_str());
    printHelp();
    return 2;
}
