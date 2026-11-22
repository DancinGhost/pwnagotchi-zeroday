#pragma once

// Pure zero-dependency assessment report formatter (Markdown, CSV, self-contained HTML).
// Safe against CSV formula injection (CWE-1236) and HTML XSS (CWE-79).

#include <zd/secops.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace zd {
namespace sec {

enum class ReportFormat : uint8_t {
    Markdown = 0,
    Csv,
    Html
};

inline std::optional<ReportFormat> reportFormatFromPath(const std::string& path) {
    const auto dot = path.rfind('.');
    if (dot == std::string::npos) {
        return std::nullopt;
    }
    std::string ext;
    ext.reserve(path.size() - dot);
    for (std::size_t i = dot; i < path.size(); ++i) {
        ext.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(path[i]))));
    }
    if (ext == ".md" || ext == ".markdown") {
        return ReportFormat::Markdown;
    }
    if (ext == ".csv") {
        return ReportFormat::Csv;
    }
    if (ext == ".html" || ext == ".htm") {
        return ReportFormat::Html;
    }
    return std::nullopt;
}

inline std::string csvSafeCell(const std::string& raw) {
    std::string clean;
    clean.reserve(raw.size());
    for (unsigned char c : raw) {
        if (c == '\r' || c == '\n' || c < 0x20u || c >= 0x7Fu) {
            clean.push_back(' ');
        } else {
            clean.push_back(static_cast<char>(c));
        }
    }
    if (!clean.empty()) {
        const char first = clean[0];
        if (first == '=' || first == '+' || first == '-' || first == '@' ||
            first == '\t' || first == '\r') {
            clean.insert(clean.begin(), '\'');
        }
    }
    std::string out = "\"";
    out.reserve(clean.size() + 4u);
    for (char c : clean) {
        if (c == '"') {
            out += "\"\"";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

inline std::string htmlEscape(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() + 8u);
    for (unsigned char c : raw) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:
                if (c < 0x20u && c != ' ' && c != '\t') {
                    out.push_back(' ');
                } else if (c >= 0x7Fu) {
                    out.push_back('?');
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

inline std::string markdownSafeCell(const std::string& raw) {
    const std::string clean = sanitizePrintableText(raw, 96u);
    std::string out;
    out.reserve(clean.size());
    for (char c : clean) {
        if (c == '|') {
            out += "\\|";
        } else if (c == '`') {
            out += "'";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

inline const char* severityLabel(Severity s) {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Warn:     return "WARN";
        case Severity::Critical: return "CRITICAL";
    }
    return "INFO";
}

inline std::string targetCaptureFlags(const WifiTarget& t, bool trusted) {
    std::string flags;
    if (trusted) flags += "TRUSTED ";
    if (t.handshake) flags += "HS ";
    if (t.pmkid) flags += "PMKID ";
    if (t.wps) flags += "WPS ";
    if (!flags.empty() && flags.back() == ' ') {
        flags.pop_back();
    }
    return flags.empty() ? std::string("-") : flags;
}

inline std::string formatReport(const SecState& s, ReportFormat fmt, uint32_t nowMs = 0u) {
    const uint32_t stampMs = (nowMs != 0u) ? nowMs : s.lastEventMs;

    std::vector<WifiTarget> targets = s.targets;
    std::sort(targets.begin(), targets.end(), [](const WifiTarget& a, const WifiTarget& b) {
        if (a.handshake != b.handshake) return a.handshake;
        if (a.pmkid != b.pmkid) return a.pmkid;
        return a.rssi > b.rssi;
    });

    if (fmt == ReportFormat::Csv) {
        std::string out =
            "kind,bssid_or_mac,name_or_ssid,channel_or_freq_khz,rssi,security_or_severity,flags,count,extra\n";
        for (const WifiTarget& t : targets) {
            out += "ap," + csvSafeCell(t.bssid) + "," +
                   csvSafeCell(t.ssid.empty() ? "<hidden>" : t.ssid) + "," +
                   std::to_string(t.channel) + "," + std::to_string(t.rssi) + "," +
                   csvSafeCell(encryptionLabel(t.enc)) + "," +
                   csvSafeCell(targetCaptureFlags(t, isTrustedBssid(s, t.bssid))) + "," +
                   std::to_string(t.beacons) + "," +
                   csvSafeCell("clients=" + std::to_string(t.clientCount) +
                               " data=" + std::to_string(t.dataFrames) +
                               " deauths=" + std::to_string(t.deauthsSeen)) +
                   "\n";
        }
        for (const Alert& a : s.alerts) {
            out += "alert," + csvSafeCell(a.bssid) + "," + csvSafeCell(a.ssid) + "," +
                   std::to_string(a.nowMs) + ",0," + csvSafeCell(severityLabel(a.severity)) + "," +
                   csvSafeCell(alertKindLabel(a.kind)) + ",1," + csvSafeCell(a.message) + "\n";
        }
        for (const Station& st : s.stations) {
            std::string probed;
            for (std::size_t i = 0u; i < st.probedSsids.size(); ++i) {
                if (i > 0u) probed += "; ";
                probed += st.probedSsids[i];
            }
            out += "station," + csvSafeCell(st.mac) + "," + csvSafeCell(st.lastBssid) + ",0,0," +
                   csvSafeCell("STA") + "," + csvSafeCell("probes") + "," +
                   std::to_string(st.probeCount) + "," + csvSafeCell(probed) + "\n";
        }
        for (const BleTarget& b : s.bleTargets) {
            out += "ble," + csvSafeCell(b.mac) + "," + csvSafeCell(b.name) + ",2402," +
                   std::to_string(b.rssi) + "," +
                   csvSafeCell(b.threat == BleThreatKind::None ? "BENIGN"
                                                               : bleThreatLabel(b.threat)) +
                   "," + std::to_string(b.companyId) + "," + std::to_string(b.seenCount) + "," +
                   csvSafeCell("uuid=" + std::to_string(b.serviceUuid)) + "\n";
        }
        for (const SubGhzCapture& sub : s.subGhzCaptures) {
            out += "subghz," + csvSafeCell(formatFreqMhz(sub.freqKhz)) + "," +
                   csvSafeCell(sub.protocol) + "," + std::to_string(sub.freqKhz) + "," +
                   std::to_string(sub.rssi) + "," +
                   csvSafeCell(sub.continuousCarrier ? "JAMMER"
                                                     : (sub.burstCount >= 6u ? "REPLAY" : "RX")) +
                   "," + csvSafeCell(sub.continuousCarrier ? "carrier" : "pulse") + "," +
                   std::to_string(sub.burstCount) + ",\n";
        }
        return out;
    }

    if (fmt == ReportFormat::Markdown) {
        std::string out = "# Pwnagotchi ZeroDay — Assessment Report\n\n";
        out += "- **Session Timestamp (ms):** `" + std::to_string(stampMs) + "`\n";
        out += "- **Access Points:** `" + std::to_string(s.targets.size()) + "`\n";
        out += "- **Client Stations:** `" + std::to_string(s.stations.size()) + "`\n";
        out += "- **WPA Handshakes:** `" + std::to_string(s.totalHandshakes) + "`\n";
        out += "- **PMKIDs Captured:** `" + std::to_string(s.totalPmkids) + "`\n";
        out += "- **Deauth/Disassoc Frames:** `" + std::to_string(s.totalDeauths) + "`\n";
        out += "- **Alerts Emitted:** `" + std::to_string(s.totalAlertsEmitted) + "`\n";
        out += "- **Trusted BSSIDs:** `" + std::to_string(s.trustedBssids.size()) + "`\n";
        out += "- **BLE / Sub-GHz Detections:** `" + std::to_string(s.bleTargets.size()) +
               "` / `" + std::to_string(s.subGhzCaptures.size()) + "`\n\n";

        out += "## Access Points\n\n";
        if (targets.empty()) {
            out += "_No access points recorded._\n\n";
        } else {
            out += "| BSSID | SSID | Ch | RSSI | Security | Flags | Clients | Beacons |\n";
            out += "| --- | --- | ---: | ---: | --- | --- | ---: | ---: |\n";
            for (const WifiTarget& t : targets) {
                out += "| `" + markdownSafeCell(t.bssid) + "` | " +
                       markdownSafeCell(t.ssid.empty() ? "<hidden>" : t.ssid) + " | " +
                       std::to_string(t.channel) + " | " + std::to_string(t.rssi) + " dBm | " +
                       encryptionLabel(t.enc) + " | " +
                       markdownSafeCell(targetCaptureFlags(t, isTrustedBssid(s, t.bssid))) + " | " +
                       std::to_string(t.clientCount) + " | " + std::to_string(t.beacons) + " |\n";
            }
            out += "\n";
        }

        out += "## Security Alerts\n\n";
        if (s.alerts.empty()) {
            out += "_No defensive or capture alerts emitted._\n\n";
        } else {
            out += "| Time (ms) | Severity | Kind | BSSID | Detail |\n";
            out += "| ---: | --- | --- | --- | --- |\n";
            for (const Alert& a : s.alerts) {
                out += "| " + std::to_string(a.nowMs) + " | " + severityLabel(a.severity) +
                       " | `" + alertKindLabel(a.kind) + "` | `" + markdownSafeCell(a.bssid) +
                       "` | " + markdownSafeCell(a.message) + " |\n";
            }
            out += "\n";
        }

        if (!s.stations.empty()) {
            out += "## Client Stations\n\n";
            out += "| Station MAC | Last BSSID | Probes | Probed SSIDs |\n";
            out += "| --- | --- | ---: | --- |\n";
            for (const Station& st : s.stations) {
                std::string probed;
                for (std::size_t i = 0u; i < st.probedSsids.size(); ++i) {
                    if (i > 0u) probed += ", ";
                    probed += st.probedSsids[i];
                }
                out += "| `" + markdownSafeCell(st.mac) + "` | `" +
                       markdownSafeCell(st.lastBssid.empty() ? "-" : st.lastBssid) + "` | " +
                       std::to_string(st.probeCount) + " | " +
                       markdownSafeCell(probed.empty() ? "-" : probed) + " |\n";
            }
            out += "\n";
        }

        if (!s.bleTargets.empty() || !s.subGhzCaptures.empty()) {
            out += "## RF Guard (BLE & Sub-GHz)\n\n";
            for (const BleTarget& b : s.bleTargets) {
                out += "- **BLE** `" + markdownSafeCell(b.mac) + "` " +
                       markdownSafeCell(b.name.empty() ? "Unnamed" : b.name) + " (" +
                       std::to_string(b.rssi) + " dBm)" +
                       (b.threat != BleThreatKind::None
                            ? (" **[" + std::string(bleThreatLabel(b.threat)) + "]**")
                            : "") +
                       "\n";
            }
            for (const SubGhzCapture& sub : s.subGhzCaptures) {
                out += "- **Sub-GHz** `" + formatFreqMhz(sub.freqKhz) + "` " +
                       markdownSafeCell(sub.protocol) + " (" + std::to_string(sub.rssi) +
                       " dBm, bursts=" + std::to_string(sub.burstCount) +
                       (sub.continuousCarrier ? ", **JAMMER**" : "") + ")\n";
            }
            out += "\n";
        }
        return out;
    }

    // Self-contained static HTML5 report (all untrusted strings escaped via htmlEscape).
    std::string html =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Pwnagotchi ZeroDay Report</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;"
        "margin:24px;line-height:1.45;}h1,h2{color:#58a6ff;}"
        ".grid{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;}"
        ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 14px;"
        "min-width:130px;}.k{font-size:12px;color:#8b949e;}.v{font-size:20px;font-weight:700;}"
        "table{width:100%;border-collapse:collapse;margin:12px 0 24px;background:#161b22;"
        "border:1px solid #30363d;}th,td{padding:7px 10px;border-bottom:1px solid #21262d;"
        "text-align:left;font-size:13px;}th{background:#1f242c;color:#8b949e;}"
        "code{background:#21262d;padding:1px 5px;border-radius:4px;}"
        ".crit{color:#ff7b72;font-weight:600;}.warn{color:#d29922;font-weight:600;}"
        "</style></head><body><h1>Pwnagotchi ZeroDay — Assessment Report</h1>"
        "<div class=\"grid\">";

    auto addCard = [&](const char* label, uint64_t val) {
        html += "<div class=\"card\"><div class=\"k\">" + htmlEscape(label) +
                "</div><div class=\"v\">" + std::to_string(val) + "</div></div>";
    };
    addCard("Timestamp (ms)", stampMs);
    addCard("Access Points", s.targets.size());
    addCard("Client Stations", s.stations.size());
    addCard("Handshakes", s.totalHandshakes);
    addCard("PMKIDs", s.totalPmkids);
    addCard("Deauth Frames", s.totalDeauths);
    addCard("Alerts", s.totalAlertsEmitted);
    addCard("BLE + Sub-GHz", s.bleTargets.size() + s.subGhzCaptures.size());
    html += "</div>";

    html += "<h2>Access Points</h2><table><thead><tr>"
            "<th>BSSID</th><th>SSID</th><th>Ch</th><th>RSSI</th><th>Security</th>"
            "<th>Flags</th><th>Clients</th><th>Beacons</th></tr></thead><tbody>";
    for (const WifiTarget& t : targets) {
        html += "<tr><td><code>" + htmlEscape(t.bssid) + "</code></td><td>" +
                htmlEscape(t.ssid.empty() ? "<hidden>" : t.ssid) + "</td><td>" +
                std::to_string(t.channel) + "</td><td>" + std::to_string(t.rssi) + " dBm</td><td>" +
                htmlEscape(encryptionLabel(t.enc)) + "</td><td>" +
                htmlEscape(targetCaptureFlags(t, isTrustedBssid(s, t.bssid))) + "</td><td>" +
                std::to_string(t.clientCount) + "</td><td>" + std::to_string(t.beacons) +
                "</td></tr>";
    }
    if (targets.empty()) {
        html += "<tr><td colspan=\"8\">No access points observed.</td></tr>";
    }
    html += "</tbody></table>";

    html += "<h2>Security Alerts</h2><table><thead><tr>"
            "<th>Time (ms)</th><th>Severity</th><th>Kind</th><th>BSSID</th><th>Detail</th>"
            "</tr></thead><tbody>";
    for (const Alert& a : s.alerts) {
        const char* cls = (a.severity == Severity::Critical)
                              ? " class=\"crit\""
                              : ((a.severity == Severity::Warn) ? " class=\"warn\"" : "");
        html += "<tr><td>" + std::to_string(a.nowMs) + "</td><td" + cls + ">" +
                htmlEscape(severityLabel(a.severity)) + "</td><td><code>" +
                htmlEscape(alertKindLabel(a.kind)) + "</code></td><td><code>" +
                htmlEscape(a.bssid) + "</code></td><td>" + htmlEscape(a.message) + "</td></tr>";
    }
    if (s.alerts.empty()) {
        html += "<tr><td colspan=\"5\">No alerts recorded.</td></tr>";
    }
    html += "</tbody></table>";

    if (!s.stations.empty()) {
        html += "<h2>Client Stations</h2><table><thead><tr>"
                "<th>Station</th><th>Last BSSID</th><th>Probes</th><th>Probed SSIDs</th>"
                "</tr></thead><tbody>";
        for (const Station& st : s.stations) {
            std::string probed;
            for (std::size_t i = 0u; i < st.probedSsids.size(); ++i) {
                if (i > 0u) probed += ", ";
                probed += st.probedSsids[i];
            }
            html += "<tr><td><code>" + htmlEscape(st.mac) + "</code></td><td><code>" +
                    htmlEscape(st.lastBssid.empty() ? "-" : st.lastBssid) + "</code></td><td>" +
                    std::to_string(st.probeCount) + "</td><td>" +
                    htmlEscape(probed.empty() ? "-" : probed) + "</td></tr>";
        }
        html += "</tbody></table>";
    }

    html += "</body></html>\n";
    return html;
}

}  // namespace sec
}  // namespace zd
