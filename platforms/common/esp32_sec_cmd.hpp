#pragma once

// Pure, host-testable ESP32 `sec` offensive console core (zero Arduino/ESP-IDF headers).
// Wraps `zd::sec::SecSession` and validates operator serial commands before reaching the PHY.

#include <cstdint>
#include <string>
#include <vector>

#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

namespace zd {
namespace esp32_common {

class IOffensiveChannelInjector : public zd::sec::IInjector {
public:
    virtual void setChannel(int channel) = 0;
};

class IOffensiveScanner {
public:
    virtual ~IOffensiveScanner() = default;
    virtual std::string runScan(uint32_t nowMs, zd::sec::SecSession& session) = 0;
};

class IAuditCounters {
public:
    virtual ~IAuditCounters() = default;
    virtual unsigned long transmittedTotal() const = 0;
    virtual unsigned long blockedTotal() const = 0;
};

class OffensiveConsoleCore {
public:
    static constexpr const char* kArmToken = "I-HAVE-AUTHORIZATION";
    static constexpr uint32_t kMaxBurst = 64u;

    OffensiveConsoleCore(IOffensiveChannelInjector& injector,
                         zd::sec::IAuditLog& audit,
                         IOffensiveScanner& scanner,
                         const IAuditCounters* counters = nullptr)
        : injector_(injector), audit_(audit), scanner_(scanner), counters_(counters) {
        session_.setMaxRecordedEvents(0u);
    }

    bool isArmed() const { return session_.authorization().operatorConfirmed; }
    const zd::sec::SecSession& session() const { return session_; }
    zd::sec::SecSession& mutableSession() { return session_; }

    static bool parseStrictBurstCount(const std::string& raw, uint32_t& out) {
        if (raw.empty()) {
            return false;
        }
        uint64_t val = 0u;
        for (unsigned char c : raw) {
            if (c < '0' || c > '9') {
                return false;
            }
            val = val * 10u + static_cast<uint64_t>(c - '0');
            if (val > 0xFFFFFFFFull) {
                val = kMaxBurst;
                break;
            }
        }
        if (val == 0u) {
            return false;
        }
        out = (val > kMaxBurst) ? kMaxBurst : static_cast<uint32_t>(val);
        return true;
    }

    std::string handleLine(const std::string& line, uint32_t nowMs) {
        std::vector<std::string> tok = tokenize(line);
        const std::string sub = tok.size() > 1 ? tok[1] : std::string("help");

        if (sub == "help") {
            return help();
        }
        if (sub == "status") {
            return status();
        }
        if (sub == "scan") {
            return scanner_.runScan(nowMs, session_);
        }
        if (sub == "allow" || sub == "deny") {
            if (tok.size() < 3 || !zd::sec::isValidMac(tok[2]) || zd::sec::isMulticastMac(tok[2])) {
                return "usage: sec " + sub + " <unicast-bssid>\n";
            }
            const std::string mac = zd::sec::normalizeMac(tok[2]);
            if (sub == "allow") {
                session_.authorization().allow(mac);
                return "allow-listed " + mac + " (" +
                       std::to_string(session_.authorization().allowedBssids.size()) + " total)\n";
            }
            return session_.authorization().disallow(mac)
                       ? ("removed " + mac + " from allow-list\n")
                       : (mac + " was not on the allow-list\n");
        }
        if (sub == "arm") {
            if (tok.size() < 3 || tok[2] != std::string(kArmToken)) {
                return std::string("Arming authorizes THIS device to transmit deauth frames at\n"
                                   "targets you have explicitly allow-listed. Only do this for\n"
                                   "networks you own or are authorized in writing to assess.\n"
                                   "To confirm: sec arm ") +
                       kArmToken + "\n";
            }
            session_.authorization().operatorConfirmed = true;
            (void)audit_.record("ARM operatorConfirmed=true");
            return "ARMED. Gate still requires each target on the allow-list. `sec disarm` to revert.\n";
        }
        if (sub == "disarm") {
            session_.authorization().operatorConfirmed = false;
            (void)audit_.record("DISARM operatorConfirmed=false");
            return "DISARMED. No transmit will be permitted until re-armed.\n";
        }
        if (sub == "deauth") {
            return deauth(tok, nowMs);
        }
        return "unknown subcommand '" + sub + "'\n" + help();
    }

private:
    static std::vector<std::string> tokenize(const std::string& line) {
        std::vector<std::string> out;
        std::string cur;
        for (char c : line) {
            if (c == ' ' || c == '\t') {
                if (!cur.empty()) {
                    out.push_back(cur);
                    cur.clear();
                }
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) {
            out.push_back(cur);
        }
        return out;
    }

    static std::string help() {
        return "sec commands (active offense — authorized use only):\n"
               "  sec status                 show arm state, allow-list, counters\n"
               "  sec scan                   discover nearby BSSIDs + channels\n"
               "  sec allow <bssid>          add a BSSID you are authorized to test\n"
               "  sec deny  <bssid>          remove a BSSID from the allow-list\n"
               "  sec arm I-HAVE-AUTHORIZATION  confirm authorization (required to transmit)\n"
               "  sec disarm                 revoke authorization\n"
               "  sec deauth <bssid> [count] [client] transmit deauth (gated; allow-listed + armed)\n";
    }

    std::string status() const {
        const zd::sec::Authorization& a = session_.authorization();
        const zd::sec::SecState& s = session_.state();
        std::string out = "sec: ";
        out += a.operatorConfirmed ? "ARMED" : "DISARMED";
        out += " | allow-list: " + std::to_string(a.allowedBssids.size());
        for (const std::string& b : a.allowedBssids) {
            out += "\n    allow " + b;
        }
        out += "\n  targets seen: " + std::to_string(s.targets.size());
        out += " | tx allowed: " + std::to_string(s.allowedInjections);
        out += " | tx blocked: " + std::to_string(s.blockedInjections);
        if (counters_ != nullptr) {
            out += "\n  durable counters: deauth_tx=" +
                   std::to_string(counters_->transmittedTotal()) +
                   " deauth_blk=" + std::to_string(counters_->blockedTotal());
        }
        out += "\n";
        return out;
    }

    std::string deauth(const std::vector<std::string>& tok, uint32_t nowMs) {
        if (tok.size() < 3 || !zd::sec::isValidMac(tok[2]) || zd::sec::isMulticastMac(tok[2])) {
            return "usage: sec deauth <unicast-bssid> [count 1-64] [client-mac]\n";
        }
        const std::string bssid = zd::sec::normalizeMac(tok[2]);
        uint32_t reqCount = 8u;
        if (tok.size() >= 4 && !parseStrictBurstCount(tok[3], reqCount)) {
            return "invalid count '" + tok[3] + "' (must be 1..64)\n";
        }
        std::string client;
        if (tok.size() >= 5) {
            if (!zd::sec::isValidClientTarget(tok[4])) {
                return "invalid client MAC '" + tok[4] + "'\n";
            }
            client = tok[4];
        }

        const zd::sec::WifiTarget* t = zd::sec::findTarget(session_.state(), bssid);
        if (t == nullptr) {
            return "unknown BSSID " + bssid + " — run `sec scan` first\n";
        }
        injector_.setChannel(t->channel);

        const zd::sec::InjectResult r =
            session_.requestDeauth(injector_, bssid, client, reqCount, nowMs, &audit_);
        if (r.decision != zd::sec::AuthDecision::Allowed) {
            return std::string("BLOCKED: ") + zd::sec::authDecisionLabel(r.decision) +
                   "\n  (need: sec allow " + bssid + "  then  sec arm " + kArmToken + ")\n";
        }
        return std::string(r.transmitted ? "OK: " : "TX-FAIL: ") + r.detail + "\n";
    }

    IOffensiveChannelInjector& injector_;
    zd::sec::IAuditLog& audit_;
    IOffensiveScanner& scanner_;
    const IAuditCounters* counters_ = nullptr;
    zd::sec::SecSession session_;
};

}  // namespace esp32_common
}  // namespace zd
