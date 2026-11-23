// Host unit tests for the Linux imperative shell components:
//   - process.hpp (trusted path resolution, timeout, output cap, DetachedProcess)
//   - async_job.hpp (single-flight worker, non-blocking poll/collect)
//   - cli_backend.hpp (FileAuditLog fail-closed + O_NOFOLLOW, save/loadEventsFromFile caps)
//   - controller.hpp (preflightDeauth, ARM/DISARM audit trail, shutdown safety)

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "async_job.hpp"
#include "cli_backend.hpp"
#include "controller.hpp"
#include "process.hpp"

namespace {

using namespace zd::linux_backend;
using namespace zd::linux_app;

void testTrustedProcessExecution() {
    // Trusted system binary succeeds.
    const CommandResult ok = runCapture({"echo", "hello-zd"});
    assert(ok.launched);
    assert(ok.exitCode == 0);
    assert(!ok.timedOut);
    assert(ok.stdoutText.find("hello-zd") != std::string::npos);

    // Relative paths and non-existent executables are rejected before fork.
    const CommandResult rel = runCapture({"./evil-binary"});
    assert(!rel.launched);
    assert(rel.exitCode == -1);

    // Output byte cap truncates safely instead of allocating unbounded memory.
    const CommandResult capped = runCapture({"yes"}, /*timeoutMs=*/400u, /*maxBytes=*/1024u);
    assert(capped.launched);
    assert(capped.stdoutText.size() <= 1024u);
    assert(capped.truncated);

    // Timeout terminates hung child processes cleanly.
    const CommandResult timed = runCapture({"sleep", "10"}, /*timeoutMs=*/150u);
    assert(timed.launched);
    assert(timed.timedOut);

    // DetachedProcess starts, reports running, and terminates cleanly on stop().
    DetachedProcess dp;
    assert(dp.start({"sleep", "10"}));
    assert(dp.running());
    dp.stop();
    assert(!dp.running());
}

void testAsyncJobLifecycle() {
    AsyncJob<int> job;
    assert(!job.running());
    assert(!job.collect().has_value());

    assert(job.start([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        return 42;
    }));
    // Single-flight: second start while running is rejected.
    assert(!job.start([]() { return 99; }));

    while (job.running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const auto v = job.collect();
    assert(v.has_value() && *v == 42);
    // Consumed exactly once.
    assert(!job.collect().has_value());
}

void testAuditLogAndSessionFileHardening() {
    char dirTmpl[] = "/tmp/zd-test-shell-XXXXXX";
    char* tmpDir = ::mkdtemp(dirTmpl);
    assert(tmpDir != nullptr);
    const std::string base(tmpDir);

    // 1. FileAuditLog writes 0600 file, strips CR/LF/ESC log-injection chars, and returns true.
    const std::string auditPath = base + "/audit.log";
    FileAuditLog audit(auditPath);
    assert(audit.record("TEST_ENTRY ok=true"));
    assert(audit.record("BAD\nFAKE_ALLOWED\r\x1b[31m"));
    struct stat st {};
    assert(::stat(auditPath.c_str(), &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    const std::string auditContents = readFileToString(auditPath);
    assert(auditContents.find("TEST_ENTRY ok=true") != std::string::npos);
    assert(auditContents.find('\x1b') == std::string::npos);
    std::size_t nlCount = 0u;
    for (char ch : auditContents) {
        assert(ch != '\r');
        if (ch == '\n') {
            ++nlCount;
        }
    }
    assert(nlCount == 2u);  // exactly two log entries, no injected line break

    // 2. FileAuditLog emits UTC ISO-8601 'Z' timestamp, refuses symlinks, hardlinks & FIFOs.
    assert(auditContents.find("Z TEST_ENTRY ok=true") != std::string::npos);
    assert(isBlockedSystemPrefix("/etc/passwd"));
    assert(isBlockedSystemPrefix("/usr//local/bin/x"));
    assert(isBlockedSystemPrefix("/tmp/../etc/shadow"));
    assert(isBlockedSystemPrefix("/var/run/zd.pid"));
    assert(!isBlockedSystemPrefix("/var/tmp/zd_safe.zds"));
    assert(!isBlockedSystemPrefix(auditPath));
    {
        char prevCwd[4096];
        if (::getcwd(prevCwd, sizeof(prevCwd)) != nullptr && ::chdir("/etc") == 0) {
            assert(isBlockedSystemPrefix("cron.d/zd"));
            assert(isBlockedSystemPrefix("./passwd"));
            const int rc = ::chdir(prevCwd);
            assert(rc == 0);
        }
    }

    const std::string symAudit = base + "/sym_audit.log";
    assert(::symlink(auditPath.c_str(), symAudit.c_str()) == 0);
    FileAuditLog symLog(symAudit);
    assert(!symLog.record("SHOULD_FAIL"));

    const std::string targetFile = base + "/regular.dat";
    const int regFd = openSecureWriteRegular(targetFile, false);
    assert(regFd >= 0);
    ::close(regFd);
    const std::string hardLinkPath = base + "/hardlink.dat";
    assert(::link(targetFile.c_str(), hardLinkPath.c_str()) == 0);
    assert(openSecureWriteRegular(hardLinkPath, false) == -1);
    const std::string fifoPath = base + "/pipe.dat";
    assert(::mkfifo(fifoPath.c_str(), 0600) == 0);
    assert(openSecureWriteRegular(fifoPath, false) == -1);
    std::remove(fifoPath.c_str());
    std::remove(hardLinkPath.c_str());
    std::remove(targetFile.c_str());

    const std::string realSubDir = base + "/real_dir";
    assert(makeDirRecursive(realSubDir));
    const std::string symDir = base + "/sym_dir";
    assert(::symlink(realSubDir.c_str(), symDir.c_str()) == 0);
    assert(!makeDirRecursive(symDir + "/child"));

    // 3. saveEventsToFile / loadEventsFromFile round-trip + symlink & size-cap rejection.
    const std::string sessPath = base + "/session.zds";
    const std::vector<zd::sec::SecEvent> evs = {
        zd::sec::ApObserved{100u, "02:aa:bb:cc:dd:ee", "LabAP", 6, -42,
                            zd::sec::Encryption::Wpa2, false},
        zd::sec::DeauthObserved{200u, "02:aa:bb:cc:dd:ee", "02:aa:bb:cc:dd:ee",
                                "02:11:22:33:44:55"},
    };
    assert(saveEventsToFile(sessPath, evs));
    const auto loaded = loadEventsFromFile(sessPath);
    assert(loaded.has_value() && loaded->size() == 2u);

    // Reject oversized file via maxBytes cap.
    assert(!loadEventsFromFile(sessPath, /*maxBytes=*/8u).has_value());

    // Reject symlink on loadEventsFromFile (O_NOFOLLOW).
    const std::string symSess = base + "/sym_session.zds";
    assert(::symlink(sessPath.c_str(), symSess.c_str()) == 0);
    assert(!loadEventsFromFile(symSess).has_value());

    // Cleanup temp directory.
    std::remove(symAudit.c_str());
    std::remove(auditPath.c_str());
    std::remove(symSess.c_str());
    std::remove(sessPath.c_str());
    std::remove(symDir.c_str());
    ::rmdir(realSubDir.c_str());
    ::rmdir(tmpDir);
}

void testControllerPreflightAndShutdown() {
    char dirTmpl[] = "/tmp/zd-test-ctrl-XXXXXX";
    char* tmpDir = ::mkdtemp(dirTmpl);
    assert(tmpDir != nullptr);
    const std::string base(tmpDir);
    ::setenv("HOME", tmpDir, 1);

    AppController ctrl("wlan0");
    ctrl.boot(1234u);
    assert(!ctrl.monitoring());
    // Unauthorized preflight refuses without touching monitor mode.
    const auto d1 = ctrl.preflightDeauth("02:aa:bb:cc:dd:ee", "", 4u);
    assert(d1 == zd::sec::AuthDecision::BlockedUnconfirmed);
    assert(!ctrl.monitoring());

    // Multicast client target & invalid deauth channel rejected before monitor/injection.
    const auto badCli = ctrl.requestDeauth("02:aa:bb:cc:dd:ee", "01:00:5e:00:00:fb", 4u);
    assert(!badCli.ok);
    const auto badCh = ctrl.requestDeauth("02:aa:bb:cc:dd:ee", "", 4u, 999);
    assert(!badCh.ok);

    // BLE auto-scan toggle persists controller state cleanly.
    const bool origBleAuto = ctrl.bleAutoEnabled();
    ctrl.setBleAutoEnabled(!origBleAuto);
    assert(ctrl.bleAutoEnabled() == !origBleAuto);
    ctrl.setBleAutoEnabled(origBleAuto);

    // Replay anchors secMood to lastEventMs rather than wall clock so historical alerts stay Alarmed.
    const std::string replayPath = base + "/replay_alarmed.zds";
    const std::vector<zd::sec::SecEvent> replayEvs = {
        zd::sec::ApObserved{1000u, "02:aa:bb:cc:dd:01", "CorpNet", 6, -42,
                            zd::sec::Encryption::Wpa2, false},
        zd::sec::ApObserved{1100u, "02:aa:bb:cc:dd:02", "CorpNet", 6, -45,
                            zd::sec::Encryption::Open, false},
    };
    assert(saveEventsToFile(replayPath, replayEvs));
    const auto loadRes = ctrl.loadSession(replayPath);
    assert(loadRes.ok);
    assert(ctrl.secMood() == zd::sec::SecMood::Alarmed);

    // Replay stays immune to step() auto-scan pollution even past boot auto-scan delay.
    ctrl.step();
    assert(!ctrl.petState().isScanning);
    assert(ctrl.secState().targets.size() == 2u);

    // Trusted BSSID memory persists across AppController boots.
    assert(ctrl.toggleTrustBssid("02:aa:bb:cc:dd:01"));
    assert(zd::sec::isTrustedBssid(ctrl.secState(), "02:aa:bb:cc:dd:01"));
    {
        AppController ctrl2("wlan0");
        ctrl2.boot(78u);
        assert(zd::sec::isTrustedBssid(ctrl2.secState(), "02:aa:bb:cc:dd:01"));
    }
    assert(!ctrl.toggleTrustBssid("02:aa:bb:cc:dd:01"));  // untrusts

    // Assessment report export writes valid .md, .csv, and .html files and rejects bad ext.
    const std::string mdOut = base + "/report.md";
    const std::string csvOut = base + "/report.csv";
    const std::string htmlOut = base + "/report.html";
    assert(ctrl.exportReport(mdOut).ok);
    assert(ctrl.exportReport(csvOut).ok);
    assert(ctrl.exportReport(htmlOut).ok);
    assert(!ctrl.exportReport(base + "/report.exe").ok);
    assert(readFileToString(mdOut).find("CorpNet") != std::string::npos);
    assert(readFileToString(csvOut).find("kind,bssid_or_mac") != std::string::npos);
    assert(readFileToString(htmlOut).find("<!doctype html>") != std::string::npos);

    // Safe shutdown when idle is a no-op.
    ctrl.shutdown();
    assert(!ctrl.monitoring());

    std::remove(mdOut.c_str());
    std::remove(csvOut.c_str());
    std::remove(htmlOut.c_str());
    std::remove(replayPath.c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/trusted_bssids").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/theme").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/highscore").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/audio_muted").c_str());
    ::rmdir((base + "/.config/pwnagotchi-zeroday").c_str());
    ::rmdir((base + "/.config").c_str());
    std::string cleanAudit = base + "/.local/share/pwnagotchi-zeroday/audit.log";
    std::remove(cleanAudit.c_str());
    ::rmdir((base + "/.local/share/pwnagotchi-zeroday").c_str());
    ::rmdir((base + "/.local/share").c_str());
    ::rmdir((base + "/.local").c_str());
    ::rmdir(tmpDir);
}

void testNotificationsAndWardriving() {
    char tmpl[] = "/tmp/zd_shell_nw_XXXXXX";
    char* tmpDir = ::mkdtemp(tmpl);
    assert(tmpDir != nullptr);
    const std::string base = tmpDir;
    ::setenv("HOME", tmpDir, 1);

    AppController ctrl("wlan0");
    ctrl.boot(91u);
    ctrl.setNotifierDryRun(true);
    ctrl.setNotificationsEnabled(true);

    // 1. Critical alert in live monitoring triggers DesktopNotifier once
    zd::sec::CapturedFrame ap1{};
    ap1.nowMs = 1000u;
    ap1.kind = zd::sec::FrameKind::Beacon;
    ap1.bssid = "02:aa:bb:cc:dd:01";
    ap1.ssid = "CorpNet";
    ap1.channel = 6;
    ap1.rssi = -45;
    ap1.enc = zd::sec::Encryption::Wpa2;
    ctrl.processFrame(ap1);
    assert(ctrl.notificationsSent() == 0u);

    zd::sec::CapturedFrame apDowngrade{};
    apDowngrade.nowMs = 1200u;
    apDowngrade.kind = zd::sec::FrameKind::Beacon;
    apDowngrade.bssid = "02:aa:bb:cc:dd:02";
    apDowngrade.ssid = "CorpNet";
    apDowngrade.channel = 6;
    apDowngrade.rssi = -48;
    apDowngrade.enc = zd::sec::Encryption::Open;
    ctrl.processFrame(apDowngrade);
    assert(ctrl.notificationsSent() == 1u);
    assert(ctrl.lastNotificationTitle().find("OPEN-DOWNGRADE") != std::string::npos);
    assert(ctrl.lastNotificationBody().find("CorpNet") != std::string::npos);

    // 2. Linux gpsd + WiGLE wardriving CSV creation & fix-gated logging
    const std::string wdPath = base + "/wardrive.wigle.csv";
    const auto startRes = ctrl.startWardrive(wdPath, /*connectGpsd=*/false);
    assert(startRes.ok && ctrl.wardriving());
    assert(ctrl.flushWardrive(1300u) == 0u);  // no GPS fix yet
    assert(ctrl.ingestGpsLine(
        R"({"class":"TPV","mode":3,"time":"2026-11-22T15:00:00Z","lat":37.7749,"lon":-122.4194})",
        1400u));
    assert(ctrl.ingestGpsLine(R"({"class":"SKY","uSat":8})", 1400u));
    assert(ctrl.gpsState().hasFix && ctrl.gpsState().satellites == 8u);
    assert(ctrl.flushWardrive(1500u) == 2u);
    assert(ctrl.wardriveLoggedCount() == 2u);
    ctrl.stopWardrive();
    assert(!ctrl.wardriving());

    const std::string csv = readFileToString(wdPath);
    assert(csv.find("WigleWifi-1.4") != std::string::npos);
    assert(csv.find("02:aa:bb:cc:dd:01") != std::string::npos);
    assert(csv.find("02:aa:bb:cc:dd:02") != std::string::npos);
    assert(csv.find("37.774") != std::string::npos);
    assert(csv.find("-122.419") != std::string::npos);

    // 3. Replay mode does NOT fire live desktop notifications
    const std::string replayPath = base + "/replay_notify.zds";
    assert(saveEventsToFile(
        replayPath,
        {zd::sec::ApObserved{100u, "02:aa:bb:cc:dd:10", "ReplayNet", 1, -40,
                             zd::sec::Encryption::Wpa2, false},
         zd::sec::ApObserved{200u, "02:aa:bb:cc:dd:11", "ReplayNet", 1, -42,
                             zd::sec::Encryption::Open, false}}));
    assert(ctrl.loadSession(replayPath).ok);
    ctrl.step();
    assert(ctrl.notificationsSent() == 1u);

    std::remove(wdPath.c_str());
    std::remove(replayPath.c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/trusted_bssids").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/theme").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/highscore").c_str());
    std::remove((base + "/.config/pwnagotchi-zeroday/audio_muted").c_str());
    ::rmdir((base + "/.config/pwnagotchi-zeroday").c_str());
    ::rmdir((base + "/.config").c_str());
    std::remove((base + "/.local/share/pwnagotchi-zeroday/audit.log").c_str());
    ::rmdir((base + "/.local/share/pwnagotchi-zeroday").c_str());
    ::rmdir((base + "/.local/share").c_str());
    ::rmdir((base + "/.local").c_str());
    ::rmdir(tmpDir);
}

}  // namespace

int main() {
    testTrustedProcessExecution();
    testAsyncJobLifecycle();
    testAuditLogAndSessionFileHardening();
    testControllerPreflightAndShutdown();
    testNotificationsAndWardriving();
    std::cout << "[linux-shell] all Linux imperative shell tests passed\n";
    return 0;
}
