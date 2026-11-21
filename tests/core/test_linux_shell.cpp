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

    // 2. FileAuditLog & makeDirRecursive refuse symlinks cleanly.
    const std::string symAudit = base + "/sym_audit.log";
    assert(::symlink(auditPath.c_str(), symAudit.c_str()) == 0);
    FileAuditLog symLog(symAudit);
    assert(!symLog.record("SHOULD_FAIL"));

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

    // Multicast client target is rejected in requestDeauth before monitor/injection.
    const auto badCli = ctrl.requestDeauth("02:aa:bb:cc:dd:ee", "01:00:5e:00:00:fb", 4u);
    assert(!badCli.ok);

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

    // Safe shutdown when idle is a no-op.
    ctrl.shutdown();
    assert(!ctrl.monitoring());

    std::remove(replayPath.c_str());
    std::string cleanAudit = base + "/.local/state/pwnagotchi-zeroday/audit.log";
    std::remove(cleanAudit.c_str());
    ::rmdir((base + "/.local/state/pwnagotchi-zeroday").c_str());
    ::rmdir((base + "/.local/state").c_str());
    ::rmdir((base + "/.local").c_str());
    ::rmdir(tmpDir);
}

}  // namespace

int main() {
    testTrustedProcessExecution();
    testAsyncJobLifecycle();
    testAuditLogAndSessionFileHardening();
    testControllerPreflightAndShutdown();
    std::cout << "[linux-shell] all Linux imperative shell tests passed\n";
    return 0;
}
