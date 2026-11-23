#pragma once

// Minimal POSIX subprocess helpers for the CLI-tool WiFi backend.
//
// Security & concurrency guarantees:
//   - Never invokes a shell; builds argv vectors BEFORE fork() so multi-threaded callers
//     (Qt6 GUI, AsyncJob workers) perform only async-signal-safe syscalls in the child.
//   - Resolves bare binary names exclusively against trusted root-owned system directories
//     (/usr/sbin, /sbin, /usr/bin, /bin) via execv(), preventing PATH hijacking (CWE-426)
//     when running with elevated privileges.
//   - Bounds captured output size and wall-clock runtime in runCapture() with EINTR retries.

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace zd {
namespace linux_backend {

struct CommandResult {
    int exitCode = -1;
    bool launched = false;
    bool timedOut = false;
    bool truncated = false;
    std::string stdoutText;
};

namespace detail {

inline bool isTrustedExecutable(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }
    if ((st.st_mode & 0111) == 0) {
        return false;
    }
    // Reject group/world-writable binaries unconditionally, and require root ownership
    // when running privileged (euid == 0). (Unprivileged user-namespace sandboxes/containers
    // map host root to nobody/65534, so checking uid==0 only when euid==0 stays portable.)
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
    if (::geteuid() == 0 && st.st_uid != 0) {
        return false;
    }
    return true;
}

// Resolve `prog` to an absolute path in fixed trusted system directories (never $PATH).
inline std::string resolveTrustedExecutable(const std::string& prog) {
    if (prog.empty()) {
        return {};
    }
    static constexpr const char* kTrustedDirs[] = {"/usr/sbin", "/sbin", "/usr/bin", "/bin"};
    if (prog.front() == '/') {
        if (prog.find("..") != std::string::npos) {
            return {};
        }
        bool inTrusted = false;
        for (const char* dir : kTrustedDirs) {
            const std::string prefix = std::string(dir) + "/";
            if (prog.rfind(prefix, 0) == 0 && prog.find('/', prefix.size()) == std::string::npos) {
                inTrusted = true;
                break;
            }
        }
        if (!inTrusted) {
            return {};
        }
        return isTrustedExecutable(prog) ? prog : std::string{};
    }
    // Reject relative paths containing '/'.
    if (prog.find('/') != std::string::npos) {
        return {};
    }
    for (const char* dir : kTrustedDirs) {
        const std::string candidate = std::string(dir) + "/" + prog;
        if (isTrustedExecutable(candidate)) {
            return candidate;
        }
    }
    return {};
}

// Async-signal-safe minimal environment for privileged subprocesses.
inline char* const* safeEnviron() noexcept {
    static char envPath[] = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";
    static char envLc[]   = "LC_ALL=C";
    static char envLang[] = "LANG=C";
    static char envTerm[] = "TERM=dumb";
    static char* const kEnv[] = {envPath, envLc, envLang, envTerm, nullptr};
    return kEnv;
}

inline int safeMaxFd() noexcept {
    long m = ::sysconf(_SC_OPEN_MAX);
    if (m < 256 || m > 65536) {
        m = 1024;
    }
    return static_cast<int>(m);
}

#if defined(__linux__) && defined(SYS_getdents64)
namespace fd_detail {
struct LinuxDirent64Header {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[1];
};
}  // namespace fd_detail
#endif

// Async-signal-safe close of all FDs >= 3 before execve().
inline void closeNonStdioFds(int maxFd) noexcept {
#if defined(__linux__) && defined(SYS_close_range)
    if (::syscall(SYS_close_range, 3u, ~0u, 0u) == 0) {
        return;
    }
#endif
#if defined(__linux__) && defined(SYS_getdents64)
    const int dirfd = ::open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd >= 0) {
        char buf[2048];
        for (;;) {
            const long nread = ::syscall(SYS_getdents64, dirfd, buf, sizeof(buf));
            if (nread <= 0) {
                break;
            }
            for (long pos = 0; pos < nread;) {
                const auto* d = reinterpret_cast<const fd_detail::LinuxDirent64Header*>(buf + pos);
                if (d->d_reclen == 0) {
                    break;
                }
                int parsed = 0;
                bool isDigits = (d->d_name[0] != '\0');
                for (std::size_t i = 0; i < 16u && d->d_name[i] != '\0'; ++i) {
                    const char ch = d->d_name[i];
                    if (ch < '0' || ch > '9') {
                        isDigits = false;
                        break;
                    }
                    parsed = parsed * 10 + (ch - '0');
                }
                if (isDigits && parsed >= 3 && parsed != dirfd) {
                    ::close(parsed);
                }
                pos += d->d_reclen;
            }
        }
        ::close(dirfd);
        return;
    }
#endif
    for (int fd = 3; fd < maxFd; ++fd) {
        ::close(fd);
    }
}

inline pid_t waitpidNoIntr(pid_t pid, int* status, int options) {
    pid_t r;
    do {
        r = ::waitpid(pid, status, options);
    } while (r < 0 && errno == EINTR);
    return r;
}

inline void terminateChild(pid_t pid) {
    if (pid <= 0) {
        return;
    }
    ::kill(-pid, SIGTERM);
    ::kill(pid, SIGTERM);
    for (int i = 0; i < 10; ++i) {
        int st = 0;
        if (waitpidNoIntr(pid, &st, WNOHANG) == pid) {
            return;
        }
        ::usleep(20 * 1000);
    }
    ::kill(-pid, SIGKILL);
    ::kill(pid, SIGKILL);
    int st = 0;
    waitpidNoIntr(pid, &st, 0);
}

}  // namespace detail

// Run argv[0] with argv to completion, capturing stdout+stderr with bounded output and timeout.
// Returns exitCode == 0 on success.
inline CommandResult runCapture(const std::vector<std::string>& argv,
                                uint32_t timeoutMs = 15000u,
                                std::size_t maxBytes = 4u * 1024u * 1024u) {
    CommandResult res;
    if (argv.empty()) {
        return res;
    }
    const std::string resolved = detail::resolveTrustedExecutable(argv[0]);
    if (resolved.empty()) {
        return res;
    }

    int pipefd[2];
#if defined(__linux__)
    if (::pipe2(pipefd, O_CLOEXEC) != 0) {
        return res;
    }
#else
    if (::pipe(pipefd) != 0) {
        return res;
    }
    ::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
#endif

    // Pre-build argv pointers BEFORE fork() so the child performs zero heap allocations.
    std::vector<std::string> ownedArgs = argv;
    ownedArgs[0] = resolved;
    std::vector<char*> cargv;
    cargv.reserve(ownedArgs.size() + 1u);
    for (std::string& a : ownedArgs) {
        cargv.push_back(a.data());
    }
    cargv.push_back(nullptr);
    const char* const execPath = resolved.c_str();
    char* const* const execArgv = cargv.data();
    char* const* const execEnv = detail::safeEnviron();
    const int maxFd = detail::safeMaxFd();

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return res;
    }

    if (pid == 0) {
        // Child: async-signal-safe calls only.
        ::setpgid(0, 0);
        const int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            if (devnull != STDIN_FILENO) {
                ::close(devnull);
            }
        }
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        if (pipefd[0] > STDERR_FILENO) {
            ::close(pipefd[0]);
        }
        if (pipefd[1] > STDERR_FILENO) {
            ::close(pipefd[1]);
        }
        detail::closeNonStdioFds(maxFd);
        ::execve(execPath, execArgv, execEnv);
        ::_exit(127);
    }

    // Parent: bounded non-hanging read with monotonic deadline.
    ::close(pipefd[1]);
    res.launched = true;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    char buf[4096];
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        int pollMs = -1;
        if (timeoutMs > 0u) {
            if (now >= deadline) {
                res.timedOut = true;
                break;
            }
            const auto rem =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            pollMs = (rem > 0) ? static_cast<int>(rem) : 1;
        }

        struct pollfd pfd {};
        pfd.fd = pipefd[0];
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, pollMs);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            res.timedOut = true;
            break;
        }

        const ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
            const std::size_t got = static_cast<std::size_t>(n);
            if (res.stdoutText.size() < maxBytes) {
                const std::size_t room = maxBytes - res.stdoutText.size();
                const std::size_t take = (got < room) ? got : room;
                res.stdoutText.append(buf, take);
                if (got > room) {
                    res.truncated = true;
                }
            } else {
                res.truncated = true;
            }
        } else if (n == 0) {
            break;
        } else if (errno != EINTR) {
            break;
        }
    }
    ::close(pipefd[0]);

    if (res.timedOut) {
        detail::terminateChild(pid);
        return res;
    }

    int status = 0;
    if (detail::waitpidNoIntr(pid, &status, 0) == pid && WIFEXITED(status)) {
        res.exitCode = WEXITSTATUS(status);
    }
    return res;
}

// A long-running child process we control (e.g. airodump-ng writing CSV to disk). Its
// stdout/stderr are sent to /dev/null; we interact with it only through its output files
// and by signalling it. Call stop() to SIGTERM (then SIGKILL) it.
class DetachedProcess {
public:
    DetachedProcess() = default;
    DetachedProcess(const DetachedProcess&) = delete;
    DetachedProcess& operator=(const DetachedProcess&) = delete;
    ~DetachedProcess() { stop(); }

    bool start(const std::vector<std::string>& argv) {
        if (running_.load() || argv.empty()) {
            return false;
        }
        const std::string resolved = detail::resolveTrustedExecutable(argv[0]);
        if (resolved.empty()) {
            return false;
        }

        // Pre-build argv pointers BEFORE fork() so the child performs zero heap allocations.
        std::vector<std::string> ownedArgs = argv;
        ownedArgs[0] = resolved;
        std::vector<char*> cargv;
        cargv.reserve(ownedArgs.size() + 1u);
        for (std::string& a : ownedArgs) {
            cargv.push_back(a.data());
        }
        cargv.push_back(nullptr);
        const char* const execPath = resolved.c_str();
        char* const* const execArgv = cargv.data();
        char* const* const execEnv = detail::safeEnviron();
        const int maxFd = detail::safeMaxFd();

        const pid_t pid = ::fork();
        if (pid < 0) {
            return false;
        }
        if (pid == 0) {
            ::setpgid(0, 0);
            const int devnull = ::open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                ::dup2(devnull, STDIN_FILENO);
                ::dup2(devnull, STDOUT_FILENO);
                ::dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) {
                    ::close(devnull);
                }
            }
            detail::closeNonStdioFds(maxFd);
            ::execve(execPath, execArgv, execEnv);
            ::_exit(127);
        }
        pid_ = pid;
        running_.store(true);
        return true;
    }

    bool running() const {
        if (!running_.load()) {
            return false;
        }
        int status = 0;
        const pid_t r = detail::waitpidNoIntr(pid_, &status, WNOHANG);
        if (r == pid_) {
            running_.store(false);  // reaped
        }
        return running_.load();
    }

    void stop() {
        if (!running_.load()) {
            return;
        }
        ::kill(-pid_, SIGTERM);
        ::kill(pid_, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            int status = 0;
            if (detail::waitpidNoIntr(pid_, &status, WNOHANG) == pid_) {
                running_.store(false);
                pid_ = -1;
                return;
            }
            ::usleep(50 * 1000);  // 50ms
        }
        ::kill(-pid_, SIGKILL);
        ::kill(pid_, SIGKILL);
        int status = 0;
        detail::waitpidNoIntr(pid_, &status, 0);
        running_.store(false);
        pid_ = -1;
    }

    pid_t pid() const { return pid_; }

private:
    mutable std::atomic<bool> running_{false};
    pid_t pid_ = -1;
};

}  // namespace linux_backend
}  // namespace zd
