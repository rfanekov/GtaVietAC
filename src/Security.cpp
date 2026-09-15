#include "../include/Security.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>

namespace GTVAC {
namespace Security {

    AntiRE::DetectionCallback AntiRE::s_callback = nullptr;

    // Process blacklist extracted directly from decrypted strings of ngu.asi
    static const std::vector<std::string> g_processBlacklist = {
        "x64dbg.exe", "x32dbg.exe", "cheatengine-i386.exe", "cheatengine-x86_64.exe",
        "cheat engine.exe", "ce.exe", "ollydbg.exe", "ida64.exe", "ida.exe", "idaq.exe",
        "processhacker.exe", "artmoney.exe", "tsearch.exe", "reclass.exe", "reclass.net.exe",
        "wireshark.exe", "autohotkey.exe", "autohotkey64.exe", "autohotkeya32.exe",
        "autohotkeysc.exe", "autohotkeyu64.exe", "ahk.exe", "autoit3.exe", "autoit3_x64.exe",
        "lua52.exe", "lua53.exe", "luajit.exe", "python.exe", "pythonw.exe", "javaw.exe",
        "injector.exe"
    };

    // Whitelist of legitimate system processes
    static const std::vector<std::string> g_processWhitelist = {
        "explorer.exe", "taskmgr.exe", "csrss.exe", "lsass.exe", "fontdrvhost.exe",
        "securityhealthservice.exe", "ctfmon.exe", "gta-sa.exe", "gta_sa.exe",
        "steamwebhelper.exe", "cmd.exe", "mmc.exe", "taskhostw.exe", "msedge.exe",
        "smartscreen.exe", "wmiprvse.exe", "wt.exe", "winlogon.exe", "runtimebroker.exe"
    };

    // Window title blacklist keywords
    static const std::vector<std::string> g_windowBlacklist = {
        "ce tutorial", "cheat engine", "x64dbg", "x32dbg", "ollydbg", "ida pro",
        "ghidra", "debugger", "gamehack", "memory scanner", "memoryscanner",
        "memory hacking", "artmoney", "art money", "reclass", "process hacker",
        "sobeit", "s0beit", "samphack", "aimbot", "wallhack", "speed hack",
        "esp hack", "injector", "inject dll", "dll inject", "trainer", "tsearch"
    };

    static std::string ToLower(std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return str;
    }

    // RVA: 0x1000b389 - Dynamic XOR string decryption algorithm
    std::string AntiRE::DecryptString(const uint8_t* rawData, size_t length, uint8_t key) {
        if (!rawData || length == 0) return "";
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            uint8_t k = static_cast<uint8_t>((i % key) + key);
            char c = static_cast<char>(rawData[i] ^ k);
            if (c == '\0') break;
            result.push_back(c);
        }
        return result;
    }

    bool AntiRE::Initialize() {
        return true;
    }

    void AntiRE::SetDetectionCallback(DetectionCallback cb) {
        s_callback = cb;
    }

    // RVA: 0x1000d204 - Scans PEB flags and Hardware Breakpoints
    bool AntiRE::CheckDebuggers() {
        // 1. Check PEB BeingDebugged
        BOOL isDebuggerPresent = IsDebuggerPresent();
        if (isDebuggerPresent) {
            if (s_callback) {
                s_callback({ DetectType::DEBUGGER_ATTACHED, "PEB.BeingDebugged", GetCurrentProcessId(), "IsDebuggerPresent returned true" });
            }
            return true;
        }

        // 2. CheckRemoteDebuggerPresent
        BOOL isRemoteDebug = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebug) && isRemoteDebug) {
            if (s_callback) {
                s_callback({ DetectType::DEBUGGER_ATTACHED, "CheckRemoteDebuggerPresent", GetCurrentProcessId(), "Remote debugger attached" });
            }
            return true;
        }

        // 3. Scan Hardware Breakpoints (DR0 - DR7)
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        if (GetThreadContext(hThread, &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                if (s_callback) {
                    s_callback({ DetectType::DEBUGGER_ATTACHED, "HardwareBreakpoint", GetCurrentProcessId(), "DR0-DR3 active" });
                }
                return true;
            }
        }

        return false;
    }

    // RVA: 0x1000bd00 - Scans currently running processes
    bool AntiRE::ScanProcesses(std::vector<ExternalDetectInfo>& outDetections) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(pe32);

        bool detected = false;
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                char exeName[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeName, MAX_PATH, nullptr, nullptr);
                std::string procNameLower = ToLower(exeName);

                // Skip if whitelisted
                bool isWhitelisted = false;
                for (const auto& w : g_processWhitelist) {
                    if (procNameLower == w) {
                        isWhitelisted = true;
                        break;
                    }
                }
                if (isWhitelisted) continue;

                // Check against blacklist
                for (const auto& b : g_processBlacklist) {
                    if (procNameLower == b || procNameLower.find(b) != std::string::npos) {
                        ExternalDetectInfo info = {
                            DetectType::PROCESS_BLACKLIST,
                            procNameLower,
                            pe32.th32ProcessID,
                            "Blacklisted cheating or reversing tool process active"
                        };
                        outDetections.push_back(info);
                        if (s_callback) s_callback(info);
                        detected = true;
                        break;
                    }
                }
            } while (Process32NextW(hSnap, &pe32));
        }

        CloseHandle(hSnap);
        return detected;
    }

    // EnumWindows callback inspecting desktop window titles
    BOOL CALLBACK AntiRE::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        if (!IsWindowVisible(hwnd)) return TRUE;

        char title[512] = { 0 };
        int len = GetWindowTextA(hwnd, title, sizeof(title));
        if (len <= 0) return TRUE;

        std::string titleLower = ToLower(title);
        auto* detections = reinterpret_cast<std::vector<ExternalDetectInfo>*>(lParam);

        for (const auto& keyword : g_windowBlacklist) {
            if (titleLower.find(keyword) != std::string::npos) {
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);

                ExternalDetectInfo info = {
                    DetectType::WINDOW_BLACKLIST,
                    std::string(title),
                    pid,
                    "Window title contains forbidden keyword: " + keyword
                };
                detections->push_back(info);
                if (s_callback) s_callback(info);
                break;
            }
        }
        return TRUE;
    }

    // RVA: 0x1000b370 - Enumerates all desktop windows
    bool AntiRE::ScanWindows(std::vector<ExternalDetectInfo>& outDetections) {
        size_t prevCount = outDetections.size();
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&outDetections));
        return outDetections.size() > prevCount;
    }

    bool AntiRE::PerformSecurityAudit(std::vector<ExternalDetectInfo>& outDetections) {
        bool d1 = CheckDebuggers();
        bool d2 = ScanProcesses(outDetections);
        bool d3 = ScanWindows(outDetections);
        return d1 || d2 || d3;
    }

} // namespace Security
} // namespace GTVAC
