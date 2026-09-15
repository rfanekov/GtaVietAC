#pragma once
#include "GtvTypes.h"
#include <windows.h>
#include <vector>
#include <string>
#include <functional>

namespace GTVAC {
namespace Security {

    class AntiRE {
    public:
        using DetectionCallback = std::function<void(const ExternalDetectInfo&)>;

        // Initializes Anti-Reverse Engineering subsystem (RVA: 0x1000b100)
        static bool Initialize();

        // GTAVIET proprietary dynamic XOR string decryption algorithm (Key = 0x39)
        static std::string DecryptString(const uint8_t* rawData, size_t length, uint8_t key = 0x39);

        // Checks PEB BeingDebugged flag, CheckRemoteDebuggerPresent, and Hardware Breakpoints DR0-DR7
        static bool CheckDebuggers();

        // Scans background running processes against Blacklist & Whitelist (RVA: 0x1000bd00)
        static bool ScanProcesses(std::vector<ExternalDetectInfo>& outDetections);

        // Scans desktop window titles for memory tampering and reversing tools (RVA: 0x1000b370)
        static bool ScanWindows(std::vector<ExternalDetectInfo>& outDetections);

        // Registers callback invoked upon violation detection
        static void SetDetectionCallback(DetectionCallback cb);

        // Executes all security audit checks
        static bool PerformSecurityAudit(std::vector<ExternalDetectInfo>& outDetections);

    private:
        static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
        static DetectionCallback s_callback;
    };

} // namespace Security
} // namespace GTVAC
