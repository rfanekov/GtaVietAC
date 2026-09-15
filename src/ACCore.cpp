#include "../include/ACCore.h"
#include <chrono>
#include <thread>

namespace GTVAC {

    ACCore& ACCore::GetInstance() {
        static ACCore instance;
        return instance;
    }

    ACCore::ACCore()
        : m_hModule(nullptr), m_hInitThread(nullptr), m_hWaitThread(nullptr), m_isRunning(false) {
        m_integrityMgr = std::make_unique<IntegrityManager>();
        m_rpcHandler = std::make_unique<RPCHandler>(m_integrityMgr.get());
    }

    ACCore::~ACCore() {
        Shutdown();
    }

    bool ACCore::Initialize(HMODULE hModule) {
        m_hModule = hModule;
        m_isRunning = true;

        // Register security violation callback handler
        Security::AntiRE::SetDetectionCallback([this](const ExternalDetectInfo& info) {
            this->OnExternalDetected(info);
        });

        // Create primary initialization thread: InitThread
        m_hInitThread = CreateThread(nullptr, 0, InitThread, this, 0, nullptr);

        // Create thread listening for SA-MP connection: WaitForConnection
        m_hWaitThread = CreateThread(nullptr, 0, WaitForConnection, this, 0, nullptr);

        return true;
    }

    void ACCore::Shutdown() {
        m_isRunning = false;
        if (m_hInitThread) {
            WaitForSingleObject(m_hInitThread, 1000);
            CloseHandle(m_hInitThread);
            m_hInitThread = nullptr;
        }
        if (m_hWaitThread) {
            WaitForSingleObject(m_hWaitThread, 1000);
            CloseHandle(m_hWaitThread);
            m_hWaitThread = nullptr;
        }
    }

    // RVA: 0x1000b100 - Background initialization and monitoring thread
    DWORD WINAPI ACCore::InitThread(LPVOID lpParam) {
        ACCore* core = static_cast<ACCore*>(lpParam);

        // 1. Initialize Anti-RE
        Security::AntiRE::Initialize();

        // 2. Generate unique machine HWID
        core->m_clientHwid = HWIDManager::GenerateHWID();

        // 3. Capture game file tree baseline snapshot
        char currentDir[MAX_PATH] = { 0 };
        GetCurrentDirectoryA(MAX_PATH, currentDir);
        core->m_integrityMgr->TakeFileSystemSnapshot(currentDir);

        // 4. Enter periodic scan tick loop
        core->MainTickLoop();

        return 0;
    }

    // RVA: 0x1000b200 - Thread awaiting SA-MP network connection
    DWORD WINAPI ACCore::WaitForConnection(LPVOID lpParam) {
        ACCore* core = static_cast<ACCore*>(lpParam);

        // Wait until samp.dll is loaded into current process
        while (core->m_isRunning && !GetModuleHandleA("samp.dll")) {
            Sleep(500);
        }

        if (!core->m_isRunning) return 0;

        // Allow samp.dll to stabilize and complete initialization
        Sleep(1500);

        // Hook into samp.dll
        if (core->m_rpcHandler->Initialize()) {
            // Dispatch HWID authentication handshake packet
            core->m_rpcHandler->SendHWIDHandshake(core->m_clientHwid);
        }

        return 0;
    }

    // Periodic scan loop executed every 2.5 seconds
    void ACCore::MainTickLoop() {
        while (m_isRunning) {
            std::vector<ExternalDetectInfo> detections;

            // Scan for debuggers, cheating processes, and memory tampering window titles
            Security::AntiRE::PerformSecurityAudit(detections);

            // Check CLEO directory integrity
            char currentDir[MAX_PATH] = { 0 };
            GetCurrentDirectoryA(MAX_PATH, currentDir);
            std::vector<FileCheckError> fileErrors;
            m_integrityMgr->ScanCleoDirectory(std::string(currentDir) + "\\cleo", fileErrors);

            // Sleep between audit cycles
            Sleep(2500);
        }
    }

    void ACCore::OnExternalDetected(const ExternalDetectInfo& info) {
        // Record detected cheat / violation event
        // Send detection report to server if RPC handler is active
        if (m_rpcHandler && m_rpcHandler->IsSampHooked()) {
            FileCheckError err = {
                FileCheckStatus::FILE_DETECTED,
                info.targetName,
                "", "",
                info.description
            };
            m_rpcHandler->SendFileCheckResponse(false, err);
        }
    }

} // namespace GTVAC
