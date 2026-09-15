#pragma once
#include "GtvTypes.h"
#include "HWID.h"
#include "Security.h"
#include "Integrity.h"
#include "RPCHandler.h"
#include <windows.h>
#include <memory>
#include <atomic>

namespace GTVAC {

    class ACCore {
    public:
        static ACCore& GetInstance();

        // Initializes all Anti-Cheat components and subsystems (RVA: 0x1000a000)
        bool Initialize(HMODULE hModule);

        // Stops all threads and releases allocated resources
        void Shutdown();

        IntegrityManager* GetIntegrityManager() { return m_integrityMgr.get(); }
        RPCHandler* GetRPCHandler() { return m_rpcHandler.get(); }
        const std::string& GetClientHWID() const { return m_clientHwid; }

    private:
        ACCore();
        ~ACCore();

        // Main background initialization and monitoring thread: GTVAC::ACCore::InitThread (RVA: 0x1000b100)
        static DWORD WINAPI InitThread(LPVOID lpParam);

        // SA-MP network connection listener thread: GTVAC::ACCore::WaitForConnection (RVA: 0x1000b200)
        static DWORD WINAPI WaitForConnection(LPVOID lpParam);

        // Periodic heartbeat / security tick evaluation loop
        void MainTickLoop();

        // Handler invoked upon external tampering / cheat detection
        void OnExternalDetected(const ExternalDetectInfo& info);

        HMODULE m_hModule;
        HANDLE m_hInitThread;
        HANDLE m_hWaitThread;
        std::atomic<bool> m_isRunning;
        std::string m_clientHwid;

        std::unique_ptr<IntegrityManager> m_integrityMgr;
        std::unique_ptr<RPCHandler> m_rpcHandler;
    };

} // namespace GTVAC
