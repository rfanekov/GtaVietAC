#pragma once
#include "GtvTypes.h"
#include <windows.h>
#include <functional>

namespace GTVAC {

    class IntegrityManager;

    class RPCHandler {
    public:
        RPCHandler(IntegrityManager* integrityMgr);
        ~RPCHandler();

        // Initializes and hooks into samp.dll (RVA: 0x10016905)
        bool Initialize();

        // Handles file verification RPC request from server: GTVAC::RPCHandler::OnFileCheckRequest (RVA: 0x10013500)
        void OnFileCheckRequest(BitStream& bs);

        // Dispatches verification results / error reports back to the SA-MP server
        void SendFileCheckResponse(bool success, const FileCheckError& error);

        // Transmits client HWID handshake upon successful server connection
        void SendHWIDHandshake(const std::string& hwid);

        // Locates RPC pointer via pattern scanning: "xx????xxx" (RVA: 0x100169a5)
        static uintptr_t FindPattern(uintptr_t baseAddress, size_t imageSize, const uint8_t* pattern, const char* mask);

        bool IsSampHooked() const { return m_isHooked; }

    private:
        IntegrityManager* m_integrityMgr;
        uintptr_t m_sampBase;
        uintptr_t m_rakClient;
        bool m_isHooked;
    };

} // namespace GTVAC
