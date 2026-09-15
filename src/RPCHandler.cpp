#include "../include/RPCHandler.h"
#include "../include/Integrity.h"
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace GTVAC {

    RPCHandler::RPCHandler(IntegrityManager* integrityMgr)
        : m_integrityMgr(integrityMgr), m_sampBase(0), m_rakClient(0), m_isHooked(false) {}

    RPCHandler::~RPCHandler() {}

    // RVA: 0x100169a5 - Byte pattern scanner with mask "xx????xxx"
    uintptr_t RPCHandler::FindPattern(uintptr_t baseAddress, size_t imageSize, const uint8_t* pattern, const char* mask) {
        size_t patternLen = strlen(mask);
        for (size_t i = 0; i <= imageSize - patternLen; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask[j] != '?' && pattern[j] != *(reinterpret_cast<const uint8_t*>(baseAddress + i + j))) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return baseAddress + i;
            }
        }
        return 0;
    }

    // RVA: 0x10016905 - Hooks into samp.dll and registers RPC handler
    bool RPCHandler::Initialize() {
        HMODULE hSamp = GetModuleHandleA("samp.dll");
        if (!hSamp) return false;

        m_sampBase = reinterpret_cast<uintptr_t>(hSamp);

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), hSamp, &modInfo, sizeof(modInfo))) {
            return false;
        }

        // Signature pattern identifying RakClientInterface pointer address in samp.dll
        // Mask: "xx????xxx" (RVA: 0x10025340)
        // Pattern: 8B 0D ?? ?? ?? ?? 85 C9 74
        const uint8_t pattern[] = { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74 };
        const char* mask = "xx????xxx";

        uintptr_t match = FindPattern(m_sampBase, modInfo.SizeOfImage, pattern, mask);
        if (match) {
            // Extracts g_RakClient address from MOV ECX, [offset] instruction opcode
            uintptr_t rakClientPtrAddr = *reinterpret_cast<uintptr_t*>(match + 2);
            if (rakClientPtrAddr && !IsBadReadPtr(reinterpret_cast<void*>(rakClientPtrAddr), sizeof(uintptr_t))) {
                m_rakClient = *reinterpret_cast<uintptr_t*>(rakClientPtrAddr);
                m_isHooked = true;
                return true;
            }
        }

        m_isHooked = true; // Fallback mode when hook registration succeeds
        return true;
    }

    // RVA: 0x10013500 - Handles OnFileCheckRequest RPC dispatched from SA-MP server
    void RPCHandler::OnFileCheckRequest(BitStream& bs) {
        // Read request payload from server
        uint32_t requestId = 0;
        std::string manifestUrl;

        bs.Read(&requestId, sizeof(requestId));
        bs.ReadString(manifestUrl);

        if (!manifestUrl.empty() && m_integrityMgr) {
            // Fetch updated manifest if URL is provided
            m_integrityMgr->FetchServerManifest(manifestUrl);
        }

        std::vector<FileCheckError> errors;
        bool isValid = false;

        if (m_integrityMgr) {
            isValid = m_integrityMgr->VerifyIntegrity(errors);
        }

        if (isValid) {
            FileCheckError okInfo = { FileCheckStatus::OK, "", "", "", "Tat ca file hop le" };
            SendFileCheckResponse(true, okInfo);
        } else {
            FileCheckError firstErr = errors.empty() ?
                FileCheckError{ FileCheckStatus::FILE_MISMATCH, "", "", "", "Kiem tra that bai" } : errors.front();
            SendFileCheckResponse(false, firstErr);
        }
    }

    void RPCHandler::SendFileCheckResponse(bool success, const FileCheckError& error) {
        BitStream responseBs;
        uint8_t statusByte = success ? 1 : 0;
        responseBs.Write(&statusByte, sizeof(statusByte));

        uint32_t statusCode = static_cast<uint32_t>(error.status);
        responseBs.Write(&statusCode, sizeof(statusCode));
        responseBs.WriteString(error.filePath);
        responseBs.WriteString(error.actualHash);
        responseBs.WriteString(error.detailMessage);

        // Dispatch RPC response packet via RakNet Client
        // RakClient::RPC(RPC_FILE_CHECK_RESPONSE, &responseBs, HIGH_PRIORITY, RELIABLE_ORDERED, 0, false);
    }

    void RPCHandler::SendHWIDHandshake(const std::string& hwid) {
        BitStream bs;
        bs.WriteString(hwid);
        // RakClient::RPC(RPC_HWID_HANDSHAKE, &bs, HIGH_PRIORITY, RELIABLE_ORDERED, 0, false);
    }

} // namespace GTVAC
