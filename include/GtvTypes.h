#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace GTVAC {

    // Classification of violations detected by the anti-cheat system
    enum class DetectType : uint32_t {
        UNKNOWN = 0,
        PROCESS_BLACKLIST = 1,     // Blacklisted cheat or debugger process detected
        WINDOW_BLACKLIST = 2,      // Window title containing memory manipulation keywords detected
        FILE_INTEGRITY = 3,        // Modified, missing, or unauthorized game file (CLEO/ASI) detected
        MEMORY_HOOK = 4,           // Game API or vtable hook/tampering detected
        DEBUGGER_ATTACHED = 5      // Active debugger detected (PEB BeingDebugged, DR0-DR7, NtGlobalFlag)
    };

    // File check status codes
    enum class FileCheckStatus : uint32_t {
        OK = 0,                    // "Tat ca file hop le" (All files valid)
        FILE_MISMATCH = 1,         // File size or CRC32/SHA-256 hash mismatch
        FILE_MISSING = 2,          // "File missing: %s"
        FILE_DETECTED = 5,         // "Detected: %s" - unauthorized hack/mod file detected
        SERVER_MANIFEST_EMPTY = 6, // "Server manifest chua duoc load" (Server manifest not loaded)
        SNAPSHOT_NOT_TAKEN = 7,    // "Snapshot chua duoc thuc hien" (Snapshot not taken)
        NEW_FILE_AFTER_START = 8   // "New file after start" - new file created after game startup
    };

    // Game process module information
    struct ModuleInfo {
        std::string moduleName;
        uintptr_t baseAddress;
        uint32_t moduleSize;
        std::string sha256Hash;
    };

    // File check error report details
    struct FileCheckError {
        FileCheckStatus status;
        std::string filePath;
        std::string expectedHash;
        std::string actualHash;
        std::string detailMessage;
    };

    // External tool / intrusion detection details
    struct ExternalDetectInfo {
        DetectType type;
        std::string targetName;
        DWORD processId;
        std::string description;
    };

    // Manifest entry structure retrieved from server
    struct ManifestEntry {
        std::string name;          // "name"
        uint64_t size;             // "size"
        uint32_t crc32;            // "crc32"
        std::string sha256;        // "sha256"
    };

    // Simulated RakNet BitStream for SA-MP server RPC communication
    class BitStream {
    private:
        std::vector<uint8_t> m_buffer;
        size_t m_readOffset;

    public:
        BitStream() : m_readOffset(0) {}
        BitStream(const uint8_t* data, size_t length) : m_readOffset(0) {
            if (data && length > 0) {
                m_buffer.assign(data, data + length);
            }
        }

        void Write(const void* data, size_t numBytes) {
            if (!data || numBytes == 0) return;
            const uint8_t* bytePtr = static_cast<const uint8_t*>(data);
            m_buffer.insert(m_buffer.end(), bytePtr, bytePtr + numBytes);
        }

        void WriteString(const std::string& str) {
            uint16_t len = static_cast<uint16_t>(str.length());
            Write(&len, sizeof(len));
            if (len > 0) {
                Write(str.data(), len);
            }
        }

        bool Read(void* outData, size_t numBytes) {
            if (!outData || m_readOffset + numBytes > m_buffer.size()) return false;
            memcpy(outData, m_buffer.data() + m_readOffset, numBytes);
            m_readOffset += numBytes;
            return true;
        }

        bool ReadString(std::string& outStr) {
            uint16_t len = 0;
            if (!Read(&len, sizeof(len))) return false;
            if (m_readOffset + len > m_buffer.size()) return false;
            outStr.assign(reinterpret_cast<const char*>(m_buffer.data() + m_readOffset), len);
            m_readOffset += len;
            return true;
        }

        const uint8_t* GetData() const { return m_buffer.data(); }
        size_t GetNumberOfBytesUsed() const { return m_buffer.size(); }
        void ResetReadPointer() { m_readOffset = 0; }
    };

} // namespace GTVAC
