#pragma once
#include "GtvTypes.h"
#include <vector>
#include <string>
#include <unordered_map>

namespace GTVAC {

    class IntegrityManager {
    public:
        IntegrityManager();
        ~IntegrityManager();

        // Fetches Manifest file from server URL via WinINet HTTPS (RVA: 0x1001229e)
        bool FetchServerManifest(const std::string& manifestUrl);

        // Captures initial baseline snapshot of game root and \cleo directory (RVA: 0x100117a4)
        bool TakeFileSystemSnapshot(const std::string& gameRootPath);

        // Verifies file system integrity against server Manifest (RVA: 0x10013500)
        bool VerifyIntegrity(std::vector<FileCheckError>& outErrors);

        // Scans \cleo directory for unauthorized CLEO (.cs) scripts or ASI/DLL libraries
        bool ScanCleoDirectory(const std::string& cleoPath, std::vector<FileCheckError>& outErrors);

        // Computes CRC32 checksum of a file
        static uint32_t CalculateCRC32(const std::string& filePath);

        // Computes SHA-256 hash string of a file
        static std::string CalculateSHA256(const std::string& filePath);

        bool IsManifestLoaded() const { return !m_manifestEntries.empty(); }
        bool IsSnapshotTaken() const { return m_isSnapshotTaken; }

    private:
        std::string m_gameRoot;
        bool m_isSnapshotTaken;
        std::unordered_map<std::string, ManifestEntry> m_manifestEntries;
        std::unordered_map<std::string, uint64_t> m_initialFileSnapshot;
    };

} // namespace GTVAC
