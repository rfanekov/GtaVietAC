#include "../include/Integrity.h"
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

namespace GTVAC {

    // Standard ISO 3309 CRC32 generator table
    static uint32_t g_crc32Table[256];
    static bool g_crc32Initialized = false;

    static void InitCRC32Table() {
        if (g_crc32Initialized) return;
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; ++j) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
            g_crc32Table[i] = crc;
        }
        g_crc32Initialized = true;
    }

    IntegrityManager::IntegrityManager() : m_isSnapshotTaken(false) {
        InitCRC32Table();
    }

    IntegrityManager::~IntegrityManager() {}

    uint32_t IntegrityManager::CalculateCRC32(const std::string& filePath) {
        InitCRC32Table();
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return 0;

        uint32_t crc = 0xFFFFFFFF;
        char buffer[4096];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            std::streamsize bytesRead = file.gcount();
            for (std::streamsize i = 0; i < bytesRead; ++i) {
                uint8_t byteVal = static_cast<uint8_t>(buffer[i]);
                crc = (crc >> 8) ^ g_crc32Table[(crc ^ byteVal) & 0xFF];
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    std::string IntegrityManager::CalculateSHA256(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return "";

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result = "";

        if (CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                char buffer[4096];
                while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                    std::streamsize bytesRead = file.gcount();
                    CryptHashData(hHash, reinterpret_cast<const BYTE*>(buffer), static_cast<DWORD>(bytesRead), 0);
                }

                BYTE hashBuf[32];
                DWORD hashLen = sizeof(hashBuf);
                if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0)) {
                    std::stringstream ss;
                    for (DWORD i = 0; i < hashLen; ++i) {
                        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBuf[i]);
                    }
                    result = ss.str();
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        return result;
    }

    // RVA: 0x1001229e - Fetches Manifest from server via WinINet HTTPS
    bool IntegrityManager::FetchServerManifest(const std::string& manifestUrl) {
        if (manifestUrl.find("https://") != 0 && manifestUrl.find("http://") != 0) {
            return false;
        }

        HINTERNET hInternet = InternetOpenA("GTAVIET-AC-Agent/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet) return false;

        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (manifestUrl.find("https://") == 0) {
            flags |= INTERNET_FLAG_SECURE;
        }

        HINTERNET hUrl = InternetOpenUrlA(hInternet, manifestUrl.c_str(), nullptr, 0, flags, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return false;
        }

        std::string jsonResponse;
        char buffer[2048];
        DWORD bytesRead = 0;
        while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            jsonResponse.append(buffer, bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        if (jsonResponse.empty()) {
            return false;
        }

        // Parses JSON manifest format: "name", "size", "crc32", "sha256" (RVA: 0x10011dbb, 0x10011e25)
        // Extracts basic descriptor fields
        size_t pos = 0;
        while ((pos = jsonResponse.find("\"name\"", pos)) != std::string::npos) {
            size_t nameStart = jsonResponse.find(":", pos);
            if (nameStart == std::string::npos) break;
            nameStart = jsonResponse.find("\"", nameStart);
            if (nameStart == std::string::npos) break;
            size_t nameEnd = jsonResponse.find("\"", nameStart + 1);
            if (nameEnd == std::string::npos) break;

            std::string fileName = jsonResponse.substr(nameStart + 1, nameEnd - nameStart - 1);

            ManifestEntry entry;
            entry.name = fileName;
            entry.size = 0;
            entry.crc32 = 0;

            // Locate "size" field
            size_t sizePos = jsonResponse.find("\"size\"", nameEnd);
            if (sizePos != std::string::npos && sizePos < jsonResponse.find("\"name\"", nameEnd)) {
                size_t colon = jsonResponse.find(":", sizePos);
                if (colon != std::string::npos) {
                    entry.size = std::strtoull(&jsonResponse[colon + 1], nullptr, 10);
                }
            }

            // Locate "crc32" field
            size_t crcPos = jsonResponse.find("\"crc32\"", nameEnd);
            if (crcPos != std::string::npos && crcPos < jsonResponse.find("\"name\"", nameEnd)) {
                size_t colon = jsonResponse.find(":", crcPos);
                if (colon != std::string::npos) {
                    entry.crc32 = static_cast<uint32_t>(std::strtoul(&jsonResponse[colon + 1], nullptr, 16));
                }
            }

            // Locate "sha256" field
            size_t shaPos = jsonResponse.find("\"sha256\"", nameEnd);
            if (shaPos != std::string::npos && shaPos < jsonResponse.find("\"name\"", nameEnd)) {
                size_t quote1 = jsonResponse.find("\"", jsonResponse.find(":", shaPos));
                if (quote1 != std::string::npos) {
                    size_t quote2 = jsonResponse.find("\"", quote1 + 1);
                    if (quote2 != std::string::npos) {
                        entry.sha256 = jsonResponse.substr(quote1 + 1, quote2 - quote1 - 1);
                    }
                }
            }

            m_manifestEntries[fileName] = entry;
            pos = nameEnd;
        }

        return !m_manifestEntries.empty();
    }

    // RVA: 0x100117a4 - Scans and captures initial baseline file tree snapshot
    bool IntegrityManager::TakeFileSystemSnapshot(const std::string& gameRootPath) {
        m_gameRoot = gameRootPath;
        if (m_gameRoot.empty() || m_gameRoot.back() != '\\') {
            m_gameRoot += "\\";
        }

        m_initialFileSnapshot.clear();

        WIN32_FIND_DATAA findData;
        std::string searchPath = m_gameRoot + "*.*";
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    uint64_t fileSize = (static_cast<uint64_t>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
                    m_initialFileSnapshot[findData.cFileName] = fileSize;
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }

        m_isSnapshotTaken = true;
        return true;
    }

    // RVA: 0x100117a4 - Scans \cleo directory for forbidden cheat scripts
    bool IntegrityManager::ScanCleoDirectory(const std::string& cleoPath, std::vector<FileCheckError>& outErrors) {
        std::string searchPath = cleoPath + "\\*.*";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return true;

        bool hasViolation = false;
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string fname = findData.cFileName;
                std::string ext = "";
                size_t dotPos = fname.find_last_of('.');
                if (dotPos != std::string::npos) {
                    ext = fname.substr(dotPos);
                }

                // Block all script .cs or foreign library files in CLEO directory unless whitelisted in Manifest
                if (m_manifestEntries.find("cleo\\" + fname) == m_manifestEntries.end() &&
                    (ext == ".cs" || ext == ".asi" || ext == ".cleo" || ext == ".dll")) {
                    char msg[256];
                    sprintf_s(msg, "Detected: %s", fname.c_str());
                    outErrors.push_back({
                        FileCheckStatus::FILE_DETECTED,
                        "cleo\\" + fname,
                        "WHITELISTED",
                        "UNAUTHORIZED",
                        std::string(msg)
                    });
                    hasViolation = true;
                }
            }
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
        return !hasViolation;
    }

    // RVA: 0x10013500 - Verifies file system integrity against manifest
    bool IntegrityManager::VerifyIntegrity(std::vector<FileCheckError>& outErrors) {
        // 1. Check if Server Manifest has not been loaded
        if (m_manifestEntries.empty()) {
            outErrors.push_back({
                FileCheckStatus::SERVER_MANIFEST_EMPTY,
                "", "", "",
                "Server manifest chua duoc load"
            });
            return false;
        }

        // 2. Check if baseline snapshot was taken
        if (!m_isSnapshotTaken) {
            outErrors.push_back({
                FileCheckStatus::SNAPSHOT_NOT_TAKEN,
                "", "", "",
                "Snapshot chua duoc thuc hien"
            });
            return false;
        }

        bool allValid = true;

        // 3. Compare each file in Server Manifest against physical disk file
        for (const auto& kv : m_manifestEntries) {
            const std::string& relPath = kv.first;
            const ManifestEntry& entry = kv.second;
            std::string fullPath = m_gameRoot + relPath;

            DWORD attribs = GetFileAttributesA(fullPath.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES) {
                char msg[256];
                sprintf_s(msg, "File missing: %s", relPath.c_str());
                outErrors.push_back({
                    FileCheckStatus::FILE_MISSING,
                    relPath,
                    entry.sha256,
                    "",
                    std::string(msg)
                });
                allValid = false;
                continue;
            }

            // Verify file size
            HANDLE hFile = CreateFileA(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER size;
                if (GetFileSizeEx(hFile, &size)) {
                    if (entry.size > 0 && static_cast<uint64_t>(size.QuadPart) != entry.size) {
                        char msg[256];
                        sprintf_s(msg, "Detected: %s (Size mismatch)", relPath.c_str());
                        outErrors.push_back({
                            FileCheckStatus::FILE_DETECTED,
                            relPath,
                            std::to_string(entry.size),
                            std::to_string(size.QuadPart),
                            std::string(msg)
                        });
                        allValid = false;
                    }
                }
                CloseHandle(hFile);
            }

            // Verify SHA-256 hash
            if (!entry.sha256.empty()) {
                std::string actualHash = CalculateSHA256(fullPath);
                if (!actualHash.empty() && _stricmp(actualHash.c_str(), entry.sha256.c_str()) != 0) {
                    char msg[256];
                    sprintf_s(msg, "Detected: %s (Hash mismatch)", relPath.c_str());
                    outErrors.push_back({
                        FileCheckStatus::FILE_DETECTED,
                        relPath,
                        entry.sha256,
                        actualHash,
                        std::string(msg)
                    });
                    allValid = false;
                }
            }
        }

        // 4. Scan \cleo directory
        ScanCleoDirectory(m_gameRoot + "cleo", outErrors);

        return allValid;
    }

} // namespace GTVAC
