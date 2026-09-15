#include "../include/HWID.h"
#include <windows.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace GTVAC {

    // RVA: 0x10015c00 - Extracts MAC address of the primary network adapter
    std::string HWIDManager::GetMacAddress() {
        ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(malloc(outBufLen));
        if (!pAdapterInfo) return "MAC-UNKNOWN";

        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(malloc(outBufLen));
            if (!pAdapterInfo) return "MAC-UNKNOWN";
        }

        std::string macStr = "MAC-UNKNOWN";
        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                if (pAdapter->Type == MIB_IF_TYPE_ETHERNET && pAdapter->AddressLength == 6) {
                    char buf[32];
                    sprintf_s(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                        pAdapter->Address[0], pAdapter->Address[1],
                        pAdapter->Address[2], pAdapter->Address[3],
                        pAdapter->Address[4], pAdapter->Address[5]);
                    macStr = buf;
                    break;
                }
                pAdapter = pAdapter->Next;
            }
        }

        if (pAdapterInfo) free(pAdapterInfo);
        return macStr;
    }

    // RVA: 0x10015d00 - Retrieves Volume Serial Number of drive C:\
    std::string HWIDManager::GetDiskSerial() {
        DWORD volumeSerial = 0;
        if (GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) {
            char buf[32];
            sprintf_s(buf, "%08X", volumeSerial);
            return std::string(buf);
        }
        return "DISK-UNKNOWN";
    }

    // RVA: 0x10015e00 - Queries Registry for Mainboard / BIOS Model Name
    std::string HWIDManager::GetBiosProductName() {
        HKEY hKey = nullptr;
        // Key path: "HARDWARE\\DESCRIPTION\\System\\BIOS" (0x100252d4)
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char biosBuf[256] = { 0 };
            DWORD bufSize = sizeof(biosBuf);
            DWORD type = REG_SZ;
            // Value name: "SystemProductName" (0x100252f8)
            if (RegQueryValueExA(hKey, "SystemProductName", nullptr, &type, reinterpret_cast<LPBYTE>(biosBuf), &bufSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                if (strlen(biosBuf) > 0) {
                    return std::string(biosBuf);
                }
            }
            RegCloseKey(hKey);
        }
        return "BIOS-UNKNOWN";
    }

    // RVA: 0x10015eca - Concatenates identifiers and generates SHA-256 hash
    std::string HWIDManager::GenerateHWID() {
        std::string mac = GetMacAddress();
        std::string disk = GetDiskSerial();
        std::string bios = GetBiosProductName();

        // Build raw HWID string: "MAC|DISK|BIOS"
        std::string rawData = mac + "|" + disk + "|" + bios;

        // SHA-256 hashing via Windows CryptoAPI (CryptAcquireContext, CryptCreateHash, CryptHashData)
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string hashResult = "";

        if (CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                if (CryptHashData(hHash, reinterpret_cast<const BYTE*>(rawData.data()), static_cast<DWORD>(rawData.size()), 0)) {
                    BYTE hashBuf[32];
                    DWORD hashLen = sizeof(hashBuf);
                    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0)) {
                        std::stringstream ss;
                        for (DWORD i = 0; i < hashLen; ++i) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBuf[i]);
                        }
                        hashResult = ss.str();
                    }
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }

        if (hashResult.empty()) {
            return rawData; // Fallback: return raw string if CryptoAPI fails
        }

        return hashResult;
    }

} // namespace GTVAC
