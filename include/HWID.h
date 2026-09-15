#pragma once
#include <string>

namespace GTVAC {

    class HWIDManager {
    public:
        // Retrieves primary network adapter MAC address via GetAdaptersInfo (RVA: 0x10015c00)
        static std::string GetMacAddress();

        // Retrieves C:\ drive volume serial number via GetVolumeInformationA (RVA: 0x10015d00)
        static std::string GetDiskSerial();

        // Queries BIOS Product Name from Registry HKLM (RVA: 0x10015e00)
        static std::string GetBiosProductName();

        // Combines components and hashes with SHA-256 for a unique hardware identifier (RVA: 0x10015eca)
        static std::string GenerateHWID();
    };

} // namespace GTVAC
