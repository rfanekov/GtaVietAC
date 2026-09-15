#include <windows.h>
#include "../include/ACCore.h"

// Main entry point of the ASI Plugin (DllMain)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        // Start all Anti-Cheat services
        GTVAC::ACCore::GetInstance().Initialize(hinstDLL);
        break;

    case DLL_PROCESS_DETACH:
        GTVAC::ACCore::GetInstance().Shutdown();
        break;
    }
    return TRUE;
}
