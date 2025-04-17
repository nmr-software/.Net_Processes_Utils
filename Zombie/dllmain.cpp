#include "framework.h"
#include <iostream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
		auto hCurrThread = GetCurrentThread();
        if (hCurrThread != NULL) {
            std::cerr << "Zombie suspend on DLL_PROCESS_DETACH" << std::endl;
			std::flush(std::cerr);
			SuspendThread(hCurrThread);
		    CloseHandle(hCurrThread);
        }
    }
    return TRUE;
}

