#include "framework.h"
#include <iostream>

bool nmrLibraryUnloading = false;

// This thread will exit before DLL_PROCESS_DETACH when the process starts to terminate.
DWORD WINAPI nmrCanaryThread(LPVOID lpParam) {
	nmrLibraryUnloading = true;
	FreeLibraryAndExitThread((HMODULE)lpParam, 0x4242);
	return -1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	static_assert(sizeof(HMODULE) == sizeof(void*), "HMODULE is not a pointer type");
	static_assert(std::is_pointer_v<HMODULE>, "HMODULE is not a pointer type");

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto handle = CreateThread(NULL, 1, &nmrCanaryThread, hModule, CREATE_SUSPENDED, NULL);
		if (handle == NULL) {
			auto err = GetLastError();
			std::cerr << "nmrCanaryThread creation failed: " << err << std::endl;
		}
		else {
			while (SuspendThread(handle) < 42);
			CloseHandle(handle);
		}
	}
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (!nmrLibraryUnloading) {
			auto hCurrThread = GetCurrentThread();
			std::cerr << "Zombie suspend on DLL_PROCESS_DETACH" << std::endl;
			std::flush(std::cerr);
			SuspendThread(hCurrThread);
			CloseHandle(hCurrThread);
		}
	}
	return TRUE;
}

