#include "pch.h"
#include "il2cpp-init.hpp"

#include "config.hpp"
#include "hook.hpp"
#include "util.hpp"

DWORD __stdcall Thread(LPVOID p)
{
	config::Load();
	util::Log("Config loaded.");
	util::DisableLogReport();
	util::Log("Disabled log report.");

	while (GetModuleHandle("UserAssembly.dll") == nullptr)
	{
		util::Log("UserAssembly.dll isn't loaded, waiting for a sec.");
		Sleep(1000);
	}
	util::Log("Waiting 5 sec for game initialize.");
	Sleep(config::GetWaitTime());
	util::DisableVMProtect();
	util::Log("Disabled vm protect.");

	init_il2cpp();
	util::Log("Loaded il2cpp functions.");

	hook::Load();
	util::Log("Loaded hooks.");
	return 0;
}

DWORD __stdcall DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
	if (hInstance)
		DisableThreadLibraryCalls(hInstance);

	if (fdwReason == DLL_PROCESS_ATTACH)
		if (HANDLE hThread = CreateThread(NULL, 0, Thread, hInstance, 0, NULL))
			CloseHandle(hThread);
	return TRUE;
}
