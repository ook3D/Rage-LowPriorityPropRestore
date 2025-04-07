#include "Hooking.h"
#include "Hooking.Patterns.h"

DWORD WINAPI Main()
{
	uint8_t* location = hook::get_pattern<uint8_t>("83 3D ? ? ? ? ? 75 ? 8B 05 ? ? ? ? 89 05 ? ? ? ? 89 05", 6);
	hook::put<uint8_t>(location, 3);

	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		Main();
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{ }

	return TRUE;
}