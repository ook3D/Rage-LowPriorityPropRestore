#include <Windows.h>
#include <stdexcept>
#include "Dependencies/Hooking.h"


#include "Dependencies/msdetours/detours.h"
#pragma comment(lib,"Dependencies/msdetours/detours.lib")

//credits to Disquse for research assistance and LMS for some valuable advice 
enum class GameType
{
	Invalid = 0,
	GrandTheftAutoV = 1,
	RedDeadRedemption2 = 2,
};

//address of rage::fwMapData::ms_entityLevelCap default value here is 0 we want to set this to 3
auto loc = hook::get_address<int32_t*>(hook::get_module_pattern<uint8_t>(L"RDR2.exe", "0F 45 C2 89 05 ? ? ? ? 89 05", 0xB));

typedef VOID(*func_t)();
static func_t g_origfunc = NULL;
static VOID hk_func()
{
	// doing this cuz game keeps setting rage::fwMapData::ms_entityLevelCap to 0

	if (!g_origfunc)
	{
		return g_origfunc();
	}

	//this is a horrible hack
	hook::put<int32_t>(loc, 0x03); //rage::fwMapData::ms_entityLevelCap is now 3 ..XD	
}
void modInit(GameType Game)
{
	const uint8_t patch[7]{ 0xBB, 0x03, 0x00, 0x00, 0x00, 0x39, 0x1D };

	switch (Game)
	{

	case GameType::GrandTheftAutoV:

		// credits to cfx for finding this
		// sets rage::fwMapData::ms_entityLevelCap to PRI_OPTIONAL_LOW

		hook::patch(hook::get_pattern<uint8_t>("BB 02 00 00 00 39 1D"), patch); // for GTAV mov ebx, 0x02 to mov ebx, 0x03

		break;


	case GameType::RedDeadRedemption2:

		auto addr = hook::get_call(hook::get_pattern<uint8_t>("0F 47 C7 88 05", 0x9));
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttachEx(reinterpret_cast<PVOID*>(&addr), static_cast<PVOID>(hk_func), reinterpret_cast<PDETOUR_TRAMPOLINE*>(&g_origfunc), NULL, NULL);
		DetourTransactionCommit();

		break;
	}

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	  case DLL_PROCESS_ATTACH:
	  {
		wchar_t modulePath[MAX_PATH]{};
		GetModuleFileNameW(GetModuleHandleW(nullptr), modulePath, static_cast<DWORD>(std::size(modulePath)));

		wchar_t executableName[MAX_PATH]{};
		_wsplitpath_s(modulePath, nullptr, NULL, nullptr, NULL, executableName, std::size(executableName), nullptr, NULL);

		auto gameType = GameType::Invalid;

		if (!_wcsicmp(executableName, L"GTA5"))
			gameType = GameType::GrandTheftAutoV;
		else if (!_wcsicmp(executableName, L"RDR2"))
			gameType = GameType::RedDeadRedemption2;

		try
		{
			if (gameType == GameType::Invalid)
				throw std::runtime_error("Trying to use the mod with an unsupported game. 'GTA5.exe' or 'RDR2.exe' are expected");
			modInit(gameType);

		}
		catch (const std::exception& e)
		{
			wchar_t buffer[2048];

			swprintf_s(buffer,
				L"An exception has occurred on startup: %hs. Failed to initialize the mod. please contact mod author"
				" the Game version which are supproted by scripthook is the minimum requirement.\n\nExecutable path: %ws", e.what(), modulePath);

			MessageBoxW(nullptr, buffer, L"Error", MB_ICONERROR);
		}
	  }

	break;
	}


	return TRUE;
}