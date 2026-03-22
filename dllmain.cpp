#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
uintptr_t FindPattern(const char* module, const char* pattern)
{
	HMODULE hMod = GetModuleHandleA(module);
	if (!hMod) return 0;
	MODULEINFO info{};
	if (!K32GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info)))
	{
		return 0;
	}

	BYTE* start = (BYTE*)hMod;
	BYTE* end = start + info.SizeOfImage;
	for (BYTE* p = start; p < end; p++)
	{
		const char* pat = pattern;
		BYTE* cur = p;

		while (*pat)
		{
			if (*pat == ' ')
			{
				pat++;
				continue;
			}
			if (*pat == '?')
			{
				pat += (pat[1] == '?') ? 2 : 1;
				cur++;
				continue;
			}
			BYTE byte = (BYTE)strtoul(pat, nullptr, 16);
			if (*cur != byte)
			{
				break;
			}

			pat += 2;
			cur++;
		}

		if (!*pat)
			return (uintptr_t)p;
	}

	return 0;
}
DWORD WINAPI MainThread(LPVOID)
{
	while (!GetModuleHandleA("client.dll"))
	{
		Sleep(100);
	}
	uintptr_t addr = FindPattern("client.dll", "75 07 B0 01 48 83 C4 38");
	if (!addr)
	{
		return 0;
	}
	BYTE* target = (BYTE*)(addr + 3);
	DWORD oldProtect;
	if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		*target = 0;
		VirtualProtect(target, 1, oldProtect, &oldProtect);
	}
	return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
	}
	return TRUE;
}