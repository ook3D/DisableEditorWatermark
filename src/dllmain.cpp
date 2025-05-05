#include "Hooking.h"

DWORD WINAPI Main()
{
	// WatermarkRenderer::Render
	uint8_t* renderWatermark = hook::get_pattern<uint8_t>("48 83 EC ? 8B 0D ? ? ? ? 65 48 8B 04 25 ? ? ? ? BA ? ? ? ? 48 8B 04 C8 8B 0C 02 D1 E9 F6 C1 ? 74 ? 83 3D");
	DWORD oldProtect;
	VirtualProtect(renderWatermark, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	*renderWatermark = 0xC3; // ret
	VirtualProtect(renderWatermark, 1, oldProtect, &oldProtect);

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