#include "Hooking.h"
#include "FiveMWatermark.h"

static void DisableEditorWatermark()
{
	auto pattern = hook::pattern("48 83 EC ? 8B 0D ? ? ? ? 65 48 8B 04 25 ? ? ? ? BA ? ? ? ? 48 8B 04 C8 8B 0C 02 D1 E9 F6 C1 ? 74 ? 83 3D");
	if (pattern.size() != 1)
	{
		return;
	}

	uint8_t* renderWatermark = pattern.get_first<uint8_t>();
	DWORD oldProtect;
	VirtualProtect(renderWatermark, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	*renderWatermark = 0xC3;
	VirtualProtect(renderWatermark, 1, oldProtect, &oldProtect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		StartFiveMWatermarkDisable();
		DisableEditorWatermark();
	}

	return TRUE;
}
