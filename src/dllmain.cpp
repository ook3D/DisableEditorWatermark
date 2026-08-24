#include "Hooking.h"
#include "FiveMWatermark.h"

namespace
{
	constexpr const char* kWatermarkRendererPattern =
		"48 83 EC ? 8B 0D ? ? ? ? 65 48 8B 04 25 ? ? ? ? BA ? ? ? ? 48 8B 04 C8 8B 0C 02 D1 E9 F6 C1 ? 74 ? 83 3D";

	void DisableEditorWatermark()
	{
		auto matches = hook::pattern(kWatermarkRendererPattern);
		if (matches.size() != 1)
		{
			return;
		}

		hook::put(matches.get_first<uint8_t>(), static_cast<uint8_t>(0xC3));
	}
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
