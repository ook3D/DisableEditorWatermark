#include "FiveMWatermark.h"

#include <Windows.h>
#include <string>
#include <string_view>

namespace
{
	using DrawTextFn = void(*)(void* self, void* text, void* rect, void* color, float fontSize, float fontScale, void* fontRef);

	DrawTextFn g_originalDrawText = nullptr;

	const wchar_t* GetWStringCStr(void* text)
	{
		if (!text)
		{
			return L"";
		}

		return reinterpret_cast<const std::wstring*>(text)->c_str();
	}

	bool IsFiveMWatermark(const wchar_t* text)
	{
		if (!text || !text[0])
		{
			return false;
		}

		std::wstring_view view(text);

		if (view.find(L"packs loaded") != std::wstring_view::npos)
		{
			return true;
		}

		if (view.rfind(L"Ver.", 0) == 0)
		{
			return true;
		}

		const bool isBrand =
			view.find(L"FiveM") != std::wstring_view::npos ||
			view.find(L"RedM") != std::wstring_view::npos ||
			view.find(L"LibertyM") != std::wstring_view::npos;

		return isBrand && view.find(L"(b") != std::wstring_view::npos;
	}

	void DrawTextHook(void* self, void* text, void* rect, void* color, float fontSize, float fontScale, void* fontRef)
	{
		if (IsFiveMWatermark(GetWStringCStr(text)))
		{
			return;
		}

		g_originalDrawText(self, text, rect, color, fontSize, fontScale, fontRef);
	}

	bool BlankUnicodeString(HMODULE module, const wchar_t* needle)
	{
		const size_t needleLen = wcslen(needle);
		if (!module || needleLen == 0)
		{
			return false;
		}

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}

		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
		{
			return false;
		}

		const size_t needleBytes = needleLen * sizeof(wchar_t);
		auto section = IMAGE_FIRST_SECTION(nt);
		bool patched = false;

		for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			const bool dataSection =
				(section->Characteristics & IMAGE_SCN_MEM_READ) != 0 &&
				(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;

			if (!dataSection || section->VirtualAddress == 0 || section->Misc.VirtualSize < needleBytes)
			{
				continue;
			}

			auto* start = reinterpret_cast<uint8_t*>(module) + section->VirtualAddress;
			const size_t size = section->Misc.VirtualSize;

			for (size_t offset = 0; offset + needleBytes <= size; offset += sizeof(wchar_t))
			{
				auto* candidate = reinterpret_cast<wchar_t*>(start + offset);
				if (wmemcmp(candidate, needle, needleLen) != 0)
				{
					continue;
				}

				if (needleLen >= 5 && wmemcmp(needle, L"FiveM", 5) == 0 &&
					offset + 18 <= size && wmemcmp(candidate, L"FiveM.app", 9) == 0)
				{
					continue;
				}

				DWORD oldProtect = 0;
				if (!VirtualProtect(candidate, needleBytes, PAGE_READWRITE, &oldProtect))
				{
					continue;
				}

				wmemset(candidate, L'\0', needleLen);
				VirtualProtect(candidate, needleBytes, oldProtect, &oldProtect);
				patched = true;
			}
		}

		return patched;
	}

	void BlankBrandingStrings(HMODULE fontRenderer, HMODULE modLoader)
	{
		static const wchar_t* fontRendererStrings[] = {
			L"Ver. %d%s",
			L" (b%d)",
			L" [e%d]",
			L" (SDK)",
			L" (Canary)",
			L" (Beta)",
			L"FiveM",
			L"\xD83C\xDF19",
			L"\xD83C\xDF42",
			L"\xD83C\xDF50",
			L"\xD83E\xDD59",
		};

		if (fontRenderer)
		{
			for (const wchar_t* needle : fontRendererStrings)
			{
				BlankUnicodeString(fontRenderer, needle);
			}
		}

		if (modLoader)
		{
			BlankUnicodeString(modLoader, L"%d mod packs loaded");
		}
	}

	bool HookDrawTextVtable(HMODULE fontRenderer)
	{
		FARPROC proc = GetProcAddress(fontRenderer, "?TheFonts@@3PEAVFontRenderer@@EA");
		if (!proc)
		{
			return false;
		}

		void* fonts = *reinterpret_cast<void**>(proc);
		if (!fonts)
		{
			return false;
		}

		void** vtable = *reinterpret_cast<void***>(fonts);
		if (!vtable || !vtable[1] || vtable[1] == reinterpret_cast<void*>(&DrawTextHook))
		{
			return false;
		}

		DWORD oldProtect = 0;
		if (!VirtualProtect(&vtable[1], sizeof(void*), PAGE_READWRITE, &oldProtect))
		{
			return false;
		}

		g_originalDrawText = reinterpret_cast<DrawTextFn>(vtable[1]);
		vtable[1] = reinterpret_cast<void*>(&DrawTextHook);
		VirtualProtect(&vtable[1], sizeof(void*), oldProtect, &oldProtect);
		return true;
	}

	bool TryInstall()
	{
		HMODULE fontRenderer = GetModuleHandleW(L"font-renderer.dll");
		if (!fontRenderer)
		{
			return false;
		}

		HMODULE modLoader = GetModuleHandleW(L"citizen-mod-loader-five.dll");
		BlankBrandingStrings(fontRenderer, modLoader);
		HookDrawTextVtable(fontRenderer);
		return true;
	}

	DWORD WINAPI FiveMWatermarkThread(LPVOID)
	{
		constexpr DWORD pollMs = 200;
		constexpr DWORD timeoutMs = 120000;

		for (DWORD waited = 0; waited < timeoutMs; waited += pollMs)
		{
			if (TryInstall())
			{
				return 0;
			}

			Sleep(pollMs);
		}

		return 0;
	}
}

void StartFiveMWatermarkDisable()
{
	HANDLE thread = CreateThread(nullptr, 0, FiveMWatermarkThread, nullptr, 0, nullptr);
	if (thread)
	{
		CloseHandle(thread);
	}
}
