#include "FiveMWatermark.h"

#include <Windows.h>
#include <cstdint>
#include <cwchar>

namespace
{
	void BlankUnicodeString(HMODULE module, const wchar_t* needle)
	{
		const size_t needleLen = wcslen(needle);
		if (!module || needleLen == 0)
		{
			return;
		}

		auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return;
		}

		auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<std::uint8_t*>(module) + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
		{
			return;
		}

		const size_t needleBytes = needleLen * sizeof(wchar_t);
		auto* section = IMAGE_FIRST_SECTION(nt);

		for (UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			const bool isData =
				(section->Characteristics & IMAGE_SCN_MEM_READ) != 0 &&
				(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;

			if (!isData || section->VirtualAddress == 0 ||
				section->Misc.VirtualSize < needleBytes + sizeof(wchar_t))
			{
				continue;
			}

			auto* start = reinterpret_cast<std::uint8_t*>(module) + section->VirtualAddress;
			const size_t size = section->Misc.VirtualSize;

			for (size_t offset = 0; offset + needleBytes + sizeof(wchar_t) <= size; offset += sizeof(wchar_t))
			{
				auto* candidate = reinterpret_cast<wchar_t*>(start + offset);
				if (wmemcmp(candidate, needle, needleLen) != 0 || candidate[needleLen] != L'\0')
				{
					continue;
				}

				if (wmemcmp(needle, L"FiveM", 5) == 0 &&
					offset + 18 <= size &&
					wmemcmp(candidate, L"FiveM.app", 9) == 0)
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
			}
		}
	}

	void BlankBrandingStrings()
	{
		static const wchar_t* kFontRendererStrings[] = {
			L"Ver. %d%s",
			L" (b%d)",
			L" [e%d]",
			L" (SDK)",
			L" (Canary)",
			L" (Beta)",
			L"FiveM",
			L"RedM",
			L"LibertyM",
			L"\xD83C\xDF19",
			L"\xD83C\xDF42",
			L"\xD83C\xDF50",
			L"\xD83E\xDD59",
		};

		HMODULE fontRenderer = GetModuleHandleW(L"font-renderer.dll");
		if (fontRenderer)
		{
			for (const wchar_t* needle : kFontRendererStrings)
			{
				BlankUnicodeString(fontRenderer, needle);
			}
		}

		HMODULE modLoader = GetModuleHandleW(L"citizen-mod-loader-five.dll");
		if (modLoader)
		{
			BlankUnicodeString(modLoader, L"%d mod packs loaded");
		}
	}

	DWORD WINAPI InstallThread(LPVOID)
	{
		constexpr DWORD kPollMs = 200;
		constexpr DWORD kTimeoutMs = 120000;

		for (DWORD elapsed = 0; elapsed < kTimeoutMs; elapsed += kPollMs)
		{
			if (GetModuleHandleW(L"font-renderer.dll"))
			{
				BlankBrandingStrings();
				return 0;
			}

			Sleep(kPollMs);
		}

		return 0;
	}
}

void StartFiveMWatermarkDisable()
{
	HANDLE thread = CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
	if (thread)
	{
		CloseHandle(thread);
	}
}
