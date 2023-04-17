#pragma once

#include "pch.h"
#include "winternl.h"

namespace util
{
	HANDLE _out = NULL, _old_out = NULL;
	HANDLE _err = NULL, _old_err = NULL;
	HANDLE _in = NULL, _old_in = NULL;

	void Log(const char* text)
	{
		//std::cout << "[mhypbase] " << text << std::endl;
		WriteConsoleA(_out, text, static_cast<DWORD>(strlen(text)), nullptr, nullptr);
	}

	void Logf(const char* fmt, ...)
	{
		if (!_out)
        	return;
		char text[1024];

		va_list args;
		va_start(args, fmt);
		vsprintf_s(text, fmt, args);
		va_end(args);

		Log(text);
	}

	std::ofstream fout;

	void Flogf(const char* fmt, ...)
	{
		if (!fout.is_open())
			fout.open("mhypbase.log");

		char text[1024];

		va_list args;
		va_start(args, fmt);
		vsprintf_s(text, fmt, args);
		va_end(args);

		fout << text << std::endl;
		fout.flush();
	}

	HMODULE GetSelfModuleHandle()
	{
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
	}

	std::string GetConfigPath()
	{
		char filename[MAX_PATH] = {};
		GetModuleFileName(GetSelfModuleHandle(), filename, MAX_PATH);
		auto path = std::filesystem::path(filename).parent_path() / "mhypbase.ini";
		return path.string();
	}

	std::string ConvertToString(VOID* ptr)
	{
		auto bytePtr = reinterpret_cast<unsigned char*>(ptr);
		auto lengthPtr = reinterpret_cast<unsigned int*>(bytePtr + 0x10);
		auto charPtr = reinterpret_cast<char16_t*>(bytePtr + 0x14);
		auto size = lengthPtr[0];
		std::u16string u16;
		u16.resize(size);
		memcpy((char*)&u16[0], (char*)charPtr, size * sizeof(char16_t));
		std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter;
		return converter.to_bytes(u16);
	}

	void InitConsole()
	{
		_old_out = GetStdHandle(STD_OUTPUT_HANDLE);
		_old_err = GetStdHandle(STD_ERROR_HANDLE);
		_old_in = GetStdHandle(STD_INPUT_HANDLE);

		::AllocConsole() && ::AttachConsole(GetCurrentProcessId());

		_out = GetStdHandle(STD_OUTPUT_HANDLE);
		_err = GetStdHandle(STD_ERROR_HANDLE);
		_in = GetStdHandle(STD_INPUT_HANDLE);

		SetConsoleMode(_out,
			ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

		SetConsoleMode(_in,
			ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
			ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
	}

	void DisableLogReport()
	{
		char szProcessPath[MAX_PATH]{};
		GetModuleFileNameA(nullptr, szProcessPath, MAX_PATH);

		auto path = std::filesystem::path(szProcessPath);
		auto ProcessName = path.filename().string();
		ProcessName = ProcessName.substr(0, ProcessName.find_last_of('.'));

		auto Astrolabe = path.parent_path() / (ProcessName + "_Data\\Plugins\\Astrolabe.dll");
		auto MiHoYoMTRSDK = path.parent_path() / (ProcessName + "_Data\\Plugins\\MiHoYoMTRSDK.dll");

		// open exclusive access to these two dlls
		// so they cannot be loaded
		HANDLE hFile = CreateFileA(Astrolabe.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		hFile = CreateFileA(MiHoYoMTRSDK.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	// https://github.com/yubie-re/vmp-virtualprotect-bypass/blob/main/src/vp-patch.hpp
	void DisableVMProtect()
	{
		DWORD old = 0;
		auto ntdll = GetModuleHandleA("ntdll.dll");
		bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
		void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
		VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
		*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
		VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
	}

	// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/Utils.cpp
	uintptr_t FindEntry(uintptr_t addr)
	{
		__try
		{
			while (true)
			{
				// walk back until we find function entry
				uint32_t code = *(uint32_t*)addr;
				code &= ~0xFF000000;
				if (_byteswap_ulong(code) == 0x4883EC00) // sub rsp, ??
					return addr;
				addr--;
			}
		}
		__except (1)
		{
		}
		return 0;
	}

	// https://github.com/34736384/RSAPatch/blob/master/RSAPatch/Utils.cpp
	uintptr_t PatternScan(LPCSTR module, LPCSTR pattern)
	{
		static auto pattern_to_byte = [](const char* pattern)
		{
			auto bytes = std::vector<int>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);
			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					if (*current == '?')
						++current;
					bytes.push_back(-1);
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

		auto mod = GetModuleHandle(module);
		if (!mod)
			return 0;

		auto dosHeader = (PIMAGE_DOS_HEADER)mod;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)mod + dosHeader->e_lfanew);
		auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		auto patternBytes = pattern_to_byte(pattern);
		auto scanBytes = reinterpret_cast<std::uint8_t*>(mod);
		auto s = patternBytes.size();
		auto d = patternBytes.data();

		for (auto i = 0ul; i < sizeOfImage - s; ++i)
		{
			bool found = true;
			for (auto j = 0ul; j < s; ++j)
			{
				if (scanBytes[i + j] != d[j] && d[j] != -1)
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				return (uintptr_t)&scanBytes[i];
			}
		}
		return 0;
	}

	void DumpAddress(uint32_t start, long magic_a, long magic_b)
	{
		uintptr_t baseAddress = (uintptr_t)GetModuleHandle("UserAssembly.dll");
		for (uint32_t i = start; ; i++)
		{
			auto klass = il2cpp__vm__MetadataCache__GetTypeInfoFromTypeDefinitionIndex(i);
			// &reinterpret_cast<uintptr_t*>(klass)[?] is a magic for klass->byval_arg
			std::string class_name = il2cpp__vm__Type__GetName(&reinterpret_cast<uintptr_t*>(klass)[magic_a], 0);
			util::Flogf("[%d]\n%s", i, class_name.c_str());
			void* iter = 0;
			while (const LPVOID method = il2cpp__vm__Class__GetMethods(klass, (LPVOID)&iter))
			{
				// &reinterpret_cast<uintptr_t*>(method)[?] is a magic for method->methodPointer
				auto method_address = reinterpret_cast<uintptr_t*>(method)[magic_b];
				if (method_address)
					method_address -= baseAddress;
				std::string method_name = il2cpp__vm__Method__GetNameWithGenericTypes(method);
				util::Flogf("\t0x%08X: %s", method_address, method_name.c_str());
			}
			util::Flogf("");
		}
	}
}
