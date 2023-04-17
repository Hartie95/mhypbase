#include "pch.h"
/*#include "util.hpp"


typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);


// https://github.com/yubie-re/vmp-virtualprotect-bypass/blob/main/src/vp-patch.hpp
void util::DisableVMProtect()
{
	DWORD old_protect = 0;
	auto ntdll = GetModuleHandleA("ntdll.dll");
	bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
	BYTE callcode = ((BYTE*)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
	BYTE restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, callcode };
	auto nt_vp = (BYTE*)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	VirtualProtect(nt_vp, sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
	memcpy(nt_vp, restore, sizeof(restore));
	VirtualProtect(nt_vp, sizeof(restore), old_protect, &old_protect);
}
*/