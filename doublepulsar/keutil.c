/*!
 *
 * keutil.c
 *
 * Windows Kernel Utilities for parsing PE's and
 * traversing KPCR(Kernel Process Control Routine)
 * safely.
 *
 * @ authors Mumbai (Austin)
 * @ version 0.1 Alpha
 *
**/
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <string.h>
#pragma warning(disable: 4201 26452 26451 4293 6297)
#include "pe.h"
#include "keutil.h"

//
// Acquires Kernel KPCR
//
PKPCR KeGetKpcr(
	VOID
) {
#if defined(_WIN64)
	return (PKPCR)__readgsqword(FIELD_OFFSET(KPCR, Self));
#else
	return (PKPCR)__readfsdword(FIELD_OFFSET(KPCR, SelfPcr));
#endif
};

//
// Parses Interruptor Descriptor Table
//
PVOID64 KeGetIDTEntry(
	PKPCR KpcrBase
) {
#if defined(_WIN64)
	KIDTENTRY64* IdtBase = (KIDTENTRY64*)KpcrBase->IdtBase;
	PVOID64 pEntry = (PVOID64)
		( 
			((ULONG64)IdtBase->OffsetHigh   << 32) + 
			((ULONG32)IdtBase->OffsetMiddle << 16) +
			IdtBase->OffsetLow
		);
	return pEntry;
#else
	KIDTENTRY* IdtBase = (KIDTENTRY*)KpcrBase->IDT;
	PVOID pEntry = (PVOID)
		(
			((ULONG32)IdtBase->ExtendedOffset << 16) +
			IdtBase->Offset
		);
	return pEntry;
#endif
};

//
// Parses the PE Export Directory (x64)
//
PVOID KeGetPeExport64(
	PVOID ImageBaseAddress, PCHAR FunctionName
) {
	PIMAGE_NT_HEADERS64 pNtsHdr = NULL;
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)ImageBaseAddress;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	
	pNtsHdr = 
		(PIMAGE_NT_HEADERS64)(((ULONG64)pDosHdr) + pDosHdr->e_lfanew);
	pDataDir = 
		&pNtsHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)
		(((ULONG64)ImageBaseAddress) + pDataDir->VirtualAddress);

	for (
		unsigned int i = 0; i < pExportDir->NumberOfNames ; i++ 
	) {
		ULONG * Names = \
			(ULONG *)(((ULONG64)ImageBaseAddress) 
				+ pExportDir->AddressOfNames);
		USHORT * Ordinals = \
			(USHORT*)(((ULONG64)ImageBaseAddress) 
				+ pExportDir->AddressOfNameOrdinals);
		ULONG * Address = \
			(ULONG *)(((ULONG64)ImageBaseAddress) 
				+ pExportDir->AddressOfFunctions);

		PCHAR FunctionNamePtr = (PCHAR)(((ULONG64)ImageBaseAddress) 
			+ Names[i]);

		if (strcmp(FunctionName, FunctionNamePtr) == 0 ) {
			return (PVOID)(((ULONG64)ImageBaseAddress) 
				+ Address[Ordinals[i]]);
		}
	};

	return NULL;
};

//
// Parses SYSTEM_MODULE_ENTRY array until it reaches 
// the destined driver.
//
PVOID64 KeGetDriverBase(
	PSYSTEM_MODULE_INFORMATION pModuleInfo,
	PCHAR DriverName
) {
	PSYSTEM_MODULE_ENTRY pModEntry = pModuleInfo->Module;
	for (
		unsigned int i = 0; i < pModuleInfo->Count; i++
		) {
		PCHAR DriverNameOff = \
			(PCHAR)(pModEntry[i].FullPathName + pModEntry[i].OffsetToFileName);
		if (
			strcmp(DriverNameOff, DriverName) == 0
			) {
			return pModEntry[i].ImageBase;
		};
	};
	return NULL;
};

//
// Parses the section headers of a PE until it 
// locates the section matching the name specified.
//
PVOID64 KeGetDriverSection64(
	PVOID DriverBase, PCHAR SectionName
) {
	PIMAGE_NT_HEADERS64 pNtsHdr = \
		(PIMAGE_NT_HEADERS64)(((ULONG64)DriverBase)
			+ ((PIMAGE_DOS_HEADER)DriverBase)->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr = \
		(PIMAGE_SECTION_HEADER)(((ULONG64)pNtsHdr)
			+ FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
			+ pNtsHdr->FileHeader.SizeOfOptionalHeader);
	for (
		unsigned int i = 0;
		i < pNtsHdr->FileHeader.NumberOfSections;
		i++
	) {
		if (
			strcmp((PCHAR)SectionName, (PCHAR)&pSecHdr[i].Name) == 0
		) {
			return (PVOID64)(((ULONG64)DriverBase) + pSecHdr[i].VirtualAddress);
		}
	};
	return NULL;
};