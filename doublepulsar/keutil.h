#ifndef KE_UTIL_H
#define KE_UTIL_H
#pragma warning(disable: 4214 4201)
//
// PAGE_SIZE_KERNEL :
//  Size of the kernel memory page. Always 0x1000
//  as the windows kernel doesn't change :)
//
#define PAGE_SIZE_KERNEL     0x1000
#define IMAGE_DOS_SIGNATURE  0x5A4D

//
//  KIDTENTRY   = x86 Kernel Interruptor Descriptor Table Entry
//  KIDTENTRY64 = x64 Kernel Interruptor Descriptor Table Entry
//
typedef struct _KIDTENTRY {
	unsigned short Offset;
	unsigned short Selector;
	unsigned short Access;
	unsigned short ExtendedOffset;
} KIDTENTRY, * PKIDTENTRY;


// x64 KIDTENTRY64
typedef union _KIDTENTRY64
{
	union
	{
		struct
		{
			unsigned short OffsetLow;
			unsigned short Selector;
			struct
			{
				unsigned short IstIndex : 3; 
				unsigned short Reserved0 : 5;
				unsigned short Type : 5; 
				unsigned short Dpl : 2; 
				unsigned short Present : 1; 
			};
			unsigned short OffsetMiddle;
			unsigned long OffsetHigh;
			unsigned long Reserved1;
		};
		unsigned __int64 Alignment;
	};
} KIDTENTRY64, * PKIDTENTRY64;

typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


//
// KeGetKpcr():
//  Acquires the process control routine address
//  using fs/gs registers (__readgsqword/__readfsdword)
//  and FIELD_OFFSET macros.
//
PKPCR KeGetKpcr(VOID);

//
// KeGetIDTEntry():
//  Acquires the first entry of Interrupt Descriptor Table
//  and returns it.
//
PVOID64 KeGetIDTEntry(PKPCR KpcrBase);

//
// KeGetPeExport64():
//	Parses the PE Export Directory of a driver.
//
PVOID KeGetPeExport64(PVOID ImageBaseAddress, PCHAR FunctionName);

//
// KeGetDriverBase():
//	Acquires the Driver Base Address using 
//	ZwQuerySystemInformation, just as the 
//	originaly DoublePulsar did.
//
PVOID64 KeGetDriverBase(PSYSTEM_MODULE_INFORMATION pModuleInfo, PCHAR DriverName);

//
// KeGetDriverSection64():
//	Acquires the section from the start of the 
//	section header, given the name.
//
PVOID64 KeGetDriverSection64(PVOID DriverBase, PCHAR SectionName);
#endif