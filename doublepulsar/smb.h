#ifndef SMB_H
#define SMB_H
//
// SMB 1.(x)/2.(x) Header
//
#pragma pack(1)
typedef struct _SMB_HEADER
{
	UCHAR    Protocol[4];
	UCHAR    Command;
	NTSTATUS Status;
	UCHAR    Flags;
	USHORT   Flags2;
	USHORT   PIDHigh;
	UCHAR    SecurityFeatures[8];
	USHORT   Reserved;
	USHORT   TID;
	USHORT   PIDLow;
	USHORT   UID;
	USHORT   MID;
} SMB_HEADER, * PSMB_HEADER;

//
// Header for reading oncoming requests
// from client.
//
typedef struct _SMB_TRANS2_PARAM_HEADER
{
	UCHAR  WordCount;
	struct Words
	{
		USHORT TotalParameterCount;
		USHORT TotalDataCount;
		USHORT Reserved1;
		USHORT ParameterCount;
		USHORT ParameterOffset;
		USHORT ParameterDisplacement;
		USHORT DataCount;
		USHORT DataOffset;
		USHORT DataDisplacement;
		UCHAR  SetupCount;
		UCHAR  Reserved2;
		USHORT Setup[1];
	};
} SMB_TRANS2_HDR, * PSMB_TRANS2_HDR;
#endif