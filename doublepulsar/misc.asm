.CODE
COMMENT @
	Acquires the pointer value in r8 
	on x64, and returns it to be parsed
@
GetRegR8 PROC
	mov qword ptr rax, qword ptr r8
	ret
GetRegR8 ENDP
END