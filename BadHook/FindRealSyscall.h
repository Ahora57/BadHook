#ifndef SYSCALL_BRUT
#define SYSCALL_BRUT 1

#include "Struct.h" 
#include <iostream>

namespace brut_syscall
{
	namespace crt_wrapper
	{
		auto memcpy(PVOID dest, PVOID src, unsigned __int64 count) -> PVOID
		{
			CHAR* char_dest = (CHAR*)dest;
			CHAR* char_src = (CHAR*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > NULL)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (CHAR*)dest + count - 1;
				char_src = (CHAR*)src + count - 1;
				while (count > NULL)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}
	}
	

	/*
	We do some check for get correct number syscall.
	We set don't correct handle,because syscall number can be NtTerminateProcess.
	*/
	auto get_query_info_process_syscall() -> short
	{
		short brut_number = NULL; 
		DWORD  debug_flag = NULL;
		uint64_t  debug_port = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL; 
		
		uint8_t shell_syscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscall_number
			0x4C, 0x8B, 0xD1,           // mov r10,rcx
			0x0F, 0x05,                 // syscall
			0xC3                        // ret
		};

		auto shell_address = (decltype(&NtQueryInformationProcess))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!shell_address)
			return NULL;

		memcpy(reinterpret_cast<PVOID>(shell_address), &shell_syscall, sizeof(shell_syscall));// write shellcode

		for (INT i = NULL; i < 0x13337; i++)
		{  
			memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(shell_address) + 1), &i, 4);//set syscall
			
			//not correct lenght
			nt_status = shell_address(NULL, ProcessDebugFlags, &debug_flag, sizeof(debug_port), NULL);
			if (nt_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				//send with  corrent lenght,but invalid HANDLE
				nt_status = shell_address(NULL, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL);

				if (nt_status == STATUS_INVALID_HANDLE)//By ObReferenceObjectByHandle
				{
					//Check 3 with ProcessDebugPort
					nt_status = shell_address(NULL, ProcessDebugPort, &debug_port, sizeof(debug_flag), NULL);
					if (nt_status == STATUS_INFO_LENGTH_MISMATCH)
					{
						nt_status = shell_address(NtCurrentProcess, ProcessDebugPort, &debug_port, sizeof(debug_port), NULL);
						if (NT_SUCCESS(nt_status))
						{
							brut_number = i;
							break;
						}
					}
				}
			}
		}
		VirtualFree((PVOID)shell_address, NULL, MEM_RELEASE);
		return brut_number;
	}

}
#endif // !SYSCALL_BRUT