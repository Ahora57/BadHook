#ifndef SYSCALL_BRUT
#define SYSCALL_BRUT 1

#include "Struct.h" 
#include <iostream>

#pragma comment(linker, "/SECTION:.data,EWR")

//NtUserGetThreadState trigger SEH(if it can't find syscall number)(or just use __try/__except  and e.t.c) ,but it's in  win32u.dll and syscall number > 500,so we have a little problem
#define PRESENT_MAX_NUMBER 0x500 // for safe 

namespace brut_syscall
{
	//Use global value and section have rule for execute(just for no allocate memory)
	uint8_t shell_syscall[] =
	{
		0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscall_number
		0x4C, 0x8B, 0xD1,           // mov r10,rcx
		0x0F, 0x05,                 // syscall
		0xC3                        // ret
	};

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
	auto get_query_process_info_syscall() -> short
	{
		short brut_number = NULL; 
		DWORD  debug_flag = NULL;
		uint64_t  debug_port = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL; 
		
		auto shell_address = (decltype(&NtQueryInformationProcess))shell_syscall;

		for (INT i = NULL; i < PRESENT_MAX_NUMBER; i++)
		{  
			crt_wrapper::memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(shell_address) + 1), &i, 4);//set syscall
			
			//not correct lenght
			nt_status = shell_address(NULL, ProcessDebugFlags, &debug_flag, sizeof(debug_port), reinterpret_cast<PULONG>(1));
			if (
				(nt_status == STATUS_ACCESS_VIOLATION || nt_status == STATUS_DATATYPE_MISALIGNMENT ) && 
				shell_address(NULL, ProcessDebugFlags, &debug_flag, sizeof(debug_port), NULL) == STATUS_INFO_LENGTH_MISMATCH &&
				shell_address(NULL, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL) == STATUS_INVALID_HANDLE &&
				shell_address(NULL, ProcessDebugPort, &debug_port, sizeof(debug_flag), NULL) == STATUS_INFO_LENGTH_MISMATCH &&
				shell_address(NULL, ProcessDebugPort, &debug_port, sizeof(debug_port), NULL) == STATUS_INVALID_HANDLE
				)
			{
				brut_number = i;
				break;
			}
		}
		return brut_number;
	}


	auto get_set_thread_info_syscall() -> short
	{
		short brut_number = NULL;  
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		auto shell_address = (decltype(&NtSetInformationThread))shell_syscall;

		for (INT i = NULL; i < PRESENT_MAX_NUMBER; i++)
		{
			crt_wrapper::memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(shell_address) + 1), &i, 4);//set syscall

			nt_status = shell_address(NULL, ThreadHideFromDebugger, reinterpret_cast<PVOID>(1), sizeof(ULONG));
			
			if (
				(nt_status == STATUS_ACCESS_VIOLATION || nt_status == STATUS_DATATYPE_MISALIGNMENT) && 
				shell_address(NULL, ThreadHideFromDebugger, NULL, sizeof(ULONG)) == STATUS_INFO_LENGTH_MISMATCH &&
				shell_address(NULL, ThreadHideFromDebugger, NULL, NULL) == STATUS_INVALID_HANDLE 
				/*&& NT_SUCCESS(shell_address(NtCurrentThread, ThreadHideFromDebugger, NULL, NULL))*/
				)
			{
				brut_number = i;
				break;
			}
			
		}

		return brut_number;
	}

	auto get_set_process_info_syscall() -> short
	{
		short brut_number = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		auto shell_address = (decltype(&NtSetInformationProcess))shell_syscall;

		for (INT i = NULL; i < PRESENT_MAX_NUMBER; i++)
		{
			crt_wrapper::memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(shell_address) + 1), &i, 4);//set syscall

			nt_status = shell_address(NULL, ProcessDebugPort, reinterpret_cast<PVOID>(1), sizeof(ULONG));
			
			if ( (nt_status == STATUS_ACCESS_VIOLATION || nt_status == STATUS_DATATYPE_MISALIGNMENT) && 
				shell_address(NULL, ProcessDebugPort, NULL, NULL) == STATUS_INVALID_INFO_CLASS &&
				shell_address(NULL, ProcessDebugFlags, NULL, NULL) == STATUS_INFO_LENGTH_MISMATCH
				)
			{
				brut_number = i;
				break;
			}
		}
		return brut_number;
	}
}


#endif // !SYSCALL_BRUT
