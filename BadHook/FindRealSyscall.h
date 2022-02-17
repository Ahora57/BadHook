#pragma once
#include "Struct.h" 
#include <iostream>

namespace BrutSyscall
{

	unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
	};
	

	/*
	Add check on NtSuspendProcess and NtTerminateProcess for present kill process and other NTAPI.
	For some NTAPI you can don't do it.
	Like:NtQueryInformationProcess (syscallNumber in my system = 0x19  and syscallNumber NtTerminateProcess = 0x2C)
	but for NtSetInformationObject( syscallNumber = 0x5C) process call NtTerminateProcess,before call NtSetInformationObject and process wiil be die 
	*/
	short GetOrigSycallQueryInformationProcess()
	{
		uint64_t badSyscallNumber = NULL;
		DWORD  DebugFlag = NULL;
		DWORD64  DebugFlagBad = NULL;
		DWORD64  DebugObject = NULL;

		auto nt_status = STATUS_UNSUCCESSFUL;
		auto origSyscall = NULL;
		auto addressShellCode = (t_NtQueryInformationProcess)VirtualAlloc(0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//mem check and you can delete for NtQueryInformationProcess or NtSetInformationThread
		badSyscallNumber = (uint64_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");
#ifdef _WIN64
		badSyscallNumber = *(short*)(badSyscallNumber + 4);
#else 
		badSyscallNumber = *(short*)(badSyscallNumber + 1);
#endif 
		for (size_t i = 0; i < 0x13337; i++)
		{
			memcpy(&shellSysCall64[1], &i, 2); //set syscall
			memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode

			/*
			case ProcessDebugFlags :
			if (ProcessInformationLength != sizeof (ULONG))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			 }
			*/
			// value = DWORD64 and should return  STATUS_INFO_LENGTH_MISMATCH

			if (badSyscallNumber != i) // syscallNumber != syscallNumberNtTerminateProcess
			{

 				nt_status = addressShellCode(NtCurrentProcess, ProcessDebugPort, &DebugFlagBad, sizeof(DebugFlag), 0);
 
				if (nt_status == STATUS_INFO_LENGTH_MISMATCH)
				{
					//send with  corrent size value
 
					nt_status = addressShellCode(NtCurrentProcess, ProcessDebugFlags, &DebugFlag, sizeof(DebugFlag), 0);

 
					if (NT_SUCCESS(nt_status))
					{
						//Check 2
 
						nt_status = addressShellCode(NtCurrentProcess, ProcessDebugObjectHandle, &DebugObject, sizeof(DebugObject), 0);

						if (nt_status == STATUS_PORT_NOT_SET ||//if debugger don't use or syscall hook NTSTATUS in UM or hook in KM 
							nt_status == STATUS_SUCCESS //Debugger detect
							)
						{
							origSyscall = i;
							break;
						}

					}

				}
			}
		}

		VirtualFree((PVOID)addressShellCode, 0, MEM_RELEASE);
		return origSyscall;
	}

}