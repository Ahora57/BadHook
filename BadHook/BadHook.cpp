


#include "FindRealSyscall.h"
int main()
{

    std::cout << "Syscall number NtQueryInformationProcess ->\t 0x" << std::hex << BrutSyscall::GetOrigSycallQueryInformationProcess() << '\n';
   
    std::cin.get();
}

