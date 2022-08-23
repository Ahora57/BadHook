
#include "FindRealSyscall.h"

int main()
{
    std::cout << "Syscall number NtQueryInformationProcess ->\t 0x" << std::hex << brut_syscall::get_query_info_process_syscall() << '\n';
   
    std::cin.get();
}

