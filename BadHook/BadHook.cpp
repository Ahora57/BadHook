
#include "FindRealSyscall.h"


int main()
{
    std::cout << "Syscall number NtQueryInformationProcess ->\t 0x" << std::hex << brut_syscall::get_query_process_info_syscall() << '\n';
    std::cout << "Syscall number NtSetInformationThread ->\t 0x" << std::hex << brut_syscall::get_set_thread_info_syscall() << '\n';
    std::cout << "Syscall number NtSetInformationProcess ->\t 0x" << std::hex << brut_syscall::get_set_process_info_syscall() << '\n';

    std::cin.get();
}

