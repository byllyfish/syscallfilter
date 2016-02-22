
#include <iostream>
#include "syscallfilter.h"
#include <sys/syscall.h>


int main() {
    SyscallFilter filter;
    filter.allow(SYS_exit_group);
    //filter.allow(SYS_write);
    filter.allow(SYS_fstat);
    filter.allow(SYS_mmap);

    auto err = filter.install();
    if (err) {
        std::cerr << "Filter returned " << err.message() << '\n';
    }

    std::cout << "Filter:\n";
    std::cout << filter.toString();

    return 0;
}
