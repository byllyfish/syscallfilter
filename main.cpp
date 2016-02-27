
#include <iostream>
#include "syscallfilter.h"
#include <sys/syscall.h>


int main() {
    SyscallFilter filter;
    filter.allow(SYS_exit_group);
    filter.allow(SYS_read);
    filter.allow(SYS_write);

    auto err = filter.install();
    if (err) {
        std::cerr << "Filter returned " << err.message() << '\n';
    }

    std::cout << "Filter installed:\n";
    std::cout << filter.toString();

    return 0;
}
