
#include <iostream>
#include "syscallfilter.h"


int main() {
    SyscallFilter filter;
    filter.allow(1);
    filter.allow(2);

    auto err = filter.install();
    if (err) {
        std::cerr << "Filter returned " << err << '\n';
    }

    return 0;
}
