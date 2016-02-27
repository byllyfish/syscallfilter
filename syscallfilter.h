// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#ifndef SYSCALLFILTER_H_
#define SYSCALLFILTER_H_

#include <vector>
#include <system_error>

/// Usage:
/// 
///   SyscallFilter filter;
///   filter.allow(SYS_open);
///   filter.allow(SYS_read);
///   filter.allow(SYS_write);
///   filter.allow(SYS_close);
///   
///   std::error_code err = filter.install();

class SyscallFilter {
public:
    SyscallFilter();

    void allow(uint32_t syscall);

    std::error_code install(bool testing = false);

    std::string toString() const;

private:

    // Filter is the BPF `sock_filter` structure
    struct Filter {
        uint16_t code;
        uint8_t jt;
        uint8_t jf;
        uint32_t k;
    };

    std::vector<Filter> prog_;

    void finish(bool testing);

    void load32_abs(uint32_t offset);
    void jump_if_k(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf);
    void ret(uint32_t value);

    static std::string toString(const Filter &filter);
};


#endif  // SYSCALLFILTER_H_
