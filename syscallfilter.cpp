// Copyright (c) 2015-2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#include "syscallfilter.h"
#include <cassert>
#include <linux/seccomp.h>

const uint32_t kSyscallOffset = offsetof(struct seccomp_data, nr);
const uint32_t kArchOffset = offsetof(struct seccomp_data, arch);

const uint8_t kReturnDeny = 254;
const uint8_t kReturnAllow = 255;
const uint8_t kPass = 0;

const uint32_t X32_SYSCALL_BIT = 0x40000000;
const uint32_t UPPER_LIMIT = x86_arch ? X32_SYSCALL_BIT - 1 : 0xffffffff;

#define SAME_OFFSET(struct_a, struct_b, member)  \
    offsetof(struct_a, member) == offsetof(struct_b, member)


SyscallFilter::SyscallFilter() {
    static_assert(sizeof(Filter) == 8, "Unexpected size");
    static_assert(SAME_OFFSET(Filter, sock_filter, code), "Unexpected offset");

    load32_abs(kArchOffset);
    jump_if_k(BPF_JEQ, ARCH_NR, kPass, kReturnDeny);

    load32_abs(kSyscallOffset);
    jump_if_k(BPF_JGT, UPPER_LIMIT, kReturnDeny, kPass);
}

void SyscallFilter::allow(uint32_t syscall) {
    jump_if_k(BPF_JEQ, syscall, kReturnAllow, kPass);
}

std::error_code SyscallFilter::install() {
    finish();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return {errno, std::generic_category()};
    }

    struct sock_fprog filter = { prog_.size(), prog_.data() };

    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &filter) != 0) {
        return {errno, std::generic_category()};
    }

    return {};
}

void SyscallFilter::finish() {
    size_t denyLine = prog_.size();
    size_t allowLine = denyLine + 1;

    assert(allowLine <= 253);

    ret(SECCOMP_RET_KILL);
    ret(SECCOMP_RET_ALLOW);

    // Update all jump instructions to point to the correct return line.
    for (size_t i = 0; i < prog_.size(); ++i) {
        auto &stmt = prog_[i];
        if (stmt.code & BPF_JMP) {
            if (stmt.jt == kReturnDeny) {
                stmt.jt = denyLine - i;
            } else if (stmt.jt == kReturnAllow) {
                stmt.jt = allowLine - i;
            }
            if (stmt.jf == kReturnDeny) {
                stmt.jf = denyLine - i;
            } else if (stmt.jf == kReturnAllow) {
                stmt.jf = allowLine - i;
            }
        }
    }
}

void SyscallFilter::load32_abs(uint32_t offset) {
    uint16_t code = BPF_LD | BPF_W | BPF_ABS;
    prog_.push_back(BPF_STMT(code, offset));
}

void SyscallFilter::jump_if_k(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) {
    code |= BPF_JMP | BPF_K;
    prog_.push_back(BPF_JUMP(code, jt, jf, k));
}

void SyscallFilter::ret(uint32_t value) {
    uint16_t code = BPF_RET | BPF_K;
    prog_.push_back(BPF_STMT(code, k));
}

