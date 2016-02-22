// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#include "syscallfilter.h"
#include <cstddef>
#include <cassert>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <iostream>
#include <sstream>
#include <iomanip>

const uint32_t kSyscallOffset = offsetof(struct seccomp_data, nr);
const uint32_t kArchOffset = offsetof(struct seccomp_data, arch);

const uint8_t kReturnDeny = 254;
const uint8_t kReturnAllow = 255;
const uint8_t kPass = 0;

#if defined(__i386)
const uint32_t ARCH_NR = AUDIT_ARCH_I386;
#elif defined(__x86_64__)
const uint32_t ARCH_NR = AUDIT_ARCH_X86_64;
#else
# error "Unsupported architecture"
#endif

const uint32_t X32_SYSCALL_BIT = 0x40000000;
const uint32_t SYSCALL_UPPER_LIMIT = (ARCH_NR == AUDIT_ARCH_X86_64) ? X32_SYSCALL_BIT - 1 : 0xffffffff;

#define SAME_OFFSET(struct_a, struct_b, member)  \
    offsetof(struct_a, member) == offsetof(struct_b, member)


SyscallFilter::SyscallFilter() {
    static_assert(sizeof(Filter) == 8, "Unexpected size");
    static_assert(SAME_OFFSET(Filter, sock_filter, code), "Unexpected offset");

    load32_abs(kArchOffset);
    jump_if_k(BPF_JEQ, ARCH_NR, kPass, kReturnDeny);

    load32_abs(kSyscallOffset);
    jump_if_k(BPF_JGT, SYSCALL_UPPER_LIMIT, kReturnDeny, kPass);
}

void SyscallFilter::allow(uint32_t syscall) {
    jump_if_k(BPF_JEQ, syscall, kReturnAllow, kPass);
}

std::error_code SyscallFilter::install(bool testing) {
    if (prog_.size() > 250) {
	return std::make_error_code(std::errc::value_too_large);
    }

    finish(testing);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return {errno, std::generic_category()};
    }

    struct sock_fprog filter = { static_cast<uint16_t>(prog_.size()), reinterpret_cast<sock_filter *>(prog_.data()) };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) != 0) {
        return {errno, std::generic_category()};
    }

    return {};
}

std::string SyscallFilter::toString() const {
    std::ostringstream oss;

    for (int i = 0; i < prog_.size(); ++i) {
        oss << toString(prog_[i]) << '\n';
    }

    return oss.str();
}

void SyscallFilter::finish(bool testing) {
    size_t denyLine = prog_.size();
    size_t allowLine = denyLine + 1;

    assert(allowLine <= 253);

    ret(testing ? SECCOMP_RET_TRACE : SECCOMP_RET_KILL);
    ret(SECCOMP_RET_ALLOW);

    // Update all jump instructions to point to the correct return line.
    for (size_t i = 0; i < prog_.size(); ++i) {
        auto &stmt = prog_[i];
        if (stmt.code & BPF_JMP) {
            if (stmt.jt == kReturnDeny) {
                stmt.jt = denyLine - i - 1;
            } else if (stmt.jt == kReturnAllow) {
                stmt.jt = allowLine - i - 1;
            }
            if (stmt.jf == kReturnDeny) {
                stmt.jf = denyLine - i - 1;
            } else if (stmt.jf == kReturnAllow) {
                stmt.jf = allowLine - i - 1;
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
    prog_.push_back(BPF_JUMP(code, k, jt, jf));
}

void SyscallFilter::ret(uint32_t value) {
    uint16_t code = BPF_RET | BPF_K;
    prog_.push_back(BPF_STMT(code, value));
}

#define PAIR(name)   { BPF_ ## name, #name }
#define PAIR_(name)   { BPF_ ## name, "," #name }

static std::pair<unsigned,const char *> bpf_class[] = {
    PAIR(LD),
    PAIR(LDX),
    PAIR(ST),
    PAIR(STX),
    PAIR(ALU),
    PAIR(JMP),
    PAIR(RET),
    PAIR(MISC)
};

static std::pair<unsigned, const char *> bpf_size[] = {
    PAIR_(W),
    PAIR_(H),
    PAIR_(B)
};

static std::pair<unsigned, const char *> bpf_mode[] = {
    PAIR_(IMM),
    PAIR_(ABS),
    PAIR_(IND),
    PAIR_(MEM),
    PAIR_(LEN),
    PAIR_(MSH)
};

static std::pair<unsigned, const char *> bpf_jmp[] = {
    PAIR_(JA),
    PAIR_(JEQ),
    PAIR_(JGT),
    PAIR_(JGE),
    PAIR_(JSET)
};

static std::pair<unsigned, const char *> bpf_op[] = {
    PAIR_(ADD),
    PAIR_(SUB),
    PAIR_(MUL),
    PAIR_(DIV),
    PAIR_(OR),
    PAIR_(AND),
    PAIR_(LSH),
    PAIR_(RSH),
    PAIR_(NEG),
    PAIR_(MOD),
    PAIR_(XOR)
};

static std::pair<unsigned, const char *> bpf_src[] = {
    PAIR_(K),
    PAIR_(X)
};

static std::pair<unsigned, const char *> bpf_rval[] = {
    PAIR_(K),
    PAIR_(X),
    PAIR_(A)
};

template <size_t N>
static const char *bpf_translate(uint16_t code, const std::pair<unsigned,const char *> (&lookup)[N]) {
    for (const auto &p : lookup) {
        if (code == p.first) 
            return p.second;
    }
    return "?";
}

std::string SyscallFilter::toString(const Filter &filter) {
    std::ostringstream oss;
    oss << std::showbase << std::internal << std::setfill('0');

    uint16_t clss = BPF_CLASS(filter.code);
    oss << bpf_translate(clss, bpf_class);
    if (clss == BPF_LD || clss == BPF_LDX) {
        oss << bpf_translate(BPF_SIZE(filter.code), bpf_size);
        oss << bpf_translate(BPF_MODE(filter.code), bpf_mode);
    } else if (clss == BPF_JMP) {
        oss << bpf_translate(BPF_OP(filter.code), bpf_jmp);
        oss << bpf_translate(BPF_SRC(filter.code), bpf_src);
    } else if (clss == BPF_ALU) {
        oss << bpf_translate(BPF_OP(filter.code), bpf_op);
        oss << bpf_translate(BPF_SRC(filter.code), bpf_src);
    } else if (clss == BPF_RET) {
        oss << bpf_translate(BPF_RVAL(filter.code), bpf_rval);
    }

    oss << " " << std::setw(10) << std::hex << filter.k << std::dec;

    if (clss == BPF_JMP) {
        oss << " ? " << static_cast<unsigned>(filter.jt) << " : " << static_cast<unsigned>(filter.jf);
    }

    return oss.str();
}

