// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#include "syscallfilter.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <cassert>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <sstream>

const uint32_t kSyscallOffset = offsetof(struct seccomp_data, nr);
const uint32_t kArchOffset = offsetof(struct seccomp_data, arch);

// This implementation is limited to 245 syscalls. (To support more, we need
// to add intermediate return instructions.)

const size_t kMaxSyscalls = 245;
const uint8_t kReturnDeny = 253;
const uint8_t kReturnAllow = 254;
const uint8_t kReturnError = 255;
const uint8_t kPass = 0;

#if defined(__i386)
const uint32_t ARCH_NR = AUDIT_ARCH_I386;
#elif defined(__x86_64__)
const uint32_t ARCH_NR = AUDIT_ARCH_X86_64;
#else
#error "Unsupported architecture"
#endif

#define SAME_OFFSET(struct_a, struct_b, member) \
  offsetof(struct_a, member) == offsetof(struct_b, member)

/// \brief Construct empty syscall filter.
///
/// Creates an empty syscall whitelist. Syscalls can be added to the whitelist
/// using the `allow` member function. A syscall that is not in the whitelist
/// will cause the program to terminate.
///
/// If you enable the `trap` option, a disallowed syscall will raise SIGSYS
/// instead.
///
/// \param trap If true, denied syscall causes signal, instead of killing
/// program. Note recommended for production use due to security concerns.
SyscallFilter::SyscallFilter(bool trap) : trap_{trap} {
  static_assert(sizeof(Filter) == sizeof(sock_filter), "Unexpected size");
  static_assert(SAME_OFFSET(Filter, sock_filter, code), "Unexpected offset");
  static_assert(SAME_OFFSET(Filter, sock_filter, jt), "Unexpected offset");
  static_assert(SAME_OFFSET(Filter, sock_filter, jf), "Unexpected offset");
  static_assert(SAME_OFFSET(Filter, sock_filter, k), "Unexpected offset");

  // Verify architecture.
  load32_abs(kArchOffset);
  jump_if_k(BPF_JEQ, ARCH_NR, kPass, kReturnDeny);

  // Load syscall number.
  load32_abs(kSyscallOffset);
}

/// \brief Allow a syscall to execute normally.
///
/// \param syscall syscall number from <sys/syscall.h>
void SyscallFilter::allow(SyscallNumber syscall) {
  // Allow if syscall matches.
  jump_if_k(BPF_JEQ, syscall, kReturnAllow, kPass);
}

/// \brief Deny a syscall by having it return an error.
///
/// For special circumstances only. It's best to leave the syscall out of the
/// whitelist entirely, rather than let it return unimplemented.
///
/// \param syscall syscall number from <sys/syscall.h>
void SyscallFilter::deny(SyscallNumber syscall) {
  // Error if syscall matches.
  jump_if_k(BPF_JEQ, syscall, kReturnError, kPass);
}

/// \brief Install the system call filter.
///
/// Finishes the syscall filter, then attempts to install it.
/// This function will return an error if called more than once.
///
/// \returns error code from prctl/seccomp.
std::error_code SyscallFilter::install() {
  if (installed_) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  if (prog_.size() > kMaxSyscalls) {
    return std::make_error_code(std::errc::value_too_large);
  }

  installed_ = true;
  finish();

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    return {errno, std::generic_category()};
  }

  struct sock_fprog filter = {static_cast<uint16_t>(prog_.size()),
                              reinterpret_cast<sock_filter *>(prog_.data())};

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) != 0) {
    return {errno, std::generic_category()};
  }

  return {};
}

/// \brief Produce textual description of syscall filter.
///
/// \returns syscall filter as a string.
std::string SyscallFilter::toString() const {
  std::ostringstream oss;

  for (unsigned i = 0; i < prog_.size(); ++i) {
    oss << toString(prog_[i]) << '\n';
  }

  return oss.str();
}

/// \brief Finish the syscall filter.
///
/// Write the final part of the syscall filter. Update jt/jf jumps to point to
/// the correct return line.
void SyscallFilter::finish() {
  size_t denyLine = prog_.size();
  size_t allowLine = denyLine + 1;
  size_t errorLine = allowLine + 1;

  assert(denyLine <= kMaxSyscalls);

  ret(trap_ ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL);
  ret(SECCOMP_RET_ALLOW);
  ret(SECCOMP_RET_ERRNO | ENOSYS);

  // Update all jump instructions to point to the correct return line.
  for (size_t i = 0; i < prog_.size(); ++i) {
    auto &stmt = prog_[i];
    if (stmt.code & BPF_JMP) {
      // Translate true jump offset.
      if (stmt.jt == kReturnDeny) {
        stmt.jt = denyLine - i - 1;
      } else if (stmt.jt == kReturnAllow) {
        stmt.jt = allowLine - i - 1;
      } else if (stmt.jt == kReturnError) {
        stmt.jt = errorLine - i - 1;
      }
      // Translate false jump offset.
      if (stmt.jf == kReturnDeny) {
        stmt.jf = denyLine - i - 1;
      } else if (stmt.jf == kReturnAllow) {
        stmt.jf = allowLine - i - 1;
      } else if (stmt.jf == kReturnError) {
        stmt.jf = errorLine - i - 1;
      }
    }
  }
}

/// \brief Append "LD,W,ABS <offset>" instruction to filter.
void SyscallFilter::load32_abs(uint32_t offset) {
  uint16_t code = BPF_LD | BPF_W | BPF_ABS;
  prog_.push_back(BPF_STMT(code, offset));
}

/// \brief Append "JMP,code,K <k> ? <jt> : <jf>" instruction to filter.
void SyscallFilter::jump_if_k(uint16_t code, uint32_t k, uint8_t jt,
                              uint8_t jf) {
  code |= BPF_JMP | BPF_K;
  prog_.push_back(BPF_JUMP(code, k, jt, jf));
}

/// \brief Append "RET <value>" instruction to filter.
void SyscallFilter::ret(uint32_t value) {
  uint16_t code = BPF_RET | BPF_K;
  prog_.push_back(BPF_STMT(code, value));
}

// Helper macros and tables for converting BPF Filter instruction to a string.

#define PAIR(name) \
  { BPF_##name, #name }
#define PAIR_(name) \
  { BPF_##name, "," #name }

static std::pair<unsigned, const char *> bpf_class[] = {
    PAIR(LD),  PAIR(LDX), PAIR(ST),  PAIR(STX),
    PAIR(ALU), PAIR(JMP), PAIR(RET), PAIR(MISC)};

static std::pair<unsigned, const char *> bpf_size[] = {PAIR_(W), PAIR_(H),
                                                       PAIR_(B)};

static std::pair<unsigned, const char *> bpf_mode[] = {
    PAIR_(IMM), PAIR_(ABS), PAIR_(IND), PAIR_(MEM), PAIR_(LEN), PAIR_(MSH)};

static std::pair<unsigned, const char *> bpf_jmp[] = {
    PAIR_(JA), PAIR_(JEQ), PAIR_(JGT), PAIR_(JGE), PAIR_(JSET)};

static std::pair<unsigned, const char *> bpf_op[] = {
    PAIR_(ADD), PAIR_(SUB), PAIR_(MUL), PAIR_(DIV), PAIR_(OR), PAIR_(AND),
    PAIR_(LSH), PAIR_(RSH), PAIR_(NEG)
#if defined(BPF_MOD)
    , PAIR_(MOD)
#endif // defined(BPF_MOD)
#if defined(BPF_XOR)
    , PAIR_(XOR)
#endif // defined(BPF_XOR)
};

static std::pair<unsigned, const char *> bpf_src[] = {PAIR_(K), PAIR_(X)};

static std::pair<unsigned, const char *> bpf_rval[] = {PAIR_(K), PAIR_(X),
                                                       PAIR_(A)};

template <size_t N>
static const char *bpf_translate(
    uint16_t code, const std::pair<unsigned, const char *> (&lookup)[N]) {
  for (const auto &p : lookup) {
    if (code == p.first)
      return p.second;
  }
  return "?";
}

/// \brief Convert filter instruction to a string.
///
/// \param filter instruction
///
/// \returns string representation of filter
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
    oss << " ? " << static_cast<unsigned>(filter.jt) << " : "
        << static_cast<unsigned>(filter.jf);
  }

  return oss.str();
}
