// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#ifndef SYSCALLFILTER_H_
#define SYSCALLFILTER_H_

#include <system_error>
#include <vector>

/// \brief Simple API for a seccomp-bpf filter.
///
/// Implements a seccomp-bpf filter that allows only specified system calls.
/// If a system call is not specified, the program will stop.
///
/// If a system call is denied, it returns an error.
///
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
  using SyscallNumber = uint32_t;

  SyscallFilter(bool trap = false);

  void allow(SyscallNumber syscall);
  void deny(SyscallNumber syscall);

  std::error_code install();

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
  bool trap_ = false;
  bool installed_ = false;

  void finish();

  void load32_abs(uint32_t offset);
  void jump_if_k(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf);
  void ret(uint32_t value);

  static std::string toString(const Filter &filter);
};

#endif  // SYSCALLFILTER_H_
