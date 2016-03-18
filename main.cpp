// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#include <sys/syscall.h>
#include <iostream>
#include "syscallfilter.h"

int main() {
  SyscallFilter filter;
  filter.allow(SYS_exit_group);
  filter.allow(SYS_write);
  filter.deny(SYS_read);  // return error
  filter.allow(SYS_fstat);
  filter.allow(SYS_mmap);

  auto err = filter.install();
  if (err) {
    std::cerr << "Filter returned " << err.message() << '\n';
  }

  std::cout << "Filter:\n";
  std::cout << filter.toString();

  int num = 0;
  std::cin >> num;

  return 0;
}
