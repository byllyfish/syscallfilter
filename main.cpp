// Copyright (c) 2016 William W. Fisher (at gmail dot com)
// This file is distributed under the MIT License.

#include <sys/syscall.h>
#include <unistd.h>
#include <iostream>
#include "syscallfilter.h"

enum ReadPerm {
  kAllowRead,
  kDenyRead,
  kKillRead,
};

int main(int argc, char **argv) {
  ReadPerm readPerm = kKillRead;

  if (argc >= 2) {
    std::string arg{argv[1]};
    if (arg == "allow_read") {
      readPerm = kAllowRead;
    } else if (arg == "deny_read") {
      readPerm = kDenyRead;
    } else {
      std::cerr << "Argument must be 'allow_read' or 'deny_read'\n";
      return 1;
    }
  }

  SyscallFilter filter;
  filter.allow(SYS_exit_group);
  filter.allow(SYS_write);
  filter.allow(SYS_fstat);
  filter.allow(SYS_mmap);

  if (readPerm == kAllowRead) {
    filter.allow(SYS_read);
  } else if (readPerm == kDenyRead) {
    filter.deny(SYS_read);
  }

  auto err = filter.install();
  if (err) {
    std::cerr << "Filter returned " << err.message() << '\n';
    return 1;
  }

  std::cout << "SyscallFilter:\n";
  std::cout << filter.toString() << '\n';

  std::cout << "Press any letter key to continue...";
  char buf = 0;
  if (read(0, &buf, 1) < 0) {
    int err = errno;
    std::cerr << "SYS_read errno=" << err << '\n';
    return err;
  }

  return 0;
}
