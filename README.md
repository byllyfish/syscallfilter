# SycallFilter: seccomp-bpf whitelist

Implements a seccomp-bpf filter that allows only specified system calls.
Once the filter is installed, attempting to call an unspecified system call
will cause the program to terminate.

```c++
SyscallFilter filter;
filter.allow(SYS_open);
filter.allow(SYS_read);
filter.allow(SYS_write);
filter.allow(SYS_close);

std::error_code err = filter.install();
```

## License

This software is licensed under the terms of the *MIT License*.
