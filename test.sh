#!/bin/bash

# Run tests for the syscallfilter program.
# 
# Usage:    `test.sh`

set -e
set -u

# Test 1: Running `syscallfilter` with no arguments should abort with an 
# ??? error because the `read` syscall isn't mentioned in the ACL.

echo "Test 1: Run `syscallfilter`"
if ./syscallfilter < /dev/null || [ "$?" != 10 ]; then
  echo "Test 1 Failed! Exit code is $?"
  exit 1
fi

# Test 2: Running `syscallfilter` with the `allow_read` argument should
# run cleanly with no error.

echo "Test 2: Run `syscallfilter allow_read`"
if ! ./syscallfilter < /dev/null; then
  echo "Test 2 Failed! Exit code is $?"
fi

# Test 3: Running `syscallfilter` with the `deny_read` argument should exit
# with a ??? error because the `read` syscall returns an error, but still
# allowed to continue.

echo "Test 3: Run `syscallfilter deny_read`"
if ./syscallfilter < /dev/null || [ "$?" != 10 ]; then
  echo "Test 3 Failed! Exit code is $?"
  exit 1
fi

exit 0
