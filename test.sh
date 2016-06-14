#!/bin/bash

# Run tests for the syscallfilter program.
# 
# Usage:    `test.sh`

set -u

BAD_SYSTEM_CALL=159
ENOSYS=38

# Test 1: Running `syscallfilter` with no arguments should abort with an 
# ??? error because the `read` syscall isn't mentioned in the ACL.

echo "Test 1: Run 'syscallfilter'"
./syscallfilter 
CODE="$?"
if [ "$CODE" != "$BAD_SYSTEM_CALL" ]; then
  echo "Test 1 Failed! Exit code is $CODE"
  exit 1
fi

# Test 2: Running `syscallfilter` with the `allow_read` argument should
# run cleanly with no error.

echo "Test 2: Run 'syscallfilter allow_read'"
./syscallfilter allow_read < /dev/zero
CODE="$?"
if [ "$CODE" != "0" ]; then
  echo "Test 2 Failed! Exit code is $CODE"
  exit 2
fi

# Test 3: Running `syscallfilter` with the `deny_read` argument should exit
# with a ??? error because the `read` syscall returns an error, but still
# allowed to continue.

echo "Test 3: Run 'syscallfilter deny_read'"
./syscallfilter deny_read
CODE="$?"
if [ "$CODE" != "$ENOSYS" ]; then
  echo "Test 3 Failed! Exit code is $CODE"
  exit 3
fi

# Test 4: Running `syscallfilter` with the `dont_read` argument should exit
# with no error, because `read` isn't used at all.

echo "Test 4: Run 'syscallfilter dont_read'"
./syscallfilter dont_read
CODE="$?"
if [ "$CODE" != "0" ]; then 
  echo "Test 4 Failed! Exit code is $CODE"
  exit 4
fi

exit 0
