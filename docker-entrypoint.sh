#!/bin/sh
set -eu

# Earlier releases created /data as 0755. The stable non-root owner can tighten
# an existing named volume during an ordinary container restart, with no host
# command required. Custom volume drivers that reject chmod remain supported;
# the application's writable-state self-check will report any real problem.
chmod 0700 /data 2>/dev/null || true

exec "$@"
