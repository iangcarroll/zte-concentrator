#!/bin/sh
# Regenerate the contract files from the real binary, so CI is asserting
# against what zte_icg_agg actually asks for rather than what someone typed.
#
#   ./refresh-contract.sh /path/to/zte_icg_agg
#
# Needs r2. The libc symbol list is subtracted by hand because the ELF does not
# record which library a symbol came from; if this ever drops something real,
# the CI check fails loudly rather than quietly passing.
set -eu
BIN=${1:-blobs/zte_icg_agg}
[ -f "$BIN" ] || { echo "usage: $0 /path/to/zte_icg_agg" >&2; exit 2; }
here=$(dirname "$0")

{
  echo '# Every DT_NEEDED name in zte_icg_agg that needs a file to exist.'
  echo "# libc.so is deliberately absent: musl's loader resolves it to itself"
  echo '# ("libc.so => /lib/ld-musl-aarch64.so.1"), so there is nothing to stub.'
  echo '# Regenerate with ./refresh-contract.sh'
  r2 -q -c il "$BIN" 2>/dev/null | grep -E '^lib' | grep -vx 'libc.so'
} > "$here/etc/expected-libs.txt"
echo "wrote $(grep -cv '^#' "$here/etc/expected-libs.txt") library names"

echo "current imports, for eyeballing against etc/expected-imports.txt:"
r2 -q -c ii "$BIN" 2>/dev/null | awk '$NF ~ /^[a-z_]/ {print $NF}' | sort -u
