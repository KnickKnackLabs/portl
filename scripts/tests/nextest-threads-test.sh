#!/usr/bin/env bash
set -euo pipefail
unset NEXTEST_TEST_THREADS

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
selector="${repo_root}/scripts/nextest-threads.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

failures=0

fail() {
  printf 'not ok - %s\n' "$1" >&2
  failures=$((failures + 1))
}

run_case() {
  local name=$1 expected=$2 os=$3 cpus=$4 memtotal=$5 cgroup_v2=$6 cgroup_v1=$7
  local proc_cgroup=${8-fail} nested_cgroup_v2=${9-fail} nested_cgroup_v1=${10-fail}
  local parent_cgroup_v2=${11-fail} parent_cgroup_v1=${12-fail}
  local bindir="${tmpdir}/${name// /-}"
  mkdir -p "${bindir}"

  cat >"${bindir}/getconf" <<'EOF'
#!/usr/bin/env bash
[[ ${1-} == _NPROCESSORS_ONLN && ${STUB_CPUS} != fail ]] || exit 1
printf '%s\n' "${STUB_CPUS}"
EOF
  cat >"${bindir}/uname" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${STUB_OS}"
EOF
  cat >"${bindir}/sysctl" <<'EOF'
#!/usr/bin/env bash
[[ ${STUB_MEMTOTAL} != fail ]] || exit 1
printf '%s\n' "${STUB_MEMTOTAL}"
EOF
  cat >"${bindir}/cat" <<'EOF'
#!/usr/bin/env bash
case ${1-} in
  /proc/meminfo) [[ ${STUB_MEMTOTAL} != fail ]] || exit 1; printf 'MemTotal: %s kB\n' "${STUB_MEMTOTAL}" ;;
  /proc/self/cgroup) [[ ${STUB_PROC_CGROUP} != fail ]] || exit 1; printf '%s\n' "${STUB_PROC_CGROUP}" ;;
  /sys/fs/cgroup/workload/ci/memory.max) [[ ${STUB_NESTED_CGROUP_V2} != fail ]] || exit 1; printf '%s\n' "${STUB_NESTED_CGROUP_V2}" ;;
  /sys/fs/cgroup/workload/memory.max) [[ ${STUB_PARENT_CGROUP_V2} != fail ]] || exit 1; printf '%s\n' "${STUB_PARENT_CGROUP_V2}" ;;
  /sys/fs/cgroup/memory/workload/ci/memory.limit_in_bytes) [[ ${STUB_NESTED_CGROUP_V1} != fail ]] || exit 1; printf '%s\n' "${STUB_NESTED_CGROUP_V1}" ;;
  /sys/fs/cgroup/memory/workload/memory.limit_in_bytes) [[ ${STUB_PARENT_CGROUP_V1} != fail ]] || exit 1; printf '%s\n' "${STUB_PARENT_CGROUP_V1}" ;;
  /sys/fs/cgroup/memory.max) [[ ${STUB_CGROUP_V2} != fail ]] || exit 1; printf '%s\n' "${STUB_CGROUP_V2}" ;;
  /sys/fs/cgroup/memory/memory.limit_in_bytes) [[ ${STUB_CGROUP_V1} != fail ]] || exit 1; printf '%s\n' "${STUB_CGROUP_V1}" ;;
  *) exec /bin/cat "$@" ;;
esac
EOF
  chmod +x "${bindir}"/*

  local actual
  if ! actual=$(STUB_OS="${os}" STUB_CPUS="${cpus}" STUB_MEMTOTAL="${memtotal}" \
    STUB_CGROUP_V2="${cgroup_v2}" STUB_CGROUP_V1="${cgroup_v1}" \
    STUB_PROC_CGROUP="${proc_cgroup}" STUB_NESTED_CGROUP_V2="${nested_cgroup_v2}" \
    STUB_NESTED_CGROUP_V1="${nested_cgroup_v1}" STUB_PARENT_CGROUP_V2="${parent_cgroup_v2}" \
    STUB_PARENT_CGROUP_V1="${parent_cgroup_v1}" \
    PATH="${bindir}:${PATH}" "${selector}" 2>"${bindir}/stderr"); then
    fail "${name}: selector exited nonzero"
  elif [[ ${actual} != "${expected}" ]]; then
    fail "${name}: expected ${expected}, got ${actual}"
  else
    printf 'ok - %s\n' "${name}"
  fi
}

# macOS hw.memsize is bytes; Linux MemTotal is KiB.
run_case 'CPU ceiling on large macOS host' 4 Darwin 32 68719476736 fail fail
run_case '2x CPU on small host' 2 Darwin 1 68719476736 fail fail
run_case 'RAM down-cap' 2 Darwin 8 4294967296 fail fail
run_case 'cgroup limit precedes host RAM' 1 Linux 8 67108864 2147483648 fail
run_case 'zero cgroup limit down-caps to minimum' 1 Linux 8 67108864 0 fail
run_case 'cgroup v1 finite limit precedes host RAM' 1 Linux 8 67108864 fail 2147483648
run_case 'cgroup v1 common unlimited sentinel is ignored' 4 Linux 8 8388608 fail 18446744073709551615
run_case 'cgroup v1 page-aligned unlimited sentinel is ignored' 4 Linux 8 8388608 fail 9223372036854771712
run_case 'lowest finite cgroup limit wins' 1 Linux 8 8388608 6442450944 2147483648
run_case 'nested cgroup v2 limit precedes host and root RAM' 1 Linux 8 8388608 8589934592 fail '0::/workload/ci' 2147483648 fail
run_case 'nested cgroup v1 memory limit precedes host and root RAM' 1 Linux 8 8388608 fail 8589934592 '5:cpu,memory:/workload/ci' fail 2147483648
run_case 'cgroup v2 intermediate ancestor limit is effective' 1 Linux 8 8388608 8589934592 fail '0::/workload/ci' max fail 2147483648 fail
run_case 'cgroup v1 intermediate ancestor limit is effective' 1 Linux 8 8388608 fail 8589934592 '5:memory:/workload/ci' fail 9223372036854771712 fail 2147483648
run_case 'oversized CPU detection falls back safely' 2 Darwin 999999999999999999999999999999 68719476736 fail fail
run_case 'oversized Linux MemTotal is unavailable' 4 Linux 8 999999999999999999999999999999 fail fail
run_case 'missing detection fallback' 2 Unknown fail fail fail fail

if ! override=$(NEXTEST_TEST_THREADS=7 "${selector}" 2>"${tmpdir}/numeric-override.err"); then
  fail 'numeric override exited nonzero'
elif [[ ${override} != 7 ]]; then
  fail "numeric override: expected 7, got ${override}"
else
  printf 'ok - positive numeric override\n'
fi

if ! override=$(NEXTEST_TEST_THREADS=num-cpus "${selector}" 2>"${tmpdir}/num-cpus-override.err"); then
  fail 'num-cpus override exited nonzero'
elif [[ ${override} != num-cpus ]]; then
  fail "num-cpus override: expected num-cpus, got ${override}"
else
  printf 'ok - num-cpus override\n'
fi

if NEXTEST_TEST_THREADS=0 "${selector}" >"${tmpdir}/invalid.out" 2>"${tmpdir}/invalid.err"; then
  fail 'invalid override was accepted'
elif ! grep -qi 'positive integer.*num-cpus' "${tmpdir}/invalid.err"; then
  fail 'invalid override error was unclear'
else
  printf 'ok - invalid override rejected\n'
fi

if ((failures > 0)); then
  printf '%d test(s) failed\n' "${failures}" >&2
  exit 1
fi
