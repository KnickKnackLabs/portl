#!/usr/bin/env bash
set -euo pipefail

if [[ ${NEXTEST_TEST_THREADS+x} ]]; then
  if [[ ${NEXTEST_TEST_THREADS} == num-cpus || ${NEXTEST_TEST_THREADS} =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' "${NEXTEST_TEST_THREADS}"
    printf 'nextest threads: using NEXTEST_TEST_THREADS override (%s)\n' "${NEXTEST_TEST_THREADS}" >&2
    exit 0
  fi
  printf 'error: NEXTEST_TEST_THREADS must be a positive integer or num-cpus\n' >&2
  exit 2
fi

is_positive_integer() {
  [[ ${1-} =~ ^[1-9][0-9]*$ ]]
}

is_nonnegative_integer() {
  [[ ${1-} =~ ^(0|[1-9][0-9]*)$ ]]
}

decimal_at_most() {
  local value=${1-} maximum=$2
  is_positive_integer "${value}" || return 1
  ((${#value} < ${#maximum})) && return 0
  ((${#value} == ${#maximum})) || return 1
  [[ ${value} == "${maximum}" || ${value} < ${maximum} ]]
}

nonnegative_decimal_at_most() {
  local value=${1-} maximum=$2
  is_nonnegative_integer "${value}" || return 1
  ((${#value} < ${#maximum})) && return 0
  ((${#value} == ${#maximum})) || return 1
  [[ ${value} == "${maximum}" || ${value} < ${maximum} ]]
}

# This is far above any plausible host CPU count while keeping multiplication
# safely inside Bash's signed integer range.
valid_cpu_count() {
  decimal_at_most "${1-}" 1048576
}

cpu_count=''
if detected=$(getconf _NPROCESSORS_ONLN 2>/dev/null) && valid_cpu_count "${detected}"; then
  cpu_count=${detected}
else
  case $(uname -s 2>/dev/null || true) in
    Linux)
      if detected=$(nproc 2>/dev/null) && valid_cpu_count "${detected}"; then
        cpu_count=${detected}
      fi
      ;;
    Darwin)
      if detected=$(sysctl -n hw.logicalcpu 2>/dev/null) && valid_cpu_count "${detected}"; then
        cpu_count=${detected}
      fi
      ;;
  esac
fi
[[ -n ${cpu_count} ]] || cpu_count=1

# Values above 1 EiB are not plausible host limits and include common cgroup v1
# "unlimited" sentinels near INT64_MAX.
valid_memory_bytes() {
  decimal_at_most "${1-}" 1152921504606846976
}

valid_cgroup_memory_bytes() {
  nonnegative_decimal_at_most "${1-}" 1152921504606846976
}

consider_cgroup_limit() {
  local path=$1 limit
  limit=$(cat "${path}" 2>/dev/null || true)
  if valid_cgroup_memory_bytes "${limit}" && { [[ -z ${memory_bytes} ]] || ((limit < memory_bytes)); }; then
    memory_bytes=${limit}
  fi
}

consider_cgroup_ancestors() {
  local mount_root=$1 relative_path=$2 limit_file=$3 current
  if [[ ${relative_path} == / ]]; then
    current=${mount_root}
  else
    current="${mount_root}${relative_path%/}"
  fi
  while :; do
    consider_cgroup_limit "${current}/${limit_file}"
    [[ ${current} == "${mount_root}" ]] && break
    current=${current%/*}
  done
}

os=$(uname -s 2>/dev/null || true)
memory_bytes=''
if [[ ${os} == Darwin ]]; then
  if detected=$(sysctl -n hw.memsize 2>/dev/null) && valid_memory_bytes "${detected}"; then
    memory_bytes=${detected}
  fi
elif [[ ${os} == Linux ]]; then
  memtotal_kib=''
  while read -r key value _; do
    if [[ ${key} == MemTotal: ]] && decimal_at_most "${value}" 1125899906842624; then
      memtotal_kib=${value}
      break
    fi
  done < <(cat /proc/meminfo 2>/dev/null || true)
  if [[ -n ${memtotal_kib} ]]; then
    memory_bytes=$((memtotal_kib * 1024))
  fi

  cgroup_v2_relative=''
  cgroup_v1_relative=''
  while IFS=: read -r hierarchy controllers relative_path; do
    [[ ${relative_path} == /* ]] || continue
    case "/${relative_path#/}/" in
      */../*) continue ;;
    esac
    if [[ ${hierarchy} == 0 && -z ${controllers} ]]; then
      cgroup_v2_relative=${relative_path}
    elif [[ ,${controllers}, == *,memory,* ]]; then
      cgroup_v1_relative=${relative_path}
    fi
  done < <(cat /proc/self/cgroup 2>/dev/null || true)

  if [[ -n ${cgroup_v2_relative} ]]; then
    consider_cgroup_ancestors /sys/fs/cgroup "${cgroup_v2_relative}" memory.max
  else
    consider_cgroup_limit /sys/fs/cgroup/memory.max
  fi
  if [[ -n ${cgroup_v1_relative} ]]; then
    consider_cgroup_ancestors /sys/fs/cgroup/memory "${cgroup_v1_relative}" memory.limit_in_bytes
  else
    consider_cgroup_limit /sys/fs/cgroup/memory/memory.limit_in_bytes
  fi
fi

selected=$((cpu_count * 2))
((selected > 4)) && selected=4
rationale="2x ${cpu_count} online CPU(s), ceiling 4"
if [[ -n ${memory_bytes} ]]; then
  memory_cap=$((memory_bytes / 2147483648))
  ((memory_cap < 1)) && memory_cap=1
  ((selected > memory_cap)) && selected=${memory_cap}
  rationale+=", memory cap ${memory_cap}"
else
  rationale+=", memory unavailable"
fi
((selected < 1)) && selected=1

printf '%d\n' "${selected}"
printf 'nextest threads: selected %d (%s)\n' "${selected}" "${rationale}" >&2
