#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build the GUI and TShark with an explicit native compiler toolchain.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "$0")/.." && pwd)"
build_dir="${UHR_BUILD_DIR:-$repo_dir/build-uhr}"
if [[ "${1:-}" == --help ]]; then
    echo "Usage: $0 [--install-deps]"
    echo "CC/CXX select compiler executables; defaults: /usr/bin/gcc and /usr/bin/g++."
    echo "UHR_PYTHON defaults to /usr/bin/python3 (must have pytest)."
    echo "UHR_BUILD_DIR, UHR_BUILD_JOBS (2), UHR_BUILD_TYPE (RelWithDebInfo) override build settings."
    exit 0
fi
if [[ "${1:-}" == --install-deps ]]; then
    sudo bash "$repo_dir/tools/rpm-setup.sh" --install-qt6-deps --install-optional -y
    sudo dnf install -y ninja-build python3-pytest
    shift
fi
[[ $# -eq 0 ]] || { echo "Unknown argument: $1" >&2; exit 1; }
resolve_tool() {
    local resolved
    resolved="$(command -v -- "$1")" || { echo "Required executable not found: $1" >&2; return 1; }
    [[ -f "$resolved" && -x "$resolved" ]] || { echo "Expected an executable without arguments: $1" >&2; return 1; }
    printf '%s\n' "$resolved"
}
cc="$(resolve_tool "${CC:-/usr/bin/gcc}")"
cxx="$(resolve_tool "${CXX:-/usr/bin/g++}")"
cc="$(readlink -f -- "$cc")"
cxx="$(readlink -f -- "$cxx")"
python="$(resolve_tool "${UHR_PYTHON:-/usr/bin/python3}")"
# Preserve the Python symlink so an explicitly selected virtualenv still works.
python="$(cd -- "$(dirname -- "$python")" && pwd)/$(basename -- "$python")"
for tool in cmake ninja pkg-config; do
    command -v "$tool" >/dev/null || { echo "Missing $tool; use --install-deps." >&2; exit 1; }
done
"$python" -c 'import pytest' || { echo "Install pytest for $python or set UHR_PYTHON." >&2; exit 1; }
if [[ -f "$build_dir/CMakeCache.txt" ]]; then
    for lang in C CXX; do
        selected="$cc"
        [[ "$lang" != CXX ]] || selected="$cxx"
        cached="$(sed -n "s/^CMAKE_${lang}_COMPILER:[^=]*=//p" "$build_dir/CMakeCache.txt")"
        if [[ -n "$cached" && "$(readlink -f -- "$cached")" != "$selected" ]]; then
            echo "Cached $lang compiler: $cached; requested: $selected" >&2
            echo "Select a fresh UHR_BUILD_DIR when changing compilers." >&2
            exit 1
        fi
        # An equivalent cached spelling avoids a CMake compiler-path reset.
        if [[ -n "$cached" ]]; then
            if [[ "$lang" == C ]]; then cc="$cached"; else cxx="$cached"; fi
        fi
    done
fi
printf 'C compiler: %s\nC++ compiler: %s\nPython: %s\n' "$cc" "$cxx" "$python"
"$cc" --version | sed -n '1p'
"$cxx" --version | sed -n '1p'
cmake --version | sed -n '1p'
cmake -S "$repo_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
    -DPython3_EXECUTABLE="$python" -DCMAKE_BUILD_TYPE="${UHR_BUILD_TYPE:-RelWithDebInfo}" \
    -DBUILD_wireshark=ON -DBUILD_tshark=ON -DBUILD_stratoshark=OFF
cmake --build "$build_dir" --target wireshark tshark --parallel "${UHR_BUILD_JOBS:-2}"
"$python" -m pytest "$repo_dir/test/suite_uhr.py" --program-path="$build_dir/run" \
    --disable-capture --disable-gui -o addopts= -q
printf 'Wireshark: %s/run/wireshark\nTShark: %s/run/tshark\n' "$build_dir" "$build_dir"
