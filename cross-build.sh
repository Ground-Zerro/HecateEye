#!/bin/sh
# Cross-compiles hecate-eye for x86_64/mips/mipsel/aarch64 and drops
# static binaries in bin/ for committing to the repo (no release process —
# the checked-in binaries themselves are the distribution mechanism).
# musl throughout (not glibc) for fully static, warning-free binaries;
# mips/mipsel use the soft-float musl toolchains specifically, since
# router firmware userspace (e.g. Entware's mipsel feed) is soft-float and
# some embedded MIPS kernels don't emulate hard-float instructions at all.
#
# Toolchains are looked for in PATH, then under $TOOLCHAIN_PATH (colon-separated
# directories that hold <triple>-cross subdirectories), then under
# $TOOLCHAIN_DIR (default: toolchains/ next to this script). Whatever is still
# missing gets installed there: musl-gcc from the distribution's packages, the
# cross toolchains as prebuilt tarballs downloaded from $MUSL_CC.
#
#   TOOLCHAIN_PATH=/opt/toolchains ./cross-build.sh   reuse toolchains you have
#   NO_INSTALL=1 ./cross-build.sh                     never install anything
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$SCRIPT_DIR/toolchains}"
TOOLCHAIN_PATH="${TOOLCHAIN_PATH:-}"
MUSL_CC="${MUSL_CC:-https://musl.cc}"
NO_INSTALL="${NO_INSTALL:-0}"

SRCS="main.c session.c ppp_mode.c relay.c netif.c wire.c"
CFLAGS="-O2 -Wall -Wextra -std=gnu11 -static -s"
LDFLAGS="-lpthread"

have() { command -v "$1" >/dev/null 2>&1; }

scan_toolchains() {
    for root in $(echo "$TOOLCHAIN_PATH" | tr ':' ' ') "$TOOLCHAIN_DIR"; do
        [ -n "$root" ] || continue
        [ -d "$root" ] || continue
        for bin in "$root"/*/bin; do
            [ -d "$bin" ] && PATH="$bin:$PATH"
        done
    done
    export PATH
}

fetch() {
    if have curl; then curl -fsSL --retry 2 -o "$2" "$1"
    elif have wget; then wget -q -O "$2" "$1"
    else echo "  need curl or wget to download toolchains" >&2; return 1
    fi
}

install_package() {
    pkg="$1"
    if ! have apt-get; then
        echo "  no apt-get here, install '$pkg' yourself" >&2
        return 1
    fi
    echo "  installing package $pkg"
    if [ "$(id -u)" = 0 ]; then apt-get install -y "$pkg" >/dev/null 2>&1
    elif have sudo; then sudo apt-get install -y "$pkg" >/dev/null 2>&1
    else echo "  need root to install '$pkg'" >&2; return 1
    fi
}

install_musl_cross() {
    name="$1"
    have tar || { echo "  need tar to unpack toolchains" >&2; return 1; }
    mkdir -p "$TOOLCHAIN_DIR" || return 1
    tmp="$TOOLCHAIN_DIR/.$name.tgz"
    echo "  downloading $MUSL_CC/$name.tgz into $TOOLCHAIN_DIR"
    fetch "$MUSL_CC/$name.tgz" "$tmp" || { rm -f "$tmp"; return 1; }
    tar -xzf "$tmp" -C "$TOOLCHAIN_DIR" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

ensure_cc() {
    cc="$1"
    source="$2"
    have "$cc" && return 0
    if [ "$NO_INSTALL" != 0 ]; then
        echo "  $cc not found and NO_INSTALL is set" >&2
        return 1
    fi
    case "$source" in
        pkg:*) install_package "${source#pkg:}" || return 1 ;;
        *)     install_musl_cross "$source" || return 1 ;;
    esac
    scan_toolchains
    have "$cc"
}

scan_toolchains
mkdir -p "$BIN_DIR"
fail=0

build() {
    arch="$1"
    cc="$2"
    source="$3"
    out="$BIN_DIR/hecate-eye-$arch"

    echo "==> $arch ($cc)"
    if ! ensure_cc "$cc" "$source"; then
        echo "SKIP $arch: no $cc and could not install it" >&2
        fail=1
        return
    fi

    if ( cd "$SCRIPT_DIR" && "$cc" $CFLAGS -o "$out" $SRCS $LDFLAGS ); then
        echo "OK   $arch -> $out"
    else
        echo "FAIL $arch" >&2
        fail=1
    fi
}

build x86_64  musl-gcc                 pkg:musl-tools
build mips    mips-linux-muslsf-gcc    mips-linux-muslsf-cross
build mipsel  mipsel-linux-muslsf-gcc  mipsel-linux-muslsf-cross
build aarch64 aarch64-linux-musl-gcc   aarch64-linux-musl-cross

echo
echo "--- results ---"
for f in "$BIN_DIR"/hecate-eye-*; do
    [ -e "$f" ] || continue
    file "$f" 2>/dev/null || ls -la "$f"
done

exit "$fail"
