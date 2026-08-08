#!/usr/bin/env bash
#
# Protector (zqfw) — distro-agnostic install script.
#
# Installs the build prerequisites (clang/LLVM toolchain, libbpf, Rust) for the
# eBPF agentic firewall and builds/installs the `zqfw` binary into
# /usr/local/bin. Works on Debian/Ubuntu, Fedora/RHEL, Arch, Alpine and their
# derivatives. Uses `sudo` when required (it will prompt for a password — a
# normal, unconfigured sudo setup is fine).
#
# Usage:
#   ./scripts/install.sh            # install deps + build + install binary
#   ./scripts/install.sh --no-build # only install the build dependencies
#   ./scripts/install.sh --llm      # build with the optional LLM triage feature
#
set -euo pipefail

NO_BUILD=0
LLM=0
for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=1 ;;
    --llm) LLM=1 ;;
    -h|--help)
      grep '^#' "$0" | sed '1d;s/^# *//'
      exit 0
      ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."

have() { command -v "$1" >/dev/null 2>&1; }
have_sudo() { have sudo; }
need_sudo() {
  if [ "$(id -u)" -ne 0 ]; then
    if have_sudo; then
      echo "sudo -n true"
      if sudo -n true 2>/dev/null; then echo sudo; else echo "sudo"; fi
    else
      echo "You need root to install packages. Run this script as root or install sudo." >&2
      exit 1
    fi
  else
    echo ""
  fi
}

echo "==> Protector install"
echo "    Detected: $(uname -srm)"

# ---------------------------------------------------------------- prerequisites
INSTALL=()
if ! have clang; then INSTALL+=(clang); fi
if ! have llvm-strip && ! have llvm-strip-18 && ! have llvm-strip-17 && ! have llvm-strip-16 && ! have llvm-strip-15; then INSTALL+=(llvm); fi
if ! have cargo; then INSTALL+=(rustc cargo); fi
if ! have bpftool; then INSTALL+=(linux-tools-common linux-tools-generic 2>/dev/null || true); fi

S=need_sudo

if [ ${#INSTALL[@]} -gt 0 ]; then
  echo "==> Installing missing prerequisites: ${INSTALL[*]}"
  if have apt-get; then
    $S apt-get update -y
    $S apt-get install -y build-essential curl clang llvm libelf-dev linux-tools-common
    if ! have cargo; then
      $S apt-get install -y cargo || true
    fi
  elif have dnf; then
    $S dnf install -y gcc gcc-c++ clang llvm elfutils-libelf-devel
    if ! have cargo; then
      $S dnf install -y rust cargo || true
    fi
  elif have pacman; then
    $S pacman -Sy --noconfirm base-devel clang llvm elfutils
    if ! have cargo; then
      $S pacman -Sy --noconfirm rust || true
    fi
  elif have apk; then
    $S apk add --no-cache build-base clang llvm elfutils-dev
    if ! have cargo; then
      $S apk add --no-cache rust || true
    fi
  else
    echo "!! No supported package manager found. Install manually: clang, llvm, libelf-dev, and a Rust toolchain (https://rustup.rs)." >&2
  fi
else
  echo "==> All prerequisites present."
fi

if ! have cargo; then
  echo "==> Installing Rust via rustup (non-interactive)..."
  if ! have curl; then
    echo "!! curl is required to install Rust via rustup; install it first." >&2
    exit 1
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# ------------------------------------------------------------ kernel sanity check
echo "==> Kernel check"
KREL=$(uname -r)
echo "    Running kernel: $KREL"
if [ ! -f /sys/kernel/btf/vmlinux ]; then
  echo "!! CONFIG_DEBUG_INFO_BTF not enabled on this kernel; aya can still work"
  echo "   but may require kernel headers. If probes fail to load, install them:"
  if have apt-get; then
    echo "     $S apt-get install -y linux-headers-$(uname -r)"
  fi
fi

# --------------------------------------------------------------- optional deps
if ! have bpftool && have apt-get; then
  echo "==> Installing bpftool (for diagnostics)"
  $S apt-get install -y linux-tools-common linux-tools-$(uname -r | cut -d- -f1)-generic 2>/dev/null || \
    $S apt-get install -y linux-tools-common 2>/dev/null || true
fi

if [ "$NO_BUILD" -eq 1 ]; then
  echo "==> Prerequisites installed. Skipping build (--no-build)."
  exit 0
fi

# ------------------------------------------------------------------ build+install
echo "==> Building (release)$( [ "$LLM" -eq 1 ] && echo " with LLM triage")"
FEATURES=""
if [ "$LLM" -eq 1 ]; then FEATURES="--features llm"; fi
cargo build --release $FEATURES

echo "==> Installing to /usr/local/bin (requires sudo)"
$S install -m 0755 -o root -g root target/release/zqfw /usr/local/bin/zqfw

echo
echo "Done. Run it:"
echo "    zqfw --mock --block-ip --audit audit.jsonl            # rootless demo"
echo "    sudo zqfw --block-ip --monitor                        # attach to default route iface (auto)"
echo "    sudo kill -USR1 \$(pgrep zqfw)                        # toggle enforce"
