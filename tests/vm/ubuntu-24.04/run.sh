#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
readonly ROOT
readonly FIXTURE_DIRECTORY="$ROOT/tests/vm/ubuntu-24.04"
SCENARIO="${1:-confirm}"
VM_TMP=""
VM_PASSED=0
UPSTREAM_PID=""
readonly FAILURE_LOG_DIRECTORY="$ROOT/.cache/vm"
readonly UPSTREAM_PORT=38080

cleanup() {
  if [[ -n "$UPSTREAM_PID" ]]; then
    kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  if [[ -n "$VM_TMP" && "$VM_TMP" == /tmp/shakerproxy-vm.* && -d "$VM_TMP" ]]; then
    if [[ "$VM_PASSED" != 1 && -f "$VM_TMP/serial.log" ]]; then
      mkdir -p "$FAILURE_LOG_DIRECTORY"
      install -m 0644 "$VM_TMP/serial.log" "$FAILURE_LOG_DIRECTORY/${SCENARIO}-failed-serial.log"
      printf 'preserved failed VM serial log: %s\n' "$FAILURE_LOG_DIRECTORY/${SCENARIO}-failed-serial.log" >&2
    fi
    rm -rf -- "$VM_TMP"
  fi
}
trap cleanup EXIT

[[ "$SCENARIO" == confirm || "$SCENARIO" == timeout || "$SCENARIO" == daemon-kill || "$SCENARIO" == reboot || "$SCENARIO" == host-safety || "$SCENARIO" == dhcp || "$SCENARIO" == capture ]] || { printf 'scenario must be confirm, timeout, daemon-kill, reboot, host-safety, dhcp, or capture\n' >&2; exit 2; }
for command in docker qemu-system-x86_64 qemu-img hdiutil; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing VM dependency: %s\n' "$command" >&2; exit 2; }
done

"$ROOT/packaging/build-deb.sh" 0.1.0-dev.1
BASE_IMAGE="$($FIXTURE_DIRECTORY/download-image.sh)"
DOCKER_DEBS="$($FIXTURE_DIRECTORY/prepare-docker-debs.sh)"
HOST_DEBS="$($FIXTURE_DIRECTORY/prepare-host-debs.sh)"
VM_TMP="$(mktemp -d /tmp/shakerproxy-vm.XXXXXX)"
python3 -m http.server "$UPSTREAM_PORT" --bind 127.0.0.1 --directory "$VM_TMP" >/dev/null 2>&1 &
UPSTREAM_PID=$!
readonly DISK="$VM_TMP/disk.qcow2"
readonly SEED_ISO="$VM_TMP/seed.iso"
readonly TEST_ISO="$VM_TMP/test.iso"
readonly LOG="$VM_TMP/serial.log"

qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK" 12G
hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$SEED_ISO" "$FIXTURE_DIRECTORY/seed"
mkdir -p "$VM_TMP/test-data"
install -m 0644 "$ROOT/dist/shakerproxy-host_0.1.0-dev.1_amd64.deb" "$VM_TMP/test-data/host.deb"
mkdir -p "$VM_TMP/test-data/docker-debs"
install -m 0644 "$DOCKER_DEBS"/*.deb "$VM_TMP/test-data/docker-debs/"
mkdir -p "$VM_TMP/test-data/host-debs"
install -m 0644 "$HOST_DEBS"/*.deb "$VM_TMP/test-data/host-debs/"
install -m 0755 "$FIXTURE_DIRECTORY/acceptance.sh" "$FIXTURE_DIRECTORY/network-transaction.py" "$FIXTURE_DIRECTORY/reboot-verify.py" "$FIXTURE_DIRECTORY/udhcpc-script.sh" "$VM_TMP/test-data/"
install -m 0644 "$FIXTURE_DIRECTORY/reboot-verify.service" "$VM_TMP/test-data/"
printf '%s\n' "$SCENARIO" > "$VM_TMP/test-data/scenario"
hdiutil makehybrid -quiet -iso -joliet -default-volume-name SHAKERPROXY_TEST -o "$TEST_ISO" "$VM_TMP/test-data"

qemu_reboot_option=(-no-reboot)
if [[ "$SCENARIO" == reboot ]]; then
  qemu_reboot_option=()
fi

qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -cpu max \
  -smp 2 \
  -m 3072 \
  -nographic \
  "${qemu_reboot_option[@]}" \
  -drive "if=virtio,file=$DISK,format=qcow2" \
  -drive "file=$SEED_ISO,media=cdrom,readonly=on" \
  -drive "file=$TEST_ISO,media=cdrom,readonly=on" \
  -netdev user,id=wan,net=10.23.0.0/24,dhcpstart=10.23.0.15 \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:34:01 \
  -netdev user,id=lab,net=172.31.250.0/24,restrict=on \
  -device virtio-net-pci,netdev=lab,mac=52:54:00:12:34:02 \
  2>&1 | tee "$LOG" | awk '/SHAKERPROXY_|cloud-init.*(WARNING|ERROR)|shakerproxy-gatewayd|docker|Docker|dpkg|Failed|failure/ { print; fflush() }'

grep -Fq "SHAKERPROXY_VM_PASS scenario=$SCENARIO" "$LOG"
if grep -Fq 'SHAKERPROXY_VM_FAIL' "$LOG"; then
  printf 'VM reported a failure\n' >&2
  exit 1
fi
VM_PASSED=1
printf 'Ubuntu systemd VM acceptance passed: %s\n' "$SCENARIO"
