#!/usr/bin/env python3
import datetime
import hashlib
import json
import os
import socket
import subprocess
import time

SOCKET = "/run/shakerproxy/gatewayd.sock"
CONTEXT = "/var/lib/shakerproxy-vm-test/reboot.json"
def report(message):
    print(message, flush=True)


def fail(message):
    report(f"SHAKERPROXY_VM_FAIL scenario=reboot detail={message}")
    subprocess.run(["systemctl", "--no-pager", "--full", "status", "shakerproxy-gatewayd.service"], check=False)
    subprocess.run(["journalctl", "--no-pager", "-u", "shakerproxy-gatewayd.service", "-n", "200"], check=False)
    if "unit" in globals():
        subprocess.run(["journalctl", "--no-pager", "-u", unit, "-n", "200"], check=False)
    subprocess.run(["cat", "/var/lib/shakerproxy/gatewayd/state.json"], check=False)
    subprocess.run(["systemctl", "poweroff", "--no-block"], check=False)
    raise SystemExit(1)


def call(method):
    request = {"jsonrpc": "2.0", "id": f"vm-reboot-{time.time_ns()}", "method": method, "params": {}}
    raw = (json.dumps(request, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(8)
        client.connect(SOCKET)
        client.sendall(raw)
        response = b""
        while not response.endswith(b"\n"):
            block = client.recv(65536)
            if not block:
                break
            response += block
    decoded = json.loads(response)
    if decoded.get("error"):
        raise RuntimeError(decoded["error"])
    return decoded["result"]


with open(CONTEXT, encoding="utf-8") as context_file:
    context = json.load(context_file)

boot_id_after = open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
if boot_id_after == context["boot_id_before"]:
    fail("boot ID did not change")

deadline = datetime.datetime.fromisoformat(context["confirm_by"].replace("Z", "+00:00"))
socket_deadline = time.monotonic() + 30
while time.monotonic() < socket_deadline and not os.path.exists(SOCKET):
    time.sleep(0.25)
if not os.path.exists(SOCKET):
    fail("gateway socket did not return after reboot")

try:
    state = call("GetManagedState")
except Exception as error:
    fail(f"gateway state unavailable after reboot: {error}")

staged = state.get("staged_network_plan") or {}
if staged.get("status") != "AWAITING_CONFIRMATION":
    fail(f"active transaction was not recovered before its deadline: {staged}")
if staged.get("apply_id") != context["apply_id"] or staged.get("plan_hash") != context["plan_hash"]:
    fail(f"recovered staged identity changed: {staged}")
try:
    recovered_deadline = datetime.datetime.fromisoformat(staged.get("confirm_by", "").replace("Z", "+00:00"))
except (TypeError, ValueError) as error:
    fail(f"recovered watchdog deadline is invalid: {error}")
if recovered_deadline != deadline:
    fail(f"recovered watchdog deadline changed: {staged}")
if datetime.datetime.now(datetime.timezone.utc) >= deadline:
    fail("recovery did not preserve a future watchdog deadline")

unit = "shakerproxy-network-watchdog-" + context["apply_id"].removeprefix("apply-") + ".service"
if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode != 0:
    fail("independent watchdog was not re-armed after reboot")

# Type=exec proves execve succeeded, but allow the new process to install its
# SIGTERM handler before deliberately interrupting it to expedite rollback.
time.sleep(2)
if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode != 0:
    fail("re-armed watchdog did not remain active")
if subprocess.run(["systemctl", "stop", unit], check=False).returncode != 0:
    fail("re-armed watchdog could not be interrupted for rollback proof")

rollback_deadline = time.monotonic() + 60
while time.monotonic() < rollback_deadline:
    try:
        state = call("GetManagedState")
    except (ConnectionError, FileNotFoundError, TimeoutError, OSError):
        time.sleep(0.5)
        continue
    staged = state.get("staged_network_plan") or {}
    if staged.get("status") == "ROLLED_BACK":
        break
    if staged.get("status") == "ROLLBACK_FAILED":
        fail(f"post-reboot watchdog rollback failed: {state}")
    time.sleep(0.5)
else:
    fail("post-reboot watchdog outcome was not reconciled")

if state.get("operating_mode") != "SETUP_SAFE" or state.get("emergency_bypass"):
    fail(f"post-reboot state is not setup-safe: {state}")
if os.path.exists("/etc/netplan/90-shakerproxy.yaml"):
    fail("managed Netplan file survived rollback")
with open("/etc/kea/kea-dhcp4.conf", "rb") as kea_config_file:
    kea_config_sha256 = hashlib.sha256(kea_config_file.read()).hexdigest()
if kea_config_sha256 != context["kea_config_before_sha256"]:
    fail("prior DHCPv4 configuration was not restored exactly")
if subprocess.run(["systemctl", "is-active", "--quiet", "shakerproxy-dhcp4.service"], check=False).returncode == 0:
    fail("DHCPv4 service remained active after rollback")
if subprocess.run(["systemctl", "is-enabled", "--quiet", "shakerproxy-dhcp4.service"], check=False).returncode == 0:
    fail("DHCPv4 service remained boot-enabled after rollback")
if open("/proc/sys/net/ipv4/ip_forward", encoding="ascii").read().strip() != context["forwarding_before"]:
    fail("IPv4 forwarding was not restored")
for command in (["iptables", "-w", "2", "-S", "SHAKERPROXY-FORWARD"], ["iptables", "-w", "2", "-t", "nat", "-S", "SHAKERPROXY-POSTROUTING"]):
    if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
        fail("managed firewall chain survived rollback")

report("SHAKERPROXY_VM_PASS scenario=reboot")
subprocess.run(["systemctl", "disable", "shakerproxy-vm-reboot-verify.service"], check=False)
subprocess.run(["systemctl", "poweroff", "--no-block"], check=False)
