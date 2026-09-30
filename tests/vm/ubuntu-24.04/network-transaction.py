#!/usr/bin/env python3
import json
import hashlib
import os
import socket
import subprocess
import sys
import time

SOCKET = "/run/shakerproxy/gatewayd.sock"
SCENARIO = sys.argv[1]
KEA_CONFIG = "/etc/kea/kea-dhcp4.conf"
with open(KEA_CONFIG, "rb") as kea_config_file:
    kea_config_before_sha256 = hashlib.sha256(kea_config_file.read()).hexdigest()


def call(method, params=None):
    request = {"jsonrpc": "2.0", "id": f"vm-{time.time_ns()}", "method": method, "params": params or {}}
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
        raise RuntimeError(f"{method}: {decoded['error']}")
    return decoded.get("result")


ssh_probe = None
if SCENARIO == "host-safety":
    address_output = subprocess.check_output(["ip", "-4", "-o", "address", "show", "dev", "wan0", "scope", "global"], text=True)
    wan_address = address_output.split()[3].split("/", 1)[0]
    ssh_probe = socket.create_connection((wan_address, 22), timeout=8)
    ssh_probe.settimeout(8)
    banner = ssh_probe.recv(256)
    assert banner.startswith(b"SSH-"), banner

inspection = call("InspectHost")
interfaces = {item["name"]: item for item in inspection["interfaces"]}
assert "wan0" in interfaces and "lab0" in interfaces, interfaces
lab_name = "labbr" if SCENARIO in ("dhcp", "capture") else "lab0"
assert lab_name in interfaces, interfaces
assert inspection["firewall"]["apply_ready"] is True, inspection["firewall"]
if SCENARIO == "host-safety":
    assert any(session.get("destination_interface") == "wan0" for session in inspection["active_ssh"]), inspection["active_ssh"]

plan = {
    "schema": 1,
    "name": f"VM acceptance {SCENARIO}",
    "topology": "TWO_NIC",
    "interfaces": [
        {"stable_id": interfaces["wan0"]["stable_id"], "current_name": "wan0", "permanent_mac": interfaces["wan0"].get("hardware_address", ""), "role": "WAN"},
        {"stable_id": interfaces[lab_name]["stable_id"], "current_name": lab_name, "permanent_mac": interfaces[lab_name].get("hardware_address", ""), "role": "LAB"},
    ],
    "management": {"preserve_active_ssh": True, "allowed_cidrs": []},
    "ipv4": {"enabled": True, "lab_cidr": "10.77.0.0/24", "gateway_address": "10.77.0.1", "dhcp_start": "10.77.0.100", "dhcp_end": "10.77.0.200", "dhcp_lease_seconds": 600, "dns_addresses": ["1.1.1.1"], "search_domain": "shakerproxy.test", "reservations": [], "nat44": True, "client_isolation": True},
    "ipv6": {"strategy": "DISABLED"},
}
if SCENARIO == "host-safety":
    unsafe_plan = json.loads(json.dumps(plan))
    unsafe_plan["interfaces"][0]["role"] = "LAB"
    unsafe_plan["interfaces"][1]["role"] = "WAN"
    rejected = call("ValidateNetworkPlan", {"plan": unsafe_plan})
    assert rejected["valid"] is False, rejected
    assert any(issue["code"] == "ACTIVE_SSH_ON_LAB_INTERFACE" for issue in rejected["errors"]), rejected
preview = call("PreviewNetworkPlan", {"plan": plan})
assert preview["validation"]["valid"] is True, preview
assert preview["firewall_environment"]["apply_ready"] is True, preview
if SCENARIO == "host-safety":
    assert preview["active_ssh"] == inspection["active_ssh"], (preview["active_ssh"], inspection["active_ssh"])
plan_hash = preview["validation"]["plan_hash"]
staged = call("StageNetworkPlan", {"plan": plan, "expected_plan_hash": plan_hash, "idempotency_key": f"vm-stage-{SCENARIO}-0001", "stage_ttl_seconds": 300})
apply_id = staged["apply_id"]
forwarding_before = open("/proc/sys/net/ipv4/ip_forward", encoding="ascii").read().strip()
rollback_window = 180 if SCENARIO == "reboot" else 60
commit_params = {"apply_id": apply_id, "plan_hash": plan_hash, "idempotency_key": f"vm-commit-{SCENARIO}-0001", "rollback_window_seconds": rollback_window}
commit = call("CommitNetworkPlan", commit_params)
call("SignalNetworkHealth", {"apply_id": apply_id, "plan_hash": plan_hash, "token": commit["health_token"]})

deadline = time.monotonic() + 50
while time.monotonic() < deadline:
    status = call("GetManagedState")["staged_network_plan"]
    if status["status"] == "AWAITING_CONFIRMATION":
        break
    if status["status"] in ("ROLLED_BACK", "ROLLBACK_FAILED"):
        raise RuntimeError(f"apply ended early: {status}")
    time.sleep(1)
else:
    final_commit = call("CommitNetworkPlan", commit_params)
    raise RuntimeError(f"apply did not reach confirmation: state={status}, commit={final_commit}")

if SCENARIO == "dhcp":
    subprocess.run(["ip", "netns", "add", "labclient"], check=True)
    subprocess.run(["ip", "link", "set", "labclient0", "netns", "labclient"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "link", "set", "labclient0", "up"], check=True)
    subprocess.run([
        "ip", "netns", "exec", "labclient", "/usr/bin/busybox", "udhcpc",
        "-f", "-q", "-n", "-t", "5", "-T", "3", "-i", "labclient0",
        "-s", "/usr/local/libexec/shakerproxy-vm-udhcpc-script",
    ], check=True, timeout=30)
    address_output = subprocess.check_output(["ip", "netns", "exec", "labclient", "ip", "-4", "-o", "address", "show", "dev", "labclient0"], text=True)
    leased_address = address_output.split()[3].split("/", 1)[0]
    assert leased_address.startswith("10.77.0."), leased_address
    route_output = subprocess.check_output(["ip", "netns", "exec", "labclient", "ip", "route", "show", "default"], text=True)
    assert "via 10.77.0.1" in route_output, route_output
    subprocess.run([
        "ip", "netns", "exec", "labclient", "python3", "-c",
        'import socket; connection=socket.create_connection(("10.23.0.2",38080),10); connection.sendall(b"GET / HTTP/1.0\\r\\nHost: upstream\\r\\n\\r\\n"); assert b"200 OK" in connection.recv(1024); connection.close()',
    ], check=True, timeout=15)
    lease_contents = open("/var/lib/kea/kea-leases4.csv", encoding="utf-8").read()
    assert leased_address in lease_contents, lease_contents

if SCENARIO == "capture":
    subprocess.run(["ip", "netns", "add", "labclient"], check=True)
    subprocess.run(["ip", "link", "set", "labclient0", "netns", "labclient"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "link", "set", "labclient0", "up"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "address", "add", "10.77.0.111/24", "dev", "labclient0"], check=True)
    subprocess.run(["ip", "netns", "exec", "labclient", "ip", "route", "add", "default", "via", "10.77.0.1"], check=True)

if SCENARIO in ("confirm", "dhcp", "capture"):
    confirmed = call("ConfirmNetworkPlan", {"apply_id": apply_id, "plan_hash": plan_hash, "idempotency_key": "vm-confirm-request-0001"})
    assert confirmed["status"] == "CONFIRMED", confirmed
    state = call("GetManagedState")
    assert state["operating_mode"] == "ROUTED_PASSTHROUGH", state
    if SCENARIO == "capture":
        assert state["capture_available"] is True, state
        request = {
            "name": "VM chain-of-custody proof",
            "description": "Bounded lab-ingress header capture",
            "mode": "HEADERS_ONLY",
            "snap_length": 256,
            "segment_size_mib": 1,
            "segment_seconds": 10,
            "max_files": 2,
            "stop_after_seconds": 60,
            "retention_lock": True,
            "case_id": "VM-CAPTURE-1",
            "idempotency_key": "vm-capture-start-0001",
            "administrator": "vm-admin",
            "start_reason": "acceptance proof",
        }
        capture = call("StartCapture", {"request": request})
        capture_id = capture["session"]["id"]
        assert capture["session"]["source"]["interface_name"] == "labbr", capture
        assert capture["active"] is True, capture
        listed = json.loads(subprocess.check_output(["/usr/bin/shakerproxy", "capture", "list", "--json"], text=True))
        assert any(item["session"]["id"] == capture_id for item in listed), listed
        for _ in range(4):
            subprocess.run([
                "ip", "netns", "exec", "labclient", "python3", "-c",
                'import socket; connection=socket.create_connection(("10.23.0.2",38080),10); connection.sendall(b"GET / HTTP/1.0\\r\\nHost: capture-proof\\r\\n\\r\\n"); assert b"200 OK" in connection.recv(1024); connection.close()',
            ], check=True, timeout=15)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            live = call("GetCaptureStats", {"session_id": capture_id})
            # dumpcap's packet/drop totals are final accounting emitted when the
            # process exits; live progress is the worker state and bounded bytes.
            if live.get("worker", {}).get("state") == "RUNNING" and live.get("current_bytes", 0) > 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError(f"capture counters did not advance: {live}")
        stopped = call("StopCapture", {"session_id": capture_id})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            stopped = call("GetCaptureStats", {"session_id": capture_id})
            if not stopped["active"] and stopped.get("manifest"):
                break
            time.sleep(1)
        else:
            raise RuntimeError(f"capture did not finalize: {stopped}")
        manifest = stopped["manifest"]
        assert manifest["files"] and manifest["packets_captured"] > 0, manifest
        session_directory = os.path.join("/var/lib/shakerproxy/pcap", capture_id)
        with open(os.path.join(session_directory, "session.json"), "rb") as session_file:
            assert hashlib.sha256(session_file.read()).hexdigest() == manifest["session_sha256"]
        for artifact in manifest["files"]:
            artifact_path = os.path.join(session_directory, "artifacts", artifact["name"])
            with open(artifact_path, "rb") as capture_file:
                contents = capture_file.read()
            assert contents[:4] == b"\x0a\x0d\x0d\x0a", artifact
            assert hashlib.sha256(contents).hexdigest() == artifact["sha256"], artifact
            assert len(contents) == artifact["size_bytes"], artifact
        assert manifest["kernel_drops"] == 0 and manifest["dumpcap_drops"] == 0, manifest
    sys.exit(0)

if SCENARIO == "host-safety":
    ssh_probe.sendall(b"SSH-2.0-ShakerProxy-Host-Safety\r\n")
    assert ssh_probe.recv(1), "active SSH socket closed during guarded apply"
    confirmed = call("ConfirmNetworkPlan", {"apply_id": apply_id, "plan_hash": plan_hash, "idempotency_key": "vm-host-safety-confirm-0001"})
    assert confirmed["status"] == "CONFIRMED", confirmed
    subprocess.run(["systemctl", "stop", "docker.service", "docker.socket"], check=True)
    assert subprocess.run(["systemctl", "is-active", "--quiet", "docker.service"], check=False).returncode != 0
    enabled = json.loads(subprocess.check_output(["/usr/bin/shakerproxy", "bypass", "enable", "--json"], text=True))
    assert enabled == {"emergency_bypass": True, "operating_mode": "EMERGENCY_BYPASS"}, enabled
    state = call("GetManagedState")
    assert state["operating_mode"] == "EMERGENCY_BYPASS" and state["emergency_bypass"] is True, state
    assert open("/proc/sys/net/ipv4/ip_forward", encoding="ascii").read().strip() == "1"
    assert os.path.exists("/etc/netplan/90-shakerproxy.yaml")
    subprocess.run(["iptables", "-w", "2", "-S", "SHAKERPROXY-FORWARD"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["iptables", "-w", "2", "-t", "nat", "-S", "SHAKERPROXY-POSTROUTING"], check=True, stdout=subprocess.DEVNULL)
    docker_user = subprocess.check_output(["iptables", "-w", "2", "-S", "DOCKER-USER"], text=True)
    assert docker_user.count("-j SHAKERPROXY-FORWARD") == 1, docker_user
    disabled = json.loads(subprocess.check_output(["/usr/bin/shakerproxy", "bypass", "disable", "--json"], text=True))
    assert disabled == {"emergency_bypass": False, "operating_mode": "ROUTED_PASSTHROUGH"}, disabled
    ssh_probe.close()
    sys.exit(0)

if SCENARIO == "daemon-kill":
    subprocess.run(["systemctl", "kill", "--kill-whom=main", "--signal=KILL", "shakerproxy-gatewayd.service"], check=True)

if SCENARIO == "reboot":
    os.makedirs("/var/lib/shakerproxy-vm-test", mode=0o755, exist_ok=True)
    recovery_context = {
        "apply_id": apply_id,
        "plan_hash": plan_hash,
        "confirm_by": status["confirm_by"],
        "forwarding_before": forwarding_before,
        "kea_config_before_sha256": kea_config_before_sha256,
        "boot_id_before": open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip(),
    }
    context_path = "/var/lib/shakerproxy-vm-test/reboot.json"
    with open(context_path, "w", encoding="utf-8") as context_file:
        json.dump(recovery_context, context_file)
        context_file.write("\n")
        context_file.flush()
        os.fsync(context_file.fileno())
    subprocess.run(["sync"], check=True)
    subprocess.run(["systemctl", "reboot", "--force", "--force"], check=True)
    while True:
        time.sleep(60)

deadline = time.monotonic() + 90
while time.monotonic() < deadline:
    try:
        state = call("GetManagedState")
    except (ConnectionError, FileNotFoundError, TimeoutError, OSError):
        time.sleep(1)
        continue
    status = state["staged_network_plan"]["status"]
    if status == "ROLLED_BACK":
        assert state["operating_mode"] == "SETUP_SAFE", state
        current_forwarding = open("/proc/sys/net/ipv4/ip_forward", encoding="ascii").read().strip()
        assert current_forwarding == forwarding_before, (current_forwarding, forwarding_before)
        sys.exit(0)
    if status == "ROLLBACK_FAILED":
        raise RuntimeError(f"watchdog rollback failed: {state}")
    time.sleep(1)
raise RuntimeError("independent watchdog outcome was not reconciled")
