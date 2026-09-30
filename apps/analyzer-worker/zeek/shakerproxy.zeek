##! ShakerProxy site policy for offline protocol discovery over closed capture
##! segments. Zeek 8 already loads MQTT, QUIC, WebSocket, analyzer.log
##! (protocol violations), weird.log, and the software framework by default.
##! This script only adds bounded, per-connection enrichment; every log it
##! enables is keyed by connection or by (host, port/software) and is written
##! once per analyzed segment.

# conn.log: protocols recognised by a DPD signature that could not be
# confirmed (proprietary or truncated payloads), and analyzers that were
# removed after a protocol violation.
@load policy/protocols/conn/speculative-service
@load policy/protocols/conn/failed-service-logging

# conn.log: Community ID so Zeek and Suricata records of one flow correlate.
@load policy/protocols/conn/community-id-logging

# conn.log: layer-2 addresses of both endpoints for device attribution.
@load policy/protocols/conn/mac-logging

# known_services.log: which lab devices expose which services.
@load policy/protocols/conn/known-services

# software.log: client/server software banners (HTTP user agents and server
# headers, SSH versions, DHCP vendor classes) for device identification.
@load policy/protocols/http/software
@load policy/protocols/ssh/software
@load policy/protocols/dhcp/software

# Lab networks are private address space. Treating them as local makes
# local_orig/local_resp meaningful and lets known-services and software track
# lab devices rather than every Internet server.
redef Site::local_nets += {
	10.0.0.0/8,
	172.16.0.0/12,
	192.168.0.0/16,
	100.64.0.0/10,
	169.254.0.0/16,
	[fc00::]/7,
	[fe80::]/10,
};

# Keep analyzer violation excerpts short; they may contain payload bytes.
redef Analyzer::Logging::failure_data_max_size = 40;
