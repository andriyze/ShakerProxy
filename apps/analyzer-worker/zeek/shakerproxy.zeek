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

# conn.log: the name the client asked for (TLS or QUIC server name, else the
# HTTP Host), so a connection is shown by the domain it reached rather than
# by an address. The QUIC analyzer deletes c$quic once it logs, so the name
# is kept on the connection when the client sends it; the connection record
# is written at priority -5.
redef record Conn::Info += {
	server_name: string &optional &log;
};

redef record connection += {
	shakerproxy_server_name: string &optional;
};

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) &priority=4
	{
	if ( is_client && |names| > 0 && names[0] != "" )
		c$shakerproxy_server_name = names[0];
	}

event connection_state_remove(c: connection) &priority=0
	{
	if ( ! c?$conn )
		return;
	if ( c?$shakerproxy_server_name )
		c$conn$server_name = c$shakerproxy_server_name;
	else if ( c?$http && c$http?$host && c$http$host != "" )
		c$conn$server_name = split_string1(c$http$host, /:/)[0];
	}

# dhcp.log: the client's parameter request list (option 55, in the order
# the client asked) and the router the server hands out (option 3). With the
# vendor class from the DHCP software script, the list is a fingerprint of
# the client's DHCP implementation, so the inventory can tell what a device
# is even when the network's router, not ShakerProxy, serves its lease.
redef record DHCP::Info += {
	client_param_list: vector of count &log &optional;
	routers: vector of addr &log &optional;
};

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	# BOOTREQUEST (op 1) comes from the client, BOOTREPLY (op 2) from a
	# server; a relayed or broadcast reply can arrive as an originator.
	if ( msg$op == 1 && options?$param_list && |options$param_list| > 0 )
		DHCP::log_info$client_param_list = options$param_list;
	if ( msg$op == 2 && options?$routers && |options$routers| > 0 )
		DHCP::log_info$routers = options$routers;
	}
