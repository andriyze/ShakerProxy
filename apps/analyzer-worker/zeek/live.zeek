##! ShakerProxy live analysis tuning. Loaded after shakerproxy.zeek only by
##! the live Zeek process, which reads the lab recording as one continuous
##! packet stream instead of one closed segment at a time. A connection
##! therefore lives across segment boundaries, and this script keeps its
##! records arriving in seconds rather than when it finally ends.

# The connection framework fills a conn.log record only when a connection
# ends; this exports its filling step so an interim report matches the final
# record field for field.
module Conn;

export {
	global shakerproxy_fill: function(c: connection);
}

function shakerproxy_fill(c: connection)
	{
	set_conn(c, T);
	}

module ShakerProxyLive;

export {
	## A connection still carrying traffic reports what it carried since its
	## previous report at this interval. Each report covers its own window,
	## so the bytes and packets of all of one connection's conn.log records
	## add up to the connection's totals.
	const interim_interval = 10sec &redef;
}

# Closed connections are logged soon after their final packets, a DNS
# exchange (and an unanswered query) 3 seconds after its last packet instead
# of 10, and idle UDP and ICMP flows end after 30 seconds instead of a minute.
redef tcp_close_delay = 2sec;
redef dns_session_timeout = 3sec;
redef udp_inactivity_timeout = 30sec;
redef icmp_inactivity_timeout = 30sec;

# Zeek otherwise holds log records until its next flush, a second of traffic
# time later, which a quiet lab may not reach for a while; the live analyzer
# reads each record as soon as it is written.
redef Log::write_buffer_size = 1;

type Reported: record {
	until: time;
	orig_bytes: count &default=0;
	resp_bytes: count &default=0;
	orig_pkts: count &default=0;
	resp_pkts: count &default=0;
	orig_ip_bytes: count &default=0;
	resp_ip_bytes: count &default=0;
	missed_bytes: count &default=0;
};

redef record connection += {
	shakerproxy_reported: Reported &optional;
};

global interim: event(id: conn_id, uid: string);

function delta(total: count, reported: count): count
	{
	return total > reported ? total - reported : 0;
	}

# Narrows a conn.log record to the window after the connection's previous
# report and returns what the record now reports in total.
function narrow(c: connection, rec: Conn::Info): Reported
	{
	local last_packet = c$start_time + c$duration;
	local totals = Reported($until=last_packet);
	if ( rec?$orig_bytes ) totals$orig_bytes = rec$orig_bytes;
	if ( rec?$resp_bytes ) totals$resp_bytes = rec$resp_bytes;
	if ( rec?$orig_pkts ) totals$orig_pkts = rec$orig_pkts;
	if ( rec?$resp_pkts ) totals$resp_pkts = rec$resp_pkts;
	if ( rec?$orig_ip_bytes ) totals$orig_ip_bytes = rec$orig_ip_bytes;
	if ( rec?$resp_ip_bytes ) totals$resp_ip_bytes = rec$resp_ip_bytes;
	if ( rec?$missed_bytes ) totals$missed_bytes = rec$missed_bytes;
	if ( ! c?$shakerproxy_reported )
		return totals;
	local previous = c$shakerproxy_reported;
	rec$ts = previous$until;
	rec$duration = last_packet > previous$until ? last_packet - previous$until : 0secs;
	if ( rec?$orig_bytes ) rec$orig_bytes = delta(totals$orig_bytes, previous$orig_bytes);
	if ( rec?$resp_bytes ) rec$resp_bytes = delta(totals$resp_bytes, previous$resp_bytes);
	if ( rec?$orig_pkts ) rec$orig_pkts = delta(totals$orig_pkts, previous$orig_pkts);
	if ( rec?$resp_pkts ) rec$resp_pkts = delta(totals$resp_pkts, previous$resp_pkts);
	if ( rec?$orig_ip_bytes ) rec$orig_ip_bytes = delta(totals$orig_ip_bytes, previous$orig_ip_bytes);
	if ( rec?$resp_ip_bytes ) rec$resp_ip_bytes = delta(totals$resp_ip_bytes, previous$resp_ip_bytes);
	if ( rec?$missed_bytes ) rec$missed_bytes = delta(totals$missed_bytes, previous$missed_bytes);
	return totals;
	}

event new_connection(c: connection)
	{
	schedule interim_interval { interim(c$id, c$uid) };
	}

event interim(id: conn_id, uid: string)
	{
	# Zeek fires pending timers when it stops; every connection then gets
	# its final record anyway.
	if ( zeek_is_terminating() || ! connection_exists(id) )
		return;
	local c = lookup_connection(id);
	if ( c$uid != uid )
		return;
	schedule interim_interval { interim(id, uid) };
	local packets = c$orig$num_pkts + c$resp$num_pkts;
	if ( c?$shakerproxy_reported && packets <= c$shakerproxy_reported$orig_pkts + c$shakerproxy_reported$resp_pkts )
		return;
	if ( c$duration == 0secs )
		return;
	Conn::shakerproxy_fill(c);
	local rec = copy(c$conn);
	if ( c?$shakerproxy_server_name )
		rec$server_name = c$shakerproxy_server_name;
	else if ( c?$http && c$http?$host && c$http$host != "" )
		rec$server_name = split_string1(c$http$host, /:/)[0];
	if ( c$orig?$l2_addr )
		rec$orig_l2_addr = c$orig$l2_addr;
	if ( c$resp?$l2_addr )
		rec$resp_l2_addr = c$resp$l2_addr;
	c$shakerproxy_reported = narrow(c, rec);
	Log::write(Conn::LOG, rec);
	}

# The final record reports only the window after the last interim report.
# It runs after the site and MAC scripts fill the record and before the
# connection framework writes it at priority -5.
event connection_state_remove(c: connection) &priority=-4
	{
	if ( c?$conn && c?$shakerproxy_reported )
		narrow(c, c$conn);
	}

# QUIC records otherwise wait for the connection to end, which for a QUIC
# session is usually its idle timeout. Log one as soon as the client hello
# names the server, and suppress the end-of-connection copy; the record then
# lacks the server's connection ID and the rest of the packet history.
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=-10
	{
	if ( ! c?$quic || c$quic$logged || ! c$quic?$server_name )
		return;
	c$quic$history = join_string_vec(c$quic$history_state, "");
	Log::write(QUIC::LOG, c$quic);
	c$quic$logged = T;
	}

hook QUIC::log_policy(rec: QUIC::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$logged )
		break;
	}
