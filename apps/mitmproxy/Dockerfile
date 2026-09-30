# syntax=docker/dockerfile:1.12
FROM mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f

USER root
RUN install -d -m 0755 -o root -g root /opt/shakerproxy
COPY --chmod=0444 apps/mitmproxy/resolvers.json /opt/shakerproxy/resolvers.json
COPY --chmod=0444 apps/mitmproxy/shakerproxy_policy.py /opt/shakerproxy/shakerproxy_policy.py
COPY --chmod=0444 apps/mitmproxy/shakerproxy_stable_bypass.py /opt/shakerproxy/shakerproxy_stable_bypass.py
COPY --chmod=0444 apps/mitmproxy/shakerproxy_content_policy.py /opt/shakerproxy/shakerproxy_content_policy.py
COPY --chmod=0444 apps/mitmproxy/shakerproxy_addon.py /opt/shakerproxy/shakerproxy_addon.py
COPY --chmod=0444 apps/mitmproxy/shakerproxy_entrypoint.py /opt/shakerproxy/shakerproxy_entrypoint.py

# The upstream entrypoint mutates /etc/passwd to mirror mounted-volume owners.
# ShakerProxy instead runs at its fixed non-root UID and mounts pre-owned volumes.
USER 65532:65532
ENV HOME=/tmp \
    PYTHONPATH=/opt/shakerproxy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/mitmdump"]
# No --listen-host: mitmproxy binds every IPv4 and IPv6 address so lab IPv6
# can be redirected too. shakerproxy-gatewayd's fixed INPUT rules (iptables and
# ip6tables) keep port 8085 reachable only from loopback and the lab segment.
# stream_large_bodies bounds per-flow buffering: larger bodies are streamed
# through and recorded as metadata only.
CMD ["--mode", "transparent", "--listen-port", "8085", "--set", "confdir=/var/lib/shakerproxy/mitmproxy", "--set", "block_global=false", "--set", "connection_strategy=lazy", "--set", "stream_large_bodies=5m", "--set", "flow_detail=0", "--set", "termlog_verbosity=warn", "--set", "showhost=true", "-s", "/opt/shakerproxy/shakerproxy_entrypoint.py"]
