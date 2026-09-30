from shakerproxy_addon import ShakerProxyTLS
from shakerproxy_content_policy import ShakerProxyContentPolicy

# Ordering matters: the privacy addon refreshes the durable local content
# policy before ShakerProxyTLS handles each HTTP request/response hook.
addons = [ShakerProxyContentPolicy(), ShakerProxyTLS()]
