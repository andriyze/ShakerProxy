#!/bin/sh
# udhcpc passes the lease in the environment: interface, ip and router.
# shellcheck disable=SC2154
set -eu

case "${1:-}" in
  bound|renew)
    ip address flush dev "$interface"
    ip address add "$ip/24" dev "$interface"
    set -- $router
    ip route replace default via "$1" dev "$interface"
    ;;
esac
