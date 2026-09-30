# ADR 0001: Hybrid host package and Compose application

Status: accepted

Privileged networking and emergency recovery run in a small host-installed Go
daemon. User-facing services and protocol engines run in Compose. This avoids
granting a web container broad host privileges and keeps safe forwarding
independent from application health. The only control-plane bridge is a typed,
restricted Unix-socket protocol.
