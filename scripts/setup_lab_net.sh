#!/bin/bash
set -e

echo "Setting up veth interfaces for lab environment..."
ip link add veth0 type veth peer name veth1 || true
ip link set veth0 up
ip link set veth1 up
tc qdisc add dev veth0 clsact || true

echo "veth pair created and clsact attached."
