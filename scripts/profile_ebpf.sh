#!/bin/bash
set -e
ID=$(bpftool prog show name sigma_main -j | jq '.[0].id')
if [[ $(cat /proc/sys/kernel/perf_event_paranoid) -gt 1 ]]; then
    echo "ERROR: perf_event_paranoid > 1. Flamegraphs requieren <=1 o CAP_PERFMON" >&2
    exit 1
fi
bpftool prog profile id $ID duration 10 > /tmp/ebpf.profile
echo "Profile saved. Convert to pprof:./profile2pprof /tmp/ebpf.profile"
