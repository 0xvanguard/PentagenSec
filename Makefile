# Makefile
EBPF_DIR = ebpf
BPF_CLANG = clang
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu

$(EBPF_DIR)/sigma_filter.o: $(EBPF_DIR)/sigma_filter.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

load-xdp: $(EBPF_DIR)/sigma_filter.o
	sudo bpftool prog load $< /sys/fs/bpf/sigma_filter type xdp
	sudo bpftool net attach xdp pinned /sys/fs/bpf/sigma_filter dev eth0

unload-xdp:
	sudo bpftool net detach xdp dev eth0
	sudo rm -rf /sys/fs/bpf/sigma_filter /sys/fs/bpf/sigma

BPF_FS_DIR = /sys/fs/bpf/sigma

pin-maps:
	sudo mkdir -p $(BPF_FS_DIR)
	sudo bpftool map pin id $$(sudo bpftool prog show name sigma_xdp_filter -j | jq '.[0].map_ids[0]') $(BPF_FS_DIR)/rules_map
	sudo bpftool map pin id $$(sudo bpftool prog show name sigma_xdp_filter -j | jq '.[0].map_ids[1]') $(BPF_FS_DIR)/control_map

reload-rules:
	sudo python3 main.py --xdp --iface $(IFACE) --reload-rules

watch-maps:
	sudo watch -n1 'bpftool map dump pinned $(BPF_FS_DIR)/rules_map | head -20'
