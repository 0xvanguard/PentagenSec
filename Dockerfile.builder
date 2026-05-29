FROM ubuntu:24.04
RUN apt-get update && apt-get install -y clang llvm libelf-dev linux-headers-generic make libbpf-dev re2c python3 python3-yaml && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app

# Compilar static eBPF files que no requieren JIT
RUN mkdir -p /out && clang -O2 -target bpf -g -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c ebpf/consensus_kern.c -o /out/consensus_kern.o

# El contenedor escribirá los artefactos compilados en /out
CMD ["python3", "core/sigma_jit.py", "--rules-dir", "rules/", "--out-dir", "/out"]
