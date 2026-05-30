import ctypes
import ctypes.util

libbpf_path = ctypes.util.find_library("bpf")
if not libbpf_path:
    libbpf_path = "libbpf.so.1" # Fallback

try:
    libbpf = ctypes.CDLL(libbpf_path)
except OSError:
    libbpf = None

if libbpf:
    # bpf_object__open_file
    libbpf.bpf_object__open_file.restype = ctypes.c_void_p
    libbpf.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

    # bpf_object__load
    libbpf.bpf_object__load.restype = ctypes.c_int
    libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]

    # bpf_object__find_program_by_name
    libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
    libbpf.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # bpf_program__fd
    libbpf.bpf_program__fd.restype = ctypes.c_int
    libbpf.bpf_program__fd.argtypes = [ctypes.c_void_p]

    # bpf_set_link_xdp_fd
    libbpf.bpf_set_link_xdp_fd.restype = ctypes.c_int
    libbpf.bpf_set_link_xdp_fd.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint32]

    # bpf_object__find_map_by_name
    libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p
    libbpf.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # bpf_map__fd
    libbpf.bpf_map__fd.restype = ctypes.c_int
    libbpf.bpf_map__fd.argtypes = [ctypes.c_void_p]
