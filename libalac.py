import ctypes
from hexdump import hexdump

LIBALAC = ctypes.CDLL("./libalac-wr.dylib", use_errno=True)
LIBALAC.apple_alac_init.restype = ctypes.c_int
LIBALAC.apple_alac_decode_frame.restype = ctypes.c_int
LIBALAC.apple_alac_terminate.restype = ctypes.c_int


def libalac_init():
    fmt = (ctypes.c_int * 12)()
    fmt[0] = 96
    fmt[1] = 352
    fmt[2] = 0
    fmt[3] = 16
    fmt[4] = 40
    fmt[5] = 10
    fmt[6] = 14
    fmt[7] = 2
    fmt[8] = 255
    fmt[9] = 0
    fmt[10] = 0
    fmt[11] = 44100

    res = LIBALAC.apple_alac_init(fmt)
    return res

def libalac_decode_frame(frame):
    data_len = ctypes.c_uint(len(frame))
    buf = ctypes.create_string_buffer(4096)
    buf_len = ctypes.c_int(len(buf))
    res = LIBALAC.apple_alac_decode_frame(frame, data_len, buf, ctypes.byref(buf_len))
    return res, buf[:buf_len.value*4]

def libalac_terminate():
    LIBALAC.apple_alac_terminate()
    return
