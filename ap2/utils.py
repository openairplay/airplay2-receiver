import re
import socket
import logging
import platform
import subprocess


if platform.system() == "Windows":
    try:
        from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
    except ImportError:
        AudioUtilities = None
        ISimpleAudioVolume = None
        print('[!] Pycaw is not installed - volume control will be unavailable', )


def get_logger(name, level="INFO"):
    logging.basicConfig(
        filename="%s.log" % name,
        filemode='a',
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
        level=level
    )
    return logging.getLogger(name)


def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


def get_free_tcp_socket():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    return free_socket


def get_free_udp_socket():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    free_socket.bind(('0.0.0.0', 0))
    return free_socket


def interpolate(value, from_min, from_max, to_min, to_max):
    from_span = from_max - from_min
    to_span = to_max - to_min

    value_scale = float(value - from_min) / float(from_span)

    return to_min + (value_scale * to_span)


audio_pid = 0

def set_volume_pid(pid):
    global audio_pid
    audio_pid = pid

def get_pycaw_volume_session():
    if platform.system() != 'Windows' or AudioUtilities is None:
        return
    session = None
    for s in AudioUtilities.GetAllSessions():
        try:
            if s.Process.pid == audio_pid:
                session = s._ctl.QueryInterface(ISimpleAudioVolume)
                break
        except AttributeError:
            pass
    return session


def get_volume():
    subsys = platform.system()
    if subsys == "Darwin":
        pct = int(subprocess.check_output(["osascript", "-e", "output volume of (get volume settings)"]).rstrip())
        vol = interpolate(pct, 0, 100, -30, 0)
    elif subsys == "Linux":
        line_pct = subprocess.check_output(["amixer", "get", "PCM"]).splitlines()[-1]
        m = re.search(b"\[([0-9]+)%\]", line_pct)
        if m:
            pct = int(m.group(1))
            if pct < 45:
                pct = 45
        else:
            pct = 50
        vol = interpolate(pct, 45, 100, -30, 0)
    elif subsys == "Windows":
        volume_session = get_pycaw_volume_session()
        if not volume_session:
            vol = -15
        else:
            vol = interpolate(volume_session.GetMasterVolume(), 0, 1, -30, 0)
    else:
        # This system is not supported, whatever it is.
        vol = 50
    if vol == -30:
        return -144
    return vol


def set_volume(vol):
    if vol == -144:
        vol = -30

    subsys = platform.system()
    if subsys == "Darwin":
        pct = int(interpolate(vol, -30, 0, 0, 100))
        subprocess.run(["osascript", "-e", "set volume output volume %d" % pct])
    elif subsys == "Linux":
        pct = int(interpolate(vol, -30, 0, 45, 100))

        subprocess.run(["amixer", "set", "PCM", "%d%%" % pct])
    elif subsys == "Windows":
        volume_session = get_pycaw_volume_session()
        if volume_session:
            pct = interpolate(vol, -30, 0, 0, 1)
            volume_session.SetMasterVolume(pct, None)
