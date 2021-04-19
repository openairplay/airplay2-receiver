import re
import socket
import logging
import platform
import subprocess

try:
    import alsaaudio
except ImportError:
    USE_PORTAUDIO = True
    print("Tried to import alsaaudio/pyalsaaudio. This may not be a problem depending on your setup.")


def get_logger(name, level="INFO"):
    logging.basicConfig(filename="%s.log" % name,
                                filemode='a',
                                format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                                datefmt='%H:%M:%S',
                                level=level)
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

def get_mixer(audio_device):
    # Unfortunately getting the controller is not easy. Here we run the amixer command and extract from the result.
    controller_string = subprocess.run(["amixer", "-D", audio_device, "scontrols"], capture_output=True, text=True).stdout
    controller_extracted = re.findall("([^']*)", controller_string)[2]
    print("Using controller: ", controller_extracted)
    mixer = alsaaudio.Mixer(device=audio_device, control=controller_extracted)

    return mixer

def get_volume(audio_device):
    subsys = platform.system()
    if subsys == "Darwin":
        pct = int(subprocess.check_output(["osascript", "-e", "output volume of (get volume settings)"]).rstrip())
        vol = interpolate(pct, 0, 100, -30, 0)
    elif subsys == "Linux":
        mixer = get_mixer(audio_device)
        current_volume_percentage = mixer.getvolume()[0]

        # Not sure why this limit is here.
        if current_volume_percentage < 45:
            current_volume_percentage = 45

        vol = interpolate(current_volume_percentage, 45, 100, -30, 0)
    elif subsys == "Windows":
        # Volume get is not managed under windows, let's set to a default volume
        vol = 50;
    if vol == -30:
        return -144
    return vol


def set_volume(vol, audio_device):
    if vol == -144:
        vol = -30

    subsys = platform.system()
    if subsys == "Darwin":
        pct = int(interpolate(vol, -30, 0, 0, 100))
        subprocess.run(["osascript", "-e", "set volume output volume %d" % pct])
    elif subsys == "Linux":
        volume_percentage = int(interpolate(vol, -30, 0, 45, 100))

        mixer = get_mixer(audio_device)
        mixer.setvolume(volume_percentage)
        print(mixer.getvolume())