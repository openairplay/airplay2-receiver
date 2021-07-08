#!/bin/bash

if [ -z "${AP2HOSTNAME}" ]; then
    export AP2HOSTNAME='ap2'
fi
if [ -z "${AP2IFACE}" ]; then
    export AP2IFACE='wlan0'
fi
if [ -z "${AUDIO_DEVICE}" ]; then
    export AUDIO_DEVICE='default'
fi
NO_VOLUME_MANAGEMENT_FLAG=""
if [ "${NO_VOLUME_MANAGEMENT}" = "true" ]; then
    NO_VOLUME_MANAGEMENT_FLAG='--no-volume-management'
fi
DISABLE_PORTAUDIO_FLAG=""
if [ "${DISABLE_PORTAUDIO}" = "true" ]; then
    DISABLE_PORTAUDIO_FLAG='--disable-portaudio'
fi

# Swap hostname in the avahi config
sed "s/\(host-name=\).*/\1${AP2HOSTNAME}/g" -i /etc/avahi/avahi-daemon.conf

# Debian services for mdns
#/etc/init.d/dbus start
/etc/init.d/avahi-daemon start

# Start AirPlay 2 service
cd /airplay2
exec python3 ap2-receiver.py -m ${AP2HOSTNAME} -n ${AP2IFACE} --audio-device ${AUDIO_DEVICE} ${NO_VOLUME_MANAGEMENT_FLAG} ${DISABLE_PORTAUDIO_FLAG}