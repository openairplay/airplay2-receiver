# Experimental

Very quick python implementation of AP2 protocol using **minimal
multi-room** features. For now it implements:
- HomeKit transient pairing (SRP/Curve25519/ChaCha20-Poly1305) - bit flag 48
- HomeKit non-transient pairing
- Some refinements for HomeKit interaction (e.g. managed/active flags)
- Persist device name and some HomeKit properties across restarts (just use the -m flag again to set the device name anew)
- FairPlay (v3) authentication and decryption of AES keys - the first and only Python implementation. Credit to @systemcrash for implementation.
- Receiving of both REALTIME and BUFFERED Airplay2 audio streams
- Airplay2 Service publication
- Decoding of all Airplay2 supported CODECs: ALAC, AAC, OPUS, PCM.
 Ref: [here](https://emanuelecozzi.net/docs/airplay2/audio/) and 
      [here](https://emanuelecozzi.net/docs/airplay2/rtsp/#setup)
- Output latency compensation for sync with other Airplay receivers
- ANNOUNCE and RSA AES for unbuffered streaming from iTunes/Windows
- Spotify (via AirPlay2) and other live media streams with AES keys.


For now it does not implement:
 - FairPlay v2
 - Accurate audio sync (PTP and/or NTP)

 It may never implement:
 - MFi Authentication (requires MFi hardware module)
 
**This code is experimental. This receiver does not expect to be a real receiver but a toolbox for learning/debugging all airplay protocols and related pairing/authentication methods.**

Latest additions:
 - Implement RTP buffer (manage FLUSHBUFFERED) : play/pause/timeline/playlist

Next steps:
 - PTP (Precision Time Protocol)
 - Remove all os specific code (Soft Volume management)
 - Sender (branch-sender) - Implementation
 - Implement RSA Authentication
 - Raspbian package
 - DACP/(+MRP?) Support
 - FairPlay v2 Support
---

## Raspberry Pi 4

Install docker and then build the image:

```zsh
docker build -f docker/Dockerfile -t ap2-receiver .
```

To run the receiver:

```zsh
docker run -it --rm --device /dev/snd --net host --volume `pwd`/pairings/:/airplay2/pairings/ ap2-receiver
```

Default network device is wlan0, you can change this with AP2IFACE env variable:

```zsh
docker run -it --rm --device /dev/snd --env AP2IFACE=eth0 --net host ap2-receiver
```

## Docker Compose

Example Docker Compose
```zsh
cat << EOF > docker-compose.yaml

version: '3.8'
services:
 ap2:
   restart: unless-stopped
   network_mode: host
   build: .
   # In case we change from host mode and need to map ports.
   # ports:
     # - "7000:7000"
     # - "10000-10100:10000-10100/udp"
   volumes:
     - ./pairings:/airplay2/pairings/
   # devices:
   #  - "/dev/snd"
   environment: # All variables are optional.
     - AP2HOSTNAME=Airplay2
     - AP2IFACE=eth0
     - NO_VOLUME_MANAGEMENT=true
EOF

docker-compose up
```

## Debian

```zsh
sudo apt install -y libavformat-dev libavcodec-dev libavdevice-dev libavutil-dev libswscale-dev libswresample-dev libavfilter-dev portaudio19-dev python3 python3-pip python3-pyaudio build-essential pkg-config git alsa-utils
git clone https://github.com/openairplay/airplay2-receiver.git
cd airplay2-receiver/
pip3 install virtualenv
virtualenv airplay2-receiver
cd airplay2-receiver/
pip3 install -r requirements.txt
pip3 install pyaudio
```


## macOS Catalina

To run the receiver please use Python 3 and do the following:

* Run the following commands

```zsh
brew install python3
brew install portaudio
virtualenv -p /usr/local/bin/python3 proto
source proto/bin/activate
pip install -r requirements.txt
pip install --global-option=build_ext --global-option="-I/usr/local/Cellar/portaudio/19.6.0/include" --global-option="-L/usr/local/Cellar/portaudio/19.6.0/lib" pyaudio


python ap2-receiver.py -m myap2 --netiface=en0
```

## Windows

To run the receiver please use Python 3 and do the following:

* Run the following commands

```zsh
cd [WHERE_YOU_CLONED_AIRPLAY2_RECEIVER]
virtualenv airplay2-receiver
cd airplay2-receiver
.\Scripts\activate
pip install -r requirements.txt
pip install pipwin pycaw
pipwin install pyaudio

python ap2-receiver.py -m myap2 -n [YOUR_INTERFACE_GUID] (looks like this for instance {02681AC0-AD52-4E15-9BD6-8C6A08C4F836} )
```

* the AirPlay 2 receiver is announced as **myap2**.


---

Tested on Python 3.7.5 / macOS 10.15.2 with iPhone X 13.3 and Raspberry Pi 4

### Protocol notes

https://emanuelecozzi.net/docs/airplay2

