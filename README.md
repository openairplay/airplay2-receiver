# Experimental

Very quick python implementation of AP2 protocol using **minimal
multi-room** features. For now it implements:
- HomeKit transient pairing (SRP/Curve25519/ChaCha20-Poly1305)
- FairPlay (v3) authentication
- Receiving of both REALTIME and BUFFERED Airplay2 audio streams
- Airplay2 Service publication
- Decoding of ALAC/44100/2 or AAC/44100/2

For now it does not implement:
 - MFi Authentication / FairPlay v2 (one of them is required by iTunes/Windows)
 - Audio Sync
 
**This code is experimental. This receiver do not expect to be a real receiver but a toolbox for learning/debugging all airplay protocols and related pairing/authentication methods.** 

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

## Pre-Built Docker Image
This image is built directly from `master` so may break. Tested with Raspberry Pi.

https://hub.docker.com/r/charlesomer/airplay

Example Docker Compose
```zsh
version: "3.8"
services:
  airplay:
    image: charlesomer/airplay:latest
    restart: always
    network_mode: host
    environment: # All variables are optional.
      # - AP2HOSTNAME=Airplay2Device
      # - AP2IFACE=eth0
      # - AUDIO_DEVICE=default # For use with alsaaudio.
      # - USE_PORTAUDIO=true # If this is set to true, volume management is also disabled
      # - NO_VOLUME_MANAGEMENT=true
    devices:
      - "/dev/snd"
```

## Raspberry Pi

Install docker and then build the image:

```zsh
docker build -f docker/Dockerfile -t USERNAME/airplay .
```

To run the receiver:

```zsh
docker run -it --rm --device /dev/snd --net host USERNAME/airplay
```

## macOS

_macOS has shown issues when playing audio, if anyone is able to take a look at this to confirm/fix that would be great._

Currently `portaudio` is required for MacOS. It can be installed via homebrew:
```zsh
brew install portaudio
```
Then, you may be able to use the docker image although this is untested. Add the `--use-portaudio` option. Alternatively, clone the repo and run via python virtualenv.

```zsh
pip3 install virtualenv
virtualenv -p /usr/local/bin/python3 airplay-env
source airplay-env/bin/activate
pip3 install -r requirements.txt

# The following line may not be required.
# pip3 install --global-option=build_ext --global-option="-I/usr/local/Cellar/portaudio/19.6.0/include" --global-option="-L/usr/local/Cellar/portaudio/19.6.0/lib" pyaudio

python ap2-receiver.py -m myap2 --netiface=en0
# Allow incoming connections.
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
pip install pipwin
pipwin install pyaudio

python ap2-receiver.py -m myap2 -n [YOUR_INTERFACE_GUID] (looks like this for instance {02681AC0-AD52-4E15-9BD6-8C6A08C4F836} )
```

* the AirPlay 2 receiver is announced as **myap2**.


---

Tested on Python 3.7.5 / macOS 10.15.2 with iPhone X 13.3 and Raspberry Pi 4

### Protocol notes

https://emanuelecozzi.net/docs/airplay2

