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

## Raspberry Pi 4

Install docker and then build the image:

```zsh
docker build -f docker/Dockerfile -t invano/ap2-receiver .
```

To run the receiver:

```zsh
docker run -it --rm --device /dev/snd --net host invano/ap2-receiver
```

Default network device is wlan0, you can change this with AP2IFACE env variable:

```zsh
docker run -it --rm --device /dev/snd --env AP2IFACE=eth0 --net host invano/ap2-receiver
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
pip install pipwin
pipwin install pyaudio

python ap2-receiver.py -m myap2 -n [YOUR_INTERFACE_GUID] (looks like this for instance {02681AC0-AD52-4E15-9BD6-8C6A08C4F836} )
```

* the AirPlay 2 receiver is announced as **myap2**.


---

Tested on Python 3.7.5 / macOS 10.15.2 with iPhone X 13.3 and Raspberry Pi 4

### Protocol notes

https://emanuelecozzi.net/docs/airplay2

