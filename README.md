# Experimental

Very quick python implementation of AP2 protocol using **minimal
multi-room** features without authentication/encryption.

**This code is experimental. To use for debugging purposes only.** 

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
brew install portaudio
virtualenv proto
source proto/bin/activate
pip install -r requirements.txt
pip install --global-option=build_ext --global-option="-I/usr/local/Cellar/portaudio/19.6.0/include" --global-option="-L/usr/local/Cellar/portaudio/19.6.0/lib" pyaudio


python ap2-receiver.py -m myap2
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

