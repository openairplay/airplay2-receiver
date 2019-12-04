# Experimental

Very quick python implementation of AP2 pairing and play using **minimal
multi-room** features.

To run the receiver please use Python 3 and do the following:

* open the _event_ server;

```
nc -lk 0.0.0.0 <EPORT>
```

* open the _data_ server;

```
nc -ulk 0.0.0.0 <DPORT>
```

* open the _control_ server;

```
nc -ulk 0.0.0.0 <CPORT>
```

* start the receiver;

```
brew install portaudio
virtualenv proto
source proto/bin/activate
pip install -r requirements.txt
pip install --global-option=build_ext --global-option="-I/usr/local/Cellar/portaudio/19.6.0/include" --global-option="-L/usr/local/Cellar/portaudio/19.6.0/lib" pyaudio
python receiver.py -m gino -e <EPORT> -d <DPORT> -c <CPORT>
```

* the AirPlay 2 receiver is announced as **gino**.

Tested on Python 3.7.5 / macOS 10.15.1 with iPhone X 13.2.3

#wip explain messages exchanged

