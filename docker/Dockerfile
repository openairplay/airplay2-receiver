FROM debian:buster

RUN apt-get update -yy && \
    apt-get install -yy \
        avahi-daemon \
        avahi-discover \
        avahi-utils \
        libnss-mdns \
        dnsutils \
        python3 \
        python3-pip \
        python3-pyaudio \
        libffi-dev \
        git \
        make \
        g++ \
        alsa-utils

COPY ap2-receiver.py /airplay2/ap2-receiver.py
COPY ap2 /airplay2/ap2
COPY requirements.txt /airplay2/requirements.txt

RUN git clone https://github.com/macosforge/alac.git /ALAC && \
       cp /airplay2/ap2/alac/apple_alac.cpp /ALAC/codec/ && \
       cp /airplay2/ap2/alac/apple_alac.h /ALAC/codec/ && \
       cd /ALAC/codec/ && \
       git apply /airplay2/ap2/alac/alac.patch && \
       sed "s/\(libalac\.\)dylib/\1so/g" -i /ALAC/codec/makefile && \
       make libalac.so && \
       cp /ALAC/codec/libalac.so /airplay2/ap2/alac/

RUN pip3 install -r /airplay2/requirements.txt

COPY docker/avahi-daemon.conf /etc/avahi/avahi-daemon.conf
COPY docker/start.sh /

RUN chmod +x /start.sh

CMD ["/start.sh"]
