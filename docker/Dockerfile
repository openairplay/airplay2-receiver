FROM debian:stable-slim

RUN apt-get update -yy && \
    apt-get install -yy \
        pkg-config \ 
        avahi-daemon \
        avahi-discover \
        avahi-utils \
        libnss-mdns \
        dnsutils \
        python3 \
        python3-pip \
        python3-pyaudio \
        libffi-dev \
        alsa-utils \
        libavformat-dev \
        libavcodec-dev \
        libavdevice-dev \
        libavutil-dev \
        libavfilter-dev \
        libswscale-dev \
        libswresample-dev \
        libasound2-dev

WORKDIR /airplay2

COPY ./ap2-receiver.py ./ap2-receiver.py
COPY ./ap2 ./ap2

COPY ./requirements.txt ./requirements.txt
RUN pip3 install -r ./requirements.txt

COPY ./docker/avahi-daemon.conf /etc/avahi/avahi-daemon.conf
COPY ./docker/start.sh /

RUN chmod +x /start.sh

CMD ["/start.sh"]