FROM ubuntu:15.04

MAINTAINER aviad@perimeterx.com

RUN apt-get update
RUN apt-get install -y --fix-missing\
        apache2 \
        apache2-dev \
        wget \
        build-essential \
        libcurl4-openssl-dev \
        libjansson-dev \
        libssl-dev \
        vim \
        git \
        pkg-config \
        silversearcher-ag \
        libjson0 \
        libjson0-dev \
        check

#RUN rm /etc/ld.so.cache && ldconfig

WORKDIR tmp
RUN git clone https://github.com/PerimeterX/mod_perimeterx.git
RUN cd mod_perimeterx && make

CMD ["bash"]
