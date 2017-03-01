FROM ubuntu:16.04

MAINTAINER aviad@perimeterx.com

RUN apt-get update
RUN apt-get install -y \
        make \
        automake \
        autoconf \
        libtool \
        pkg-config \
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
        libperl-dev \
        libgdm-dev \
        cpanminus

RUN rm /etc/ld.so.cache && ldconfig

# Install apache perl_mod and test deps
RUN wget http://apache.mivzakim.net/perl/mod_perl-2.0.10.tar.gz && \
        tar xzvf mod_perl-2.0.10.tar.gz && cd mod_perl-2.0.10/ && \
        perl Makefile.PL && \
        make && make test && make install
#&& a2enmod perl

WORKDIR tmp
COPY . /tmp/mod_perimeterx
RUN cd mod_perimeterx && ./autogen.sh && ./configure && make && make install
