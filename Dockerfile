FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y \
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


# install apache perl_mod and test deps
RUN wget http://apache.mivzakim.net/perl/mod_perl-2.0.10.tar.gz && \
        tar xzvf mod_perl-2.0.10.tar.gz && cd mod_perl-2.0.10/ && \
        perl Makefile.PL && \
        make && make test && make install
#&& a2enmod perl

#RUN cpanm install Apache::Test



WORKDIR tmp
RUN git clone https://github.com/PerimeterX/mod_perimeterx.git
RUN cd mod_perimeterx && make
