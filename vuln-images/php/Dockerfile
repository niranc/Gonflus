FROM php:7.4-apache

LABEL maintainer="gonflus-vuln-lab"

# Copy ImageMagick source archive
COPY resources/ImageMagick-6.9.3-10.tar.xz /tmp/imagemagick-src/

# Install build deps and compile a deliberately vulnerable ImageMagick (6.9.3-10, pre-ImageTragick patch)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        xz-utils \
        pkg-config \
        libjpeg-dev libpng-dev libtiff-dev libxml2-dev && \
    cd /tmp/imagemagick-src && \
    tar xf ImageMagick-6.9.3-10.tar.xz && \
    cd ImageMagick-6.9.3-10 && \
    ./configure --disable-shared --enable-static && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/imagemagick-src && \
    apt-get purge -y build-essential xz-utils pkg-config && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# LAB ONLY: relax ImageMagick security policy to make ImageTragick-style payloads effective
RUN rm -f /usr/local/etc/ImageMagick-6/policy.xml /etc/ImageMagick-6/policy.xml /etc/ImageMagick/policy.xml || true

RUN a2enmod rewrite

WORKDIR /var/www/html

COPY php/index.php /var/www/html/index.php
RUN mkdir -p /var/www/html/uploads && chown -R www-data:www-data /var/www/html/uploads

EXPOSE 80


