FROM php:8.1-apache

# Install system dependencies and tools
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    unzip \
    libreoffice \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    imagemagick \
    poppler-utils \
    exiftool \
    libxml2-dev \
    libzip-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install zip xml soap

# Install vulnerable ImageMagick 6.9.3-10 from source
WORKDIR /tmp
# Copy ImageMagick tarball if available locally
COPY resources/ /tmp/resources/
RUN if [ -f /tmp/resources/ImageMagick-6.9.3-10.tar.xz ]; then \
    cp /tmp/resources/ImageMagick-6.9.3-10.tar.xz /tmp/; \
    elif [ ! -f ImageMagick-6.9.3-10.tar.xz ]; then \
    wget -q http://www.imagemagick.org/download/releases/ImageMagick-6.9.3-10.tar.xz || exit 0; \
    fi
RUN if [ -f ImageMagick-6.9.3-10.tar.xz ]; then \
    apt-get update && apt-get install -y build-essential xz-utils pkg-config libjpeg-dev libpng-dev libtiff-dev libxml2-dev && \
    tar xf ImageMagick-6.9.3-10.tar.xz && \
    cd ImageMagick-6.9.3-10 && \
    ./configure --prefix=/usr/local && \
    make && make install && \
    ldconfig && \
    rm -rf /tmp/ImageMagick-6.9.3-10*; \
    fi

# Remove ImageMagick policy.xml to allow dangerous operations
RUN rm -f /usr/local/etc/ImageMagick-6/policy.xml \
    /etc/ImageMagick-6/policy.xml \
    /etc/ImageMagick/policy.xml || true

# Install vulnerable Ghostscript 10.03.0 (CVE-2024-29510) from source
WORKDIR /tmp
RUN if [ -f /tmp/resources/ghostscript-10.03.0.tar.xz ]; then \
    cp /tmp/resources/ghostscript-10.03.0.tar.xz /tmp/; \
    elif [ ! -f ghostscript-10.03.0.tar.gz ] && [ ! -f ghostscript-10.03.0.tar.xz ]; then \
    wget -q https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs10030/ghostscript-10.03.0.tar.xz || \
    wget -q https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs10030/ghostscript-10.03.0.tar.gz || \
    (echo "Downloading from alternative source..." && \
     wget -q http://downloads.ghostscript.com/public/ghostscript-10.03.0.tar.xz || \
     wget -q http://downloads.ghostscript.com/public/ghostscript-10.03.0.tar.gz || \
     wget -q https://www.ghostscript.com/download/gsdnld/ghostscript-10.03.0.tar.xz || \
     wget -q https://www.ghostscript.com/download/gsdnld/ghostscript-10.03.0.tar.gz); \
    fi

RUN apt-get update && apt-get install -y \
    build-essential \
    xz-utils \
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libjbig2dec0-dev \
    libpaper-dev \
    zlib1g-dev \
    libx11-dev \
    libxt-dev \
    libxext-dev \
    && rm -rf /var/lib/apt/lists/*

RUN if [ -f ghostscript-10.03.0.tar.xz ]; then \
    tar xJf ghostscript-10.03.0.tar.xz || (apt-get update && apt-get install -y xz-utils && tar xJf ghostscript-10.03.0.tar.xz); \
    elif [ -f ghostscript-10.03.0.tar.gz ]; then \
    tar xzf ghostscript-10.03.0.tar.gz; \
    fi

RUN if [ -d ghostscript-10.03.0 ]; then \
    cd ghostscript-10.03.0 && \
    ./configure --prefix=/usr/local --disable-compile-inits --disable-hidden-visibility && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf ghostscript-10.03.0* ghostscript-10.03.0.tar.* /tmp/resources; \
    fi

RUN if ! command -v gs >/dev/null 2>&1; then \
    echo "Ghostscript build failed, installing from apt as fallback" && \
    apt-get update && apt-get install -y ghostscript; \
    fi

RUN gs --version || echo "Ghostscript version check failed"

# Configure Apache
RUN a2enmod rewrite
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Copy application
COPY render/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html
RUN mkdir -p /var/www/html/uploads && chown -R www-data:www-data /var/www/html/uploads && chmod 777 /var/www/html/uploads

# Expose port
EXPOSE 80

CMD ["apache2-foreground"]

