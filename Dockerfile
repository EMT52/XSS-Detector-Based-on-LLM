# linux/amd64: the archived browser and PHP extension are validated on x86-64.
ARG UBUNTU_MIRROR=
FROM ubuntu:22.04@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb AS build
ARG UBUNTU_MIRROR
ENV DEBIAN_FRONTEND=noninteractive
RUN if [ -n "$UBUNTU_MIRROR" ]; then sed -i "s#http://archive.ubuntu.com/ubuntu#$UBUNTU_MIRROR#g; s#http://security.ubuntu.com/ubuntu#$UBUNTU_MIRROR#g" /etc/apt/sources.list; fi \
    && apt-get update && apt-get install -y --no-install-recommends \
    apache2 apache2-dev autoconf bison build-essential ca-certificates curl \
    libbz2-dev libffi-dev liblzma-dev libreadline-dev libsqlite3-dev \
    libssl-dev pkg-config python3 unzip xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY docker/sources.lock.json docker/fetch_sources.py /build/
COPY docker/vendor/ /build/vendor/
RUN python3 /build/fetch_sources.py /build/sources.lock.json /build/downloads /build/vendor/downloads
COPY docker/build-runtimes.sh /build/
ARG PHP_FLAVOR=standard
RUN PHP_FLAVOR="$PHP_FLAVOR" bash /build/build-runtimes.sh

FROM ubuntu:22.04@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb
ARG UBUNTU_MIRROR
ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 \
    PATH=/opt/python/bin:/opt/php7/bin:/usr/lib/jvm/java-11-openjdk-amd64/bin:$PATH \
    PHP7=/opt/php7/bin/php PYTHON=/opt/python/bin/python3 \
    HOME=/home/xss \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    XSS_ROOT=/workspace/XSS \
    XSS_NEO4J_CONFIG=/run/xss/neo4j.json \
    XSS_NEO4J_AUTH=/opt/neo4j/data/dbms/auth.ini \
    XSS_NEO4J_PASSWORD=1 \
    JAVA_HEAP=2G
RUN if [ -n "$UBUNTU_MIRROR" ]; then sed -i "s#http://archive.ubuntu.com/ubuntu#$UBUNTU_MIRROR#g; s#http://security.ubuntu.com/ubuntu#$UBUNTU_MIRROR#g" /etc/apt/sources.list; fi \
    && apt-get update && apt-get install -y --no-install-recommends \
    apache2 ca-certificates curl libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libatspi2.0-0 libbz2-1.0 libcups2 libdbus-1-3 libdrm2 libexpat1 libffi8 \
    libgbm1 libglib2.0-0 libgtk-3-0 liblzma5 libnss3 libreadline8 libsqlite3-0 \
    libssl3 libuuid1 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 \
    libxfixes3 libxkbcommon0 libxrandr2 fonts-liberation openjdk-11-jdk-headless \
    procps util-linux zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 xss && useradd --uid 1000 --gid xss --create-home xss
COPY --from=build /opt/python /opt/python
COPY --from=build /opt/php7 /opt/php7
COPY --from=build /opt/neo4j /opt/neo4j
COPY --from=build /opt/chrome /opt/chrome
COPY --from=build /usr/lib/apache2/modules/libphp7.so /usr/lib/apache2/modules/libphp7.so
COPY --from=build /usr/local/bin/chromedriver/ /usr/local/bin/chromedriver/
COPY --from=build /build/php-flavor /usr/local/share/xss/php-flavor
COPY docker/requirements.lock /usr/local/share/xss/requirements.lock
RUN python3 -m pip install --no-cache-dir pip==23.0.1 setuptools==65.5.0 wheel==0.45.1 \
    && python3 -m pip install --no-cache-dir -r /usr/local/share/xss/requirements.lock \
    && python3 -m pip check
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
RUN a2dismod mpm_event && a2enmod mpm_prefork rewrite \
    && printf 'LoadModule php7_module /usr/lib/apache2/modules/libphp7.so\n' > /etc/apache2/mods-available/php7.load \
    && a2enmod php7 && printf 'ServerName localhost\n' > /etc/apache2/conf-available/xss.conf \
    && a2enconf xss && rm -f /var/www/html/index.html
COPY docker/bootstrap.py docker/xss docker/smoke.py /usr/local/lib/xss/
RUN ln -s /usr/local/lib/xss/xss /usr/local/bin/xss && chmod +x /usr/local/lib/xss/xss
WORKDIR /workspace/XSS
RUN chown -R xss:xss /opt/neo4j /workspace/XSS \
    && dpkg-query -W > /usr/local/share/xss/os-packages.txt \
    && python3 -m pip freeze > /usr/local/share/xss/python-packages.txt
ENV XSS_WEB_ROOT=/workspace/XSS/.docker-state/www XSS_CONTAINER=1
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD curl --fail --silent http://127.0.0.1/__xss_health.php || exit 1
ENTRYPOINT ["python3", "/usr/local/lib/xss/bootstrap.py"]
CMD ["serve"]
