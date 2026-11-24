#!/usr/bin/env bash
set -euo pipefail
cd /build
mkdir -p python-src php-src ast-src /opt/php7/etc/conf.d /opt/chrome /usr/local/bin/chromedriver
tar -xJf downloads/python -C python-src --strip-components=1
cd python-src
./configure --prefix=/opt/python --with-ensurepip=install
make -j2
make install
ln -s python3 /opt/python/bin/python
cd /build
case "${PHP_FLAVOR:-standard}" in
    standard) tar -xJf downloads/php -C php-src --strip-components=1 ;;
    instrumented)
        test -f vendor/php-instrumented.tar.gz || {
            echo 'Missing docker/vendor/php-instrumented.tar.gz; provide the real instrumented PHP 7.0 source.' >&2
            exit 1
        }
        tar -xzf vendor/php-instrumented.tar.gz -C php-src --strip-components=1
        ;;
    *) echo 'PHP_FLAVOR must be standard or instrumented' >&2; exit 1 ;;
esac
cd php-src
# PHP 7.0 predates GCC's -fno-common default.
./configure CFLAGS='-O2 -fcommon' --prefix=/opt/php7 \
    --with-config-file-path=/opt/php7/etc --with-config-file-scan-dir=/opt/php7/etc/conf.d \
    --with-apxs2=/usr/bin/apxs --disable-all --without-pear \
    --enable-cli --enable-ctype --enable-filter --enable-hash --enable-json \
    --enable-session --enable-tokenizer --enable-posix --with-pcre-regex
make -j2
make install
cp php.ini-development /opt/php7/etc/php.ini
cd /build
tar -xzf downloads/php_ast -C ast-src --strip-components=1
cd ast-src
/opt/php7/bin/phpize
./configure --with-php-config=/opt/php7/bin/php-config
make -j2
make install
printf 'extension=ast.so\n' > /opt/php7/etc/conf.d/20-ast.ini
/opt/php7/bin/php -r 'if (PHP_MAJOR_VERSION !== 7 || PHP_MINOR_VERSION !== 0 || phpversion("ast") !== "0.1.4") exit(1); ast\parse_code("<?php echo 1;", 30);'
cd /build
tar -xzf downloads/neo4j -C /opt
mv /opt/neo4j-community-4.4.37 /opt/neo4j
unzip -q downloads/chrome -d /build/chrome-unpacked
cp -a chrome-unpacked/chrome-linux64/. /opt/chrome/
unzip -q downloads/chromedriver -d /build/driver-unpacked
cp -a driver-unpacked/chromedriver-linux64/. /usr/local/bin/chromedriver/
printf '%s\n' "${PHP_FLAVOR:-standard}" > /build/php-flavor
