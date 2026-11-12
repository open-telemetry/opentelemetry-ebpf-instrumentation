#!/bin/sh
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
set -eu

# The official image's shared libpython is the default runtime; the other
# builds compile CPython from source into /opt/exception-python.
if [ "$PYTHON_EXCEPTION_BUILD" = shared ]; then
    exit 0
fi
apt-get update
apt-get install -y --no-install-recommends build-essential curl ca-certificates libssl-dev zlib1g-dev libffi-dev libbz2-dev liblzma-dev
curl --fail --location "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" -o /tmp/python.tgz
mkdir /tmp/python-source
tar -xzf /tmp/python.tgz --strip-components=1 -C /tmp/python-source
cd /tmp/python-source
case "$PYTHON_EXCEPTION_BUILD" in
    static) options="--disable-shared --without-lto" ;;
    lto) options="--enable-shared --with-lto" ;;
    free-threaded) options="--enable-shared --disable-gil" ;;
    *) echo "unknown Python build: $PYTHON_EXCEPTION_BUILD" >&2; exit 1 ;;
esac
./configure --prefix=/opt/exception-python --with-ensurepip=install $options
make -j2
make install
printf '/opt/exception-python/lib\n' > /etc/ld.so.conf.d/exception-python.conf
ldconfig
rm -rf /tmp/python-source /tmp/python.tgz /var/lib/apt/lists/*
