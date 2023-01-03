#!/bin/bash

# This script is used to setup the dev development

echo "Installing dependencies..."

if [ ! -d "third_party" ]; then
    mkdir third_party
fi

cd third_party

# Install wolfSSL
if [ ! -d "wolfssl" ]; then
    git clone https://github.com/wolfSSL/wolfssl.git
    cd wolfssl
    ./autogen.sh
    make
    make check
    sudo make install
    cd ..
fi

cd ..

echo "Done!"
