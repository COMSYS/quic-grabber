#!/bin/bash

mkdir chrome_certs
pushd chrome_certs
wget https://chromium.googlesource.com/chromium/src/+archive/master/net/quic/core/crypto.tar.gz
tar xf crypto.tar.gz
popd

cat chrome_certs/common_cert_set_2* | python gen_common_certs.py 2 > cert_set2.py
cat chrome_certs/common_cert_set_3* | python gen_common_certs.py 3 > cert_set3.py

