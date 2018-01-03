#!/bin/env python2

# usage: cat chrome_certs/common_cert_set_2* | python gen_common_certs.py
# usage: cat chrome_certs/common_cert_set_3* | python gen_common_certs.py

import re
import sys

cert_set_n = int(sys.argv[1])

data = ""
for line in sys.stdin:
    data += line

# remove all comments
data = re.sub("/\*(?:(?!\*/).)+..", "", data, flags=re.MULTILINE|re.DOTALL)

# remove all includes
data = re.sub("#include.+", "", data)

# remove all if 0
data = re.sub("#if 0(.*?)#endif", "", data, flags=re.MULTILINE|re.DOTALL)

# remove lines stating the amount of certs
data = re.sub("static const size_t kNumCerts.+", "", data)

#remove lines including cert lens
data = re.sub("static const size_t kLens[^}]+};", "", data, flags=re.MULTILINE|re.DOTALL)


# build the set of certs
data = re.sub("static const unsigned char\* const kCerts\[\] = {", "CertSet{0} = [".format(cert_set_n), data)
data = re.sub("};", "]", data, count=1)

#handle the hash
data = re.sub("static const uint64_t kHash = UINT64_C\(([^)]+)\);", "CertSet{0}Hash = \\1".format(cert_set_n), data)

# transform the certs to pythonic stuff
data = re.sub("static const unsigned char kDERCert([0-9]+)\[\] = {.", "kDERCert\\1 = \"", data, flags=re.DOTALL)
data = re.sub(" *0x([0-9a-f][0-9a-f]),.", "\\x\\1", data, flags=re.DOTALL)
data = re.sub("};", "\"", data)


# now we need to reorder some things
# we need to put everything up to the first cert after the last cert
pos = re.search("kDERCert[0-9]+ = ", data)
pos = pos.start()

data = data[pos:] + data [:pos]


print data
