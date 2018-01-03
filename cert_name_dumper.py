# -*- coding: utf-8 -*-

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
import sys
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')
import json
import base64
import traceback

REJ_MSG = "rejTags"
SHLO_MSG = "shloTags"
CRT=u"CRT\xff"

for line in sys.stdin:
    jline = json.loads(line)
    try:
	if REJ_MSG in jline:
            if CRT in jline[REJ_MSG]:
                for cert in jline[REJ_MSG][CRT]:
                    names = []
                    x = x509.load_der_x509_certificate(base64.b64decode(cert), default_backend())
                    names.append(x.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
                    try:
                        ext = x.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        if ext:
                            names.extend(ext.value.get_values_for_type(x509.DNSName))
                    except:
                        pass
                    jline["common_names"] = names
                    break
        print json.dumps(jline)
    except Exception as E:
	traceback.print_exc(file=sys.stderr)
