from __future__ import print_function

import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from config_parser.cert import Cert
from config_parser.cert_store import CertificateStore


class DxParserTagEnums:
    START_CERT_TAG = '-----BEGIN CERTIFICATE-----'
    END_CERT_TAG = '-----END CERTIFICATE-----'
    START_KEY_TAG = '-----BEGIN.*PRIVATE KEY-----'
    END_KEY_TAG = '-----END.*PRIVATE KEY-----'
    START_CERT_IMPORT = 'import cert'
    START_INTERCERT_IMPORT = 'import intermca'
    START_TRUSTCERT_IMPORT = 'import trustca'
    START_KEY_IMPORT = 'import key'

    START_CERTS_IMPORT = (START_CERT_IMPORT, START_INTERCERT_IMPORT, START_TRUSTCERT_IMPORT)
    ALL_START_IMPORTS = (*START_CERTS_IMPORT, START_KEY_IMPORT)


import_regex = re.compile('{}|{}|{}|{}'.format(*DxParserTagEnums.ALL_START_IMPORTS))


def read_config_file(cfg_file):
    cert_store = CertificateStore()

    print(cfg_file)
    with open(cfg_file, 'r') as cfg:
        lines = cfg.readlines()

    should_add = False
    config_cert_name = None
    for line in lines:
        if not config_cert_name and line.startswith(DxParserTagEnums.START_CERTS_IMPORT):
            config_cert_name = import_regex.split(line)[1].split(' ')[1].strip('"')

        if line.startswith(DxParserTagEnums.START_CERT_TAG):
            should_add = True
            cert = []

        if should_add:
            cert.append(line.strip())

        if line.startswith(DxParserTagEnums.END_CERT_TAG):
            should_add = False
            pem_cert = x509.load_pem_x509_certificate(str.encode('\n'.join(cert)), default_backend())

            c = Cert(subj=pem_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                     issuer=pem_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                     x509_cert=pem_cert,
                     name=config_cert_name)

            cert_store.store_cert(cert=c, cert_name=config_cert_name)
            config_cert_name = None

    cert_store.generate_store()
    # cert_store.dump_certs()

    return cert_store, lines
