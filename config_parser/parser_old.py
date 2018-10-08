from __future__ import print_function

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

START_CERT_TAG = '-----BEGIN CERTIFICATE-----'
END_CERT_TAG = '-----END CERTIFICATE-----'

stores = {}
orphanes = {}


class Cert(object):
    def __init__(self, subj, issuer, fingerprint):
        self.__subj = subj
        self.__issuer = issuer
        self.__fingerprint = fingerprint
        self.__children = []

    @property
    def fingerprint(self):
        return self.__fingerprint

    @property
    def issuer(self):
        return self.__issuer

    @property
    def subj(self):
        return self.__subj

    def add_child(self, child_cert):
        self.__children.append(child_cert)

    def exist_in_chain(self, fingerprint):
        for child in self.__children:
            if child.fingerprint == fingerprint:
                return True
            else:
                if child.exist_in_chain(fingerprint):
                    return True

    def is_self_signed(self):
        return self.__issuer == self.__subj

    def get_parent(self, issuer):
        if self.__subj == issuer:
            return self

        for child in self.__children:
            if child.subj == issuer:
                return child
            else:
                parent = child.get_parent(issuer)
                if parent:
                    return parent

        return None

    def get_str(self, indent=0):
        res = ['{}Cert({}, {}, {})\n'.format(' ' * indent, self.__subj, self.__issuer, self.__fingerprint)]
        for child in self.__children:
            res.append(child.get_str(indent + 2))
        return ''.join(res)

    def __str__(self):
        return self.get_str()

    def __repr__(self):
        return self.get_str()


with open('config.txt', 'r') as cfg:
    lines = cfg.readlines()

should_print = False
for line in lines:
    if line.startswith(START_CERT_TAG):
        should_print = True
        cert = []

    if should_print:
        cert.append(line.strip())

    if line.startswith(END_CERT_TAG):
        should_print = False
        pem_cert = x509.load_pem_x509_certificate(str.encode('\n'.join(cert)), default_backend())
        issuer = pem_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject = pem_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        fingerprint = int.from_bytes(pem_cert.fingerprint(hashes.SHA256()), byteorder='big', signed=False)
        c = Cert(subj=subject, issuer=issuer, fingerprint=fingerprint)

        if c.is_self_signed():
            if c.fingerprint not in stores:
                stores[c.fingerprint] = c
        else:
            for cert in stores.values():
                if cert.exist_in_chain(c.fingerprint):
                    break
                else:
                    parent = cert.get_parent(c.issuer)
                    if parent:
                        parent.add_child(c)
                        break
            else:
                if not orphanes:
                    orphanes[c.fingerprint] = c
                else:
                    for cert in orphanes.values():
                        if cert.exist_in_chain(c.fingerprint):
                            break
                        else:
                            parent = cert.get_parent(c.issuer)
                            if parent:
                                parent.add_child(c)
                                break
                    else:
                        orphanes[c.fingerprint] = c

print('Store:')
for cert in stores.values():
    print(cert.get_str())
print('=' * 80)

print('Orphanes:')
for cert in orphanes.values():
    print(cert.get_str())
print('=' * 80)
