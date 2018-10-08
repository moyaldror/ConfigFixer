import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding


class Cert(object):
    def __init__(self, subj, issuer, x509_cert, name=''):
        self.__subj = hashlib.sha256(subj.encode(encoding='UTF-8', errors='strict')).hexdigest()
        self.__issuer = hashlib.sha256(issuer.encode(encoding='UTF-8', errors='strict')).hexdigest()
        self.__subject_name = subj
        self.__issuer_name = issuer
        self.__orig_cert = x509_cert
        self.__children = set()
        self.__name = name

    def generate_self_signed(self, name):
        ten_years = datetime.timedelta(3650, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(name))
        builder = builder.issuer_name(x509.Name(name))
        builder = builder.not_valid_before(datetime.datetime.today() - (ten_years // 2))
        builder = builder.not_valid_after(datetime.datetime.today() + (ten_years // 2))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(self.__subject_name)]),
                                        critical=False)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        self.__orig_cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    def is_self_signed(self):
        return self.__subject_name == self.__issuer_name

    @property
    def name(self):
        return self.__name

    @property
    def x509_cert(self):
        return self.__orig_cert

    @property
    def issuer(self):
        return self.__issuer

    @property
    def subj(self):
        return self.__subj

    @property
    def issuer_name(self):
        return self.__issuer_name

    @property
    def subj_name(self):
        return self.__subject_name

    @property
    def children(self):
        return self.__children

    def print_cert_tree(self, indent=0):
        print('%s s:"%s", i:"%s"' % (' ' * indent, self.subj_name, self.issuer_name))

        for child in self.children:
            child.print_cert_tree(indent=indent + 2)

    def add_child(self, cert):
        self.__children.add(cert)

    def is_cert_in_chain(self, cert):
        if cert is self or cert.subj == self.__subj:
            return True

        for child in self.__children:
            if child.is_cert_in_chain(cert):
                return True

        return False

    @staticmethod
    def get_cert_pem(cert):
        return cert.public_bytes(encoding=Encoding.PEM).decode('utf-8')

    @staticmethod
    def get_key_pem(key):
        return key.private_bytes(encoding=Encoding.PEM,
                                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                                 encryption_algorithm=serialization.BestAvailableEncryption(b'radware')).decode('utf-8')
