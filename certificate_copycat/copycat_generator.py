from __future__ import print_function

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding

from certificate_copycat.copycat_result import CertificateCopyCatResult


class CertificateCopyCatGenerator(object):
    _simple_members = ['serial_number', 'not_valid_before', 'not_valid_after', ]
    _tuple_members = [('issuer', 'issuer_name'), ('subject', 'subject_name'), ]

    def __init__(self, certificate):
        self._old_cert = certificate
        self._builder = x509.CertificateBuilder()

    def _get_member_simple(self, old_cert_member_name, builder_member_name):
        return getattr(self._builder, builder_member_name)(getattr(self._old_cert, old_cert_member_name))

    def _get_extensions(self):
        return (ext for ext in self._old_cert.extensions)

    def _get_private_key(self):
        private_key = None
        pub_key = getattr(self._old_cert, 'public_key')

        if isinstance(pub_key(), RSAPublicKey):
            private_key = rsa.generate_private_key(public_exponent=pub_key().public_numbers().e,
                                                   key_size=pub_key().key_size,
                                                   backend=default_backend())
        elif isinstance(pub_key(), EllipticCurvePublicKey):
            private_key = ec.generate_private_key(curve=pub_key().curve, backend=default_backend())

        return private_key

    def _get_sign_algorithm(self):
        return getattr(self._old_cert, 'signature_hash_algorithm')

    def get_copy(self, signing_key=None):
        for member in self._simple_members:
            self._builder = self._get_member_simple(old_cert_member_name=member, builder_member_name=member)

        for old_cert_member_name, builder_member_name in self._tuple_members:
            self._builder = self._get_member_simple(old_cert_member_name=old_cert_member_name,
                                                    builder_member_name=builder_member_name)

        for extension in self._get_extensions():
            if not isinstance(extension.value, x509.AuthorityKeyIdentifier) and \
                    not isinstance(extension.value, x509.SubjectKeyIdentifier):
                self._builder = self._builder.add_extension(extension.value, extension.critical)

        priv_key = self._get_private_key()
        signing_key = priv_key if signing_key is None else signing_key
        public_key = priv_key.public_key()

        self._builder = self._builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False)

        self._builder = self._builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), False)

        self._builder = self._builder.public_key(public_key)
        return CertificateCopyCatResult(
            certificate=self._builder.sign(private_key=signing_key, algorithm=self._get_sign_algorithm(),
                                           backend=default_backend()),
            key=priv_key
        )


if __name__ == '__main__':
    pem_data = \
        ['-----BEGIN CERTIFICATE-----',
         'MIIFATCCA+mgAwIBAgISAwmW808bEhLIwbhFBlV6AhRiMA0GCSqGSIb3DQEBCwUA',
         'MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD',
         'ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODAxMTgwOTMxMjdaFw0x',
         'ODA0MTgwOTMxMjdaMBoxGDAWBgNVBAMTD2NyeXB0b2dyYXBoeS5pbzCCASIwDQYJ',
         'KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7ibxJo/yM4tSmcho1bdD/bsFIeHAra',
         'EzgNO/Yh73PBITa6K7z2BKWVDGifvMJulIeoW38UhXz93l26j6TO9DecN8dhjlRW',
         'wBarxuLngr76s7UrZDElgFwhb0sKYLyuzRk1A7YfLh4eiIh3QK4/7PXiA/nizFku',
         'uPITF9c148h/sHx0ApJdeeJ9YhV4AszQub81QxQJ5Q86Clgc3EEUk0OpI+kxw3QG',
         'aYxyeY3/SqI//6tL9E41qWn8mhTkCnQY2sRvVsUxHkLU0rPKNexL0J/w2FyCWaLO',
         'Ak4EpH/XK/5k1ke+dm+/RCH7zUxi7Sj19bSWMg1Edft8oqTu/Ii/F+8CAwEAAaOC',
         'Ag8wggILMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB',
         'BQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUp9upL+999JeJXkKizzC0NanU',
         'I9cwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUHAQEE',
         'YzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5cHQu',
         'b3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQu',
         'b3JnLzAaBgNVHREEEzARgg9jcnlwdG9ncmFwaHkuaW8wgf4GA1UdIASB9jCB8zAI',
         'BgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8v',
         'Y3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRp',
         'ZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGll',
         'cyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBv',
         'bGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5',
         'LzANBgkqhkiG9w0BAQsFAAOCAQEATpXy+ry7zALqjPKbmcNMi6yDtUvH27+GPR/X',
         'nX9We0slfdqSJHS7y+pYhN0LfGwCdtvdzYWACC7YePK22in2KtQz1BqL8ZFG6Dwl',
         '9E1mM/TM0+Itoz+SpNuTpVFnu/R8c35MCMPzCrEaGM5Xd7HQ/g7HNYXMGpbrPLtF',
         'xzgjbae1YsrjZxm4rORXIPYsLz7mf1gtZBzLXtjuhPNU4Gc/8n3f8MTAPDl1eK7l',
         'pWzl2c9MYnFXND9bday6WHmd15WPPpI1x9HN5zO0Aj21N+Z4m9F4i/JYhPYtXSiL',
         'jy4lVFtJ8mGn6QB5c/6rFWB63mPYcbcVfnOudi4ynjllvdoRuA==',
         '-----END CERTIFICATE-----']

    der_data = b'0\x82\x05\x010\x82\x03\xe9\xa0\x03\x02\x01\x02\x02\x12\x03\t\x96\xf3O\x1b\x12\x12\xc8\xc1\xb8E\x06Uz' \
               b'\x02\x14b0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000J1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x160\x14' \
               b'\x06\x03U\x04\n\x13\rLet\'s Encrypt1#0!\x06\x03U\x04\x03\x13\x1aLet\'s Encrypt Authority X30\x1e\x17' \
               b'\r180118093127Z\x17\r180418093127Z0\x1a1\x180\x16\x06\x03U\x04\x03\x13\x0fcryptography.io0\x82\x01"0' \
               b'\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xd5' \
               b'\xca\n\xd7\x9a\'\xa6\xd5\xb4\xc6\xfbh&\xf0Zl7.\x13v\t\xae\x84:\xc3%\xea>a\xf1\xeefb\xf7\x0eb\xd1\xbc' \
               b'\xfcl\x9bw\xfd\xde\x96r\xff\x10\x88\xe0|\xf5U\xc1\xfd\x8d{\x97\xf5\x9e\xcaQN\x93\xdf\x95b\xacx\x839|' \
               b'\x88&j\x9e(M\xefIt\x9c|\xe5CL\xd7\x8fo[\xec\x1b9\xb7\xdai\xa3\x952M\x89\xd6&\x8ak\xa3k\x90\xbc\xcc' \
               b'\xde\xbe\xc73Q\xab\x81\xf1\x94\xac_7\xe6glts\x8b\xa2\x81\xfa\x81\xaadI\x1d\x83X-\x9cT\xca\xc6p\x1e' \
               b'\x7f]\xa1\x0cas\xf3S\xe8\xf1\xcb\x9e\xbf\xdb\x9bK]"\xf8\x0bRJd\xf1\xdd\x88\xd3\x9b@\x17{+@\xe34\xa6' \
               b'\xe6\xa5R\x1a\x00-\x1em\xe0Z}:\'\x9c\x84\x81\x06\xc8^SEj\xa7\x18*G\'\xfa\x8d)\xf8\xdc0\x88\xf6\x8a' \
               b'\x11\x81`\x93k\x8c\x84H\xf3\xc8\xe0\xeclV\xe8\xae:\xd7\x17\'\xfdh\xc8\x80sk*\x00\xcdHuD\xc7\xb2\xffj' \
               b'\x8e\xb3I\x02\x03\x01\x00\x01\xa3\x82\x02\x0f0\x82\x02\x0b0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04' \
               b'\x03\x02\x05\xa00\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x08+\x06' \
               b'\x01\x05\x05\x07\x03\x020\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x1d\x06\x03U\x1d\x0e\x04\x16' \
               b'\x04\x14\xa7\xdb\xa9/\xef}\xf4\x97\x89^B\xa2\xcf0\xb45\xa9\xd4#\xd70\x1f\x06\x03U\x1d#\x04\x180\x16' \
               b'\x80\x14\xa8Jjc\x04}\xdd\xba\xe6\xd19\xb7\xa6Ee\xef\xf3\xa8\xec\xa10o\x06\x08+\x06\x01\x05\x05\x07' \
               b'\x01\x01\x04c0a0.\x06\x08+\x06\x01\x05\x05\x070\x01\x86"http://ocsp.int-x3.letsencrypt.org0/\x06\x08+' \
               b'\x06\x01\x05\x05\x070\x02\x86#http://cert.int-x3.letsencrypt.org/0\x1a\x06\x03U\x1d\x11\x04\x130\x11' \
               b'\x82\x0fcryptography.io0\x81\xfe\x06\x03U\x1d \x04\x81\xf60\x81\xf30\x08\x06\x06g\x81\x0c\x01\x02' \
               b'\x010\x81\xe6\x06\x0b+\x06\x01\x04\x01\x82\xdf\x13\x01\x01\x010\x81\xd60&\x06\x08+\x06\x01\x05\x05' \
               b'\x07\x02\x01\x16\x1ahttp://cps.letsencrypt.org0\x81\xab\x06\x08+\x06\x01\x05\x05\x07\x02\x020\x81\x9e' \
               b'\x0c\x81\x9bThis Certificate may only be relied upon by Relying Parties and only in accordance with ' \
               b'the Certificate Policy found at https://letsencrypt.org/repository/0\r\x06\t*\x86H\x86\xf7\r\x01\x01' \
               b'\x0b\x05\x00\x03\x82\x01\x01\x00uxN\xda$,\xd7<\xae\x94S02\xef\xff24_\xc4J\xdaj\xcav\x98O%{\xb1\x98Qv' \
               b'\xe3\x1a\x8a\xc7\xb3\x16 \xf0\t\xb6\xa7E\xc0$!\xb4\xe7\xc4\xb0\x1c\x19q\xb6ne\xf2\xf9)\xe4\x08u@\xd3' \
               b'\xe5\xe1\xe7!\xa9~\ndR+c\xcb@G\xc9e\xec\xef\x8f\xf8\x83;\xe1\xdd\xa5\x1e\xb1\xe37$\x08g\xb1<\x90\xc9' \
               b'\x07|\xe5F%QB\x8c{U\xdb@\x8c;U\x82\xe1x\xec\xf4\xaf\x839\xca\xa8-4I\xa1\xdb\x9d%^c\x10\x84\xb5\xe6' \
               b'\xac\xb3DR)\x80s\x10\xf0|\xd7\xe5\xce\xf1\xc2\xf5L\xe9%\x8e2`\xbdZ~\xd2\xb1E\xc8\x8eor\xad\x8f\x1d' \
               b'\xc0i\xfd\xba\xa5\xb4\xde\xcf-\x90W.y\xdd\xb9\x93\xa6\x8f\\]\xf3_\xd7\x19\xc9j\xdbiw9\xb6Be\x0f\x00' \
               b'\x0f\x05\x8fc\x93\xc7k,D)>\xce\xc0\xe4\xcaG\xa2\xebw\xa5" \xa5\xde\xf0\xa6u\xa6e7 \xdb\xc0I\x0b\x1eHg' \
               b'\xef\x02\xeaM\xef1\x8c\x8b\xbc'

    # test using pem certificate
    pem_cert = x509.load_pem_x509_certificate(str.encode('\n'.join(pem_data)), default_backend())
    pem_cert = CertificateCopyCatGenerator(certificate=pem_cert)
    pem_new_cert = pem_cert.get_copy()
    print(pem_new_cert.key.private_bytes(encoding=Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.BestAvailableEncryption(b'radware')).decode(
        'utf-8'))
    print(pem_new_cert.certificate.public_bytes(encoding=Encoding.PEM).decode('utf-8'))

    # test using der certificate
    der_cert = x509.load_der_x509_certificate(der_data, default_backend())
    der_ccert = CertificateCopyCatGenerator(certificate=der_cert)
    der_new_cert = der_ccert.get_copy()
    print(der_new_cert.key.private_bytes(encoding=Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption()).decode('utf-8'))
    print(der_new_cert.certificate.public_bytes(encoding=Encoding.PEM).decode('utf-8'))
