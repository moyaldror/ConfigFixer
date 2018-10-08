import hashlib
import os

from certificate_copycat import copycat_generator
from config_parser.cert import Cert


class CertificateStore(object):
    def __init__(self):
        self.__neighbor_mat = {}
        self.__nodes = {}
        self.__cert_stores = {}
        self.__final_store = {}
        self.__config_certs = {}
        self.__name_hashes = {}

    @property
    def neighbor_mat(self):
        return self.__neighbor_mat

    @property
    def nodes(self):
        return self.__nodes

    @property
    def cert_stores(self):
        return self.__cert_stores

    @property
    def final_store(self):
        return self.__final_store

    @property
    def config_certs(self):
        return self.__config_certs

    @property
    def name_hashes(self):
        return self.__name_hashes

    @staticmethod
    def compute_name_hash(cert):
        return hashlib.sha256(''.join([cert.subj, cert.issuer]).encode(encoding='UTF-8')).hexdigest()

    def get_cert_config_name(self, cert):
        try:
            return self.__config_certs[self.compute_name_hash(cert=cert)]
        except KeyError:
            return 'None'

    def __export_cert_tree(self, cert, output_dir, sign_key=None):
        pem_cert = copycat_generator.CertificateCopyCatGenerator(certificate=cert.x509_cert)
        pem_new_cert = pem_cert.get_copy(signing_key=sign_key)

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        with open('%s%s%s.pem' % (output_dir, os.path.sep, cert.subj_name.replace(' ', '_')), 'w') as cert_file:
            cert_file.writelines(Cert.get_key_pem(key=pem_new_cert.key))
            cert_file.writelines(Cert.get_cert_pem(cert=pem_new_cert.certificate))

        try:
            for cert_name in self.__name_hashes[CertificateStore.compute_name_hash(cert=cert)]:
                self.__config_certs[cert_name] = pem_new_cert
        except:
            pass

        for child in cert.children:
            self.__export_cert_tree(cert=child, output_dir=output_dir, sign_key=pem_new_cert.key)

    def __build_store(self, cert, indent=0):
        for neighbor in self.__neighbor_mat[cert.subj]:
            if not cert.is_cert_in_chain(cert=self.__nodes[neighbor]):
                cert.add_child(self.__nodes[neighbor])

            # print('%s s:"%s", i:"%s"' % (' ' * indent, self.__nodes[neighbor].subj_name,
            #                              self.__nodes[neighbor].issuer_name))
            self.__build_store(cert=self.__nodes[neighbor], indent=indent + 2)

    def generate_store(self):
        for node in self.__nodes.values():
            if node.issuer in self.__neighbor_mat and node.issuer != node.subj:
                self.__neighbor_mat[node.issuer].add(node.subj)

        for node_subj, neighbors in self.__neighbor_mat.items():
            if self.__nodes[node_subj].is_self_signed():
                self.__cert_stores[node_subj] = self.__nodes[node_subj]
                self.__build_store(cert=self.__nodes[node_subj])
            else:
                self.__build_store(cert=self.__nodes[node_subj])

        for cert in self.__nodes.values():
            for store in self.__cert_stores.values():
                if store.is_cert_in_chain(cert):
                    break
            else:
                self.__cert_stores[cert.subj_name] = cert

        for store in self.__cert_stores.values():
            if store.is_self_signed():
                self.__final_store[store.subj_name] = store
            else:
                if len(store.children) > 0:
                    c = Cert(subj=store.issuer_name, issuer=store.issuer_name, x509_cert=None)
                    c.generate_self_signed(name=store.x509_cert.issuer)
                    c.add_child(store)
                    self.__final_store[c.subj_name] = c

                    # for cert in self.__nodes.values():
                    #     for store in self.__final_store.values():
                    #         if store.is_cert_in_chain(cert):
                    #             break
                    #     else:
                    #         print('Orpahnd s:"%s", i:"%s"' % (cert.subj_name, cert.issuer_name))

    def dump_certs(self, certs_dest_dir):
        for store in self.__final_store.values():
            store.print_cert_tree()
            self.__export_cert_tree(cert=store, output_dir=certs_dest_dir)

    def store_cert(self, cert, cert_name):
        if cert.subj not in self.__neighbor_mat:
            self.__neighbor_mat[cert.subj] = set()

        if cert.issuer in self.__neighbor_mat and cert.issuer != cert.subj:
            self.__neighbor_mat[cert.issuer].add(cert.subj)

        if cert.subj not in self.__nodes:
            self.__nodes[cert.subj] = cert

        name_hash = CertificateStore.compute_name_hash(cert=cert)

        if name_hash in self.__name_hashes:
            self.__name_hashes[name_hash].append(cert_name)
        else:
            self.__name_hashes[name_hash] = [cert_name]

            self.__config_certs[cert_name] = None
