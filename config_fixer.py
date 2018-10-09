import os
import re
import shutil
import tarfile

from config_parser.cert import Cert
from config_parser.parser import DxParserTagEnums, read_config_file

import_regex = re.compile('{}|{}|{}|{}'.format(*DxParserTagEnums.ALL_START_IMPORTS))

new_config_name = 'altconfig.txt'


def create_tgzfile(output_dir, output_filename, source_dir, item_list):
    cwd = os.getcwd()
    os.chdir(source_dir)
    tgz_file_name = '%s.tar.gz' % output_filename

    with tarfile.open(os.path.join(output_dir, tgz_file_name), 'w:gz') as tar:
        for name in item_list:
            tar.add(name)

    os.chdir(cwd)
    return os.path.abspath(tgz_file_name)


def write_new_config_file(new_cfg_file, cert_dir, orig_cfg_content, cert_store):
    with open(new_cfg_file, 'w') as new_conf:
        should_print = True
        should_add = False

        config_cert_name = None
        cert = []

        cert_store.dump_certs(certs_dest_dir=cert_dir)

        for line in orig_cfg_content:
            if not config_cert_name and line.startswith(DxParserTagEnums.ALL_START_IMPORTS):
                config_cert_name = import_regex.split(line)[1].split(' ')[1].strip('"')

            if line.startswith(DxParserTagEnums.START_CERT_TAG) or re.match(DxParserTagEnums.START_KEY_TAG, line):
                should_print = False
                should_add = True
                cert = []

            if should_print:
                new_conf.writelines(line)

            if should_add:
                cert.append(line.strip())

            if line.startswith(DxParserTagEnums.END_CERT_TAG) or re.match(DxParserTagEnums.END_KEY_TAG, line):
                should_print = True
                should_add = False

                if cert_store.config_certs[config_cert_name]:
                    new_conf.writelines(Cert.get_cert_pem(cert=cert_store.config_certs[config_cert_name].certificate)
                                        if not re.match(DxParserTagEnums.END_KEY_TAG, line)
                                        else Cert.get_key_pem(key=cert_store.config_certs[config_cert_name].key))
                else:
                    new_conf.writelines(os.linesep.join(cert))
                    new_conf.writelines(os.linesep)

                config_cert_name = None


def fix_config(config_file='config.txt', out_dir='./', out_file_name=''):
    cert_store, content = read_config_file(cfg_file=config_file)
    os.mkdir(os.path.abspath(os.path.join(out_dir, out_file_name)))
    write_new_config_file(new_cfg_file=os.path.abspath(os.path.join(out_dir, out_file_name, new_config_name)),
                          cert_dir=os.path.abspath(os.path.join(out_dir, out_file_name, 'certs')),
                          orig_cfg_content=content,
                          cert_store=cert_store)

    tgz_file = create_tgzfile(output_dir=os.path.abspath(out_dir),
                              output_filename=out_file_name,
                              source_dir=os.path.abspath(os.path.join(out_dir, out_file_name)),
                              item_list=['certs', new_config_name])

    shutil.rmtree(os.path.abspath(os.path.join(out_dir, out_file_name)))

    return tgz_file
