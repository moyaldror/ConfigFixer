import os
import re
import shutil
import tarfile

from config_fixer import fix_config

config_regex = re.compile(r'script start.*script end.*DO NOT EDIT THIS LINE!', re.DOTALL)


def parse_text_config(config_file, out_dir, out_file_name):
    fix_config(config_file=config_file, out_dir=out_dir, out_file_name=out_file_name)


def parse_archive_config(config_file, out_dir, out_file_name):
    pass


def parse_techdata_config(config_file, out_dir, out_file_name):
    def write_cfg_to_file(cfg_file_name, file):
        with open(cfg_file_name, 'w') as w:
            for cfg in config_regex.findall(b''.join(file.readlines()).decode('utf-8')):
                w.writelines(cfg)

    tar = tarfile.open(config_file, 'r:gz')
    files = []

    for name in tar.getnames():
        if name.find('tsdmp') >= 0:
            files.append((tar.extractfile(tar.getmember(name)), name.split('/')[-1]))

    if len(files) > 1:
        for file, name in files:
            out_directory = os.path.join(out_dir, 'vx') if name.find('vadc') < 0 else os.path.join(out_dir, 'vadc%s' % (
            re.findall(r'\d+', name)[0]))
            # print(out_directory)

            os.mkdir(out_directory)
            write_cfg_to_file(cfg_file_name=os.path.join(out_directory, name), file=file)
            fix_config(config_file=name, out_dir=out_directory, out_file_name=out_file_name)
            shutil.rmtree(out_directory)
    else:
        write_cfg_to_file(cfg_file_name=os.path.join(out_dir, files[0][1]), file=files[0][0])
        fix_config(config_file=config_file, out_dir=out_dir, out_file_name=out_file_name)


def get_config_parser(config_file):
    if not config_file.endswith('.tgz'):
        return CONFIG_PARSING_DISPATCHER['text']

    tar = tarfile.open(config_file, 'r:gz')
    return CONFIG_PARSING_DISPATCHER['techdata' if not 'altconfig.txt' in tar.getnames() else 'archive']


CONFIG_PARSING_DISPATCHER = {
    'text': parse_text_config,
    'archive': parse_archive_config,
    'techdata': parse_techdata_config
}

if __name__ == '__main__':
    tar = tarfile.open('techdata-vx-230913.tgz', 'r:gz')
    files = []

    for name in tar.getnames():
        if name.find('tsdmp') >= 0:
            files.append((tar.extractfile(tar.getmember(name)), name.split('/')[-1]))

    for file, name in files:
        out_directory = './vx' if name.find('vadc') < 0 else os.path.join('./',
                                                                          'vadc%s' % (re.findall(r'\d+', name)[0]))
        print(out_directory)
        os.mkdir(out_directory)
        with open(os.path.join(out_directory, name), 'w') as w:
            for cfg in config_regex.findall(b''.join(file.readlines()).decode('utf-8')):
                w.writelines(cfg)
        # fix_config(config_file=name, out_dir=out_dir, out_file_name=out_file_name)
        shutil.rmtree(out_directory)

    tar.close()
