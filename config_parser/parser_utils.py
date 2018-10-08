import tarfile


def parse_text_config():
    pass


def parse_archive_config():
    pass


def parse_techdata_config():
    pass


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
