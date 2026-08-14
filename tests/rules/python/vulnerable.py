import subprocess

import yaml


def run_user_command(command):
    return subprocess.run(command, shell=True, capture_output=True)


def parse_document(document):
    return yaml.unsafe_load(document)
