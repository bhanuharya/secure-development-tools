import subprocess

import yaml


def run_fixed_command(filename):
    return subprocess.run(["sha256sum", filename], shell=False, capture_output=True)


def parse_document(document):
    return yaml.safe_load(document)
