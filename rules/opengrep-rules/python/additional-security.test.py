"""Annotated tests for python/additional-security.yaml."""
import subprocess

import yaml


def tainted(cmd, doc):
    # ruleid: scp.python.injection.subprocess-shell
    subprocess.run(cmd, shell=True)
    # ruleid: scp.python.injection.subprocess-shell
    subprocess.check_output(cmd, shell=True)
    # ruleid: scp.python.deserialization.unsafe-yaml-load
    yaml.unsafe_load(doc)
    # ruleid: scp.python.deserialization.unsafe-yaml-load
    yaml.load(doc, Loader=yaml.Loader)


def safe(cmd, doc):
    # ok: scp.python.injection.subprocess-shell
    subprocess.run(["echo", cmd], shell=False)
    # ok: scp.python.deserialization.unsafe-yaml-load
    yaml.safe_load(doc)
