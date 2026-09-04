"""Annotated tests for python/security.yaml."""
import hashlib
import os
import pickle
import subprocess


def tainted(user_input):
    # ruleid: scp.python.exec.eval
    eval(user_input)
    # ruleid: scp.python.exec.eval
    exec(user_input)
    # ruleid: scp.python.crypto.weak-md5
    hashlib.md5(b"x").hexdigest()
    # ruleid: scp.python.crypto.weak-md5
    hashlib.sha1(b"x").hexdigest()
    # ruleid: scp.python.deserialization.pickle
    pickle.loads(user_input)
    # ruleid: scp.python.injection.command
    os.system("echo " + user_input)
    # ruleid: scp.python.injection.command
    subprocess.call("ls " + user_input, shell=True)


def safe(data):
    # ok: scp.python.exec.eval
    compile(data, "<s>", "eval")
    # ok: scp.python.crypto.weak-md5
    hashlib.sha256(b"x").hexdigest()
    # ok: scp.python.injection.command
    subprocess.run(["ls", data], shell=False)
