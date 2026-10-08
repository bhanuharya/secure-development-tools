import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args.get("host"))
    return subprocess.check_output("nslookup " + request.args.get("host"), shell=True)
