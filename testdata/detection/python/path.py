import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    with open(os.path.join("/data/reports", request.args["file"])) as handle:
        return handle.read()
