import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    return requests.get(request.args["url"], verify=False).text
