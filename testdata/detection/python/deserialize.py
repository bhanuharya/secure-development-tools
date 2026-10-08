import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    data = pickle.loads(request.data)
    config = yaml.load(request.form["config"])
    return str(data) + str(config)
