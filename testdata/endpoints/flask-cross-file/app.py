from flask import Flask

from views.billing import billing_bp

app = Flask(__name__)
app.register_blueprint(billing_bp, url_prefix="/billing")
