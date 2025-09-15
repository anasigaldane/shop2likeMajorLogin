from wsgi import app
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return {"status": "ok", "message": "✅ Flask running on Vercel!"}
