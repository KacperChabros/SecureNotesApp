import os
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    user_id = os.getuid()
    return f"Hello from Flask + uWSGI + NGINX! user_id: {user_id}"

if __name__ == "__main__":
    app.run()

