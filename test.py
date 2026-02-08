
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1 style="color: green; text-align: center; margin-top: 100px;">
        HELLO! YE PAGE CHAL RAHA HAI
    </h1>
    <p style="text-align: center; font-size: 20px;">
        Agar yeh dikh raha hai to Flask sahi chal raha hai.<br>
        Ab problem templates ya file paths mein hai.
    </p>
    """

if __name__ == '__main__':
    from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1 style="color: green; text-align: center; margin-top: 100px;">
        HELLO! YE PAGE CHAL RAHA HAI
    </h1>
    <p style="text-align: center; font-size: 20px;">
        Agar yeh dikh raha hai to Flask sahi chal raha hai.<br>
        Ab problem templates ya file paths mein hai.
    </p>
    """

if __name__ == '__main__':
    app.run(debug=True, port=5003)