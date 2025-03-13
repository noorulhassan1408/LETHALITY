from flask import Flask, render_template, request
from scanner.scanner import scan_website

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    results = scan_website(url)
    return render_template('results.html', results=results)

@app.route('/advice')
def advice():
    return render_template('advice.html')

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)
