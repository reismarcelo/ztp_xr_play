#! /usr/bin/env python3
import json
from flask import Flask, request


app = Flask('REST server test')


@app.route('/api', methods=['POST'])
def handle():
    print('POST request payload:\n{payload}'.format(payload=json.dumps(request.json, indent=2)))
    return "POST request processed successfully"


app.run(port=8080, host='0.0.0.0')
