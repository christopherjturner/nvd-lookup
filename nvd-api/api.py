from flask import Flask, request
import lookup


app = Flask(__name__)

@app.route("/vulns")
def search():
    group = request.args.get('group')
    artifact = request.args.get('artifact')
    version = request.args.get('version')
    result = lookup.run(group, artifact, version)
    return result