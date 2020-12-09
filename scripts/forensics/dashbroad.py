import dash
import dash_table
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output

import requests
import json

latest_round = -1

headers = {'content-type': 'application/json'}
get_latest_round_payload = {
    "method": "forensic_get_latest_round",
    "params": [],
    "jsonrpc": "2.0",
    "id": 0,
}

def get_qcs_from_rpc(url = "http://127.0.0.1:8080"):
    global latest_round

    response = requests.post(url, data=json.dumps(get_latest_round_payload), headers=headers).json()

    new_latest_round = response["result"]

    ret = []
    for r in range(max(latest_round, new_latest_round-20)+1, new_latest_round+1):
        payload = {
                "method": "forensic_get_quorum_cert_at_round",
                "params": [r],
                "jsonrpc": "2.0",
                "id": 0,
                }
        response = requests.post(url, data=json.dumps(payload), headers=headers).json()
        if len(response["result"])==0:
            break
        qc = response["result"][0]["qc"]
        # check round number
        if qc["vote_data"]["proposed"]["round"] == r:
            ret.append({"round":r, "hash": qc["vote_data"]["proposed"]["id"][:6]+" is_nil="+str(response["result"][0]["is_nil"])})

    latest_round = new_latest_round
    return ret

app = dash.Dash(__name__)

app.layout = html.Div([
    dash_table.DataTable(
        id='table',
        columns=[{"name": i, "id": i} for i in ["round", "hash"]],
        data=[],
        ),
    dcc.Interval(
            id='interval-component',
            interval=5*1000, # in milliseconds
            n_intervals=0
        )
    ])

@app.callback(Output('table', 'data'),
              [Input('interval-component', 'n_intervals')])
def update_metrics(n):
    ret = get_qcs_from_rpc()
    return ret

if __name__ == '__main__':
    app.run_server(debug=True)
