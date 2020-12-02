import dash
import dash_table
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import re
import json
from collections import Counter
from collections import defaultdict
import argparse
import pandas as pd
import numpy as np
import requests
import json

latest_round = -1
detected = -1
culprits = []
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
    for r in range(max(latest_round, new_latest_round-3)+1, new_latest_round+1):
        payload = {
                "method": "forensic_get_quorum_cert_at_round",
                "params": [r],
                "jsonrpc": "2.0",
                "id": 0,
                }
        response = requests.post(url, data=json.dumps(payload), headers=headers).json()
        if len(response["result"])==0:
            break
        qc = response["result"][0]
        # check round number
        if qc["vote_data"]["proposed"]["round"] == r:
            ret.append({"round":r, "hash": qc["vote_data"]["proposed"]["id"][:6]})

    latest_round = new_latest_round
    return ret
qcs = defaultdict(dict)
def get_df_from_log(n):
    global qcs
    global detected, culprits
    qc_pattern = re.compile(r'([0-9]+)-node-twins.*({"quorum_cert":.*})')
    libra_twins_forensic_log = '/tmp/libra.log'
    twin_nodes = {}
    qcs = defaultdict(dict) # block hash -> qc
    commit_qcs = defaultdict(dict) # block id -> grandparent id (the commit block)

    with open(libra_twins_forensic_log) as fin:
        for line in fin:
            m = qc_pattern.search(line)
            if m is not None:
                d = json.loads(m.group(2))
                r = d["quorum_cert"]["vote_data"]["proposed"]["round"] # round/view
                h = d["quorum_cert"]["vote_data"]["proposed"]["id"] # block hash/ proposed id
                grand_h = d["quorum_cert"]["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["id"] # grandparent hash/ commit id
                qcs[m.group(1)][h]=d["quorum_cert"]
    qcr = dict()
    for i in range(6):
        a=str(i)
        for _qc in qcs[a].values():
            r = _qc["vote_data"]["proposed"]["round"]
            h = _qc["vote_data"]["proposed"]["id"]
            qcr[(i,r)] = h[:6]
    df_lst = list()
    if detected == -1:
        start = n*4
    else:
        start = detected
    for r in range(start, start+4):
        rnd_lst = [r]
        for i in range(6):
            if (2,r) in qcr and (3,r) in qcr and qcr[(2,r)] != qcr[(3,r)] and detected == -1:
                detected = r
                culprits = [x[:5] for x in check_within_view(r)]
            if (i,r) in qcr:
                rnd_lst.append(qcr[(i,r)])
            else:
                rnd_lst.append('  null')
        df_lst.append(rnd_lst)
    df = pd.DataFrame(np.array(df_lst), columns=['round', 'node0', 'node1', 'node2', 'node3', 'twin0', 'twin1'])
    
    return df.to_dict('records')
def hotstuff_forensic_within_view(qc_1, qc_2):
    epoch_1 = qc_1["vote_data"]["proposed"]["epoch"]
    epoch_2 = qc_2["vote_data"]["proposed"]["epoch"]
    round_1 = qc_1["vote_data"]["proposed"]["round"]
    round_2 = qc_2["vote_data"]["proposed"]["round"]
    id_1 = qc_1["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["id"]
    id_2 = qc_2["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["id"]
    assert epoch_1 == epoch_2
    assert round_1 == round_2
    assert id_1 != id_2
    # omit the signature checking
    signers_1 = qc_1["signed_ledger_info"]["V0"]["signatures"]
    signers_2 = qc_2["signed_ledger_info"]["V0"]["signatures"]
    signers_1 = set(signers_1.keys())
    signers_2 = set(signers_2.keys())
    return signers_1.intersection(signers_2)

def check_within_view(r):
    global qcs
    qc_1 = None
    qc_2 = None
    for _qc in qcs["2"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"]==r:
            qc_1=_qc
    for _qc in qcs["3"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"]==r:
            qc_2=_qc
    return hotstuff_forensic_within_view(qc_1,qc_2)
app = dash.Dash(__name__)
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--forensic', action='store_true')
args = parser.parse_args()

qcs = html.Div(children=[
        html.H4('Latest Quorum Cert', style={'textAlign': "center"}),
        dash_table.DataTable(
            id='table',
            columns=[{"name": i, "id": i} for i in ["round", "hash"]],
            data=[],
            style_cell={
                'textAlign': 'center'
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': 'rgb(248, 248, 248)'
                }
            ],
            style_header={
                'backgroundColor': 'rgb(230, 230, 230)',
                'fontWeight': 'bold'
            }
        ),
        html.Br(),
        html.Div("P1 = {0:1C1CC, 1:51C1B, 2:618E2}", style={'textAlign': "center"}),
        html.Div("P2 = {0:1C1CC, 1:51C1B, 3:AF6D2}", style={'textAlign': "center"}),
        dcc.Interval(
                id='interval-component',
                interval=1000, # in milliseconds
                n_intervals=0
            )
    ], style={'width': '30%', 'margin': 'auto'})

forensic_data = html.Div(children=[
        html.H4('Conflict Range', style={'textAlign': "center"}),
        dash_table.DataTable(
            id='table_df',
            data=[],
            columns=[{"name": i, "id": i} for i in ['round', 'node0', 'node1', 'node2', 'node3', 'twin0', 'twin1']],
            style_cell={
                'textAlign': 'center'
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': 'rgb(248, 248, 248)'
                },
                {
                    'if': {
                        'filter_query': '{node2} != {node3}',
                        'column_id': ['node2', 'node3'],
                    },
                    'color': 'red'
                },
            ],
            style_header={
                'backgroundColor': 'rgb(230, 230, 230)',
                'fontWeight': 'bold'
            },
        ),
        html.Br(),
        html.Div(id='forensic-output', style={'textAlign': "center"}),
        dcc.Interval(
                id='interval-component_df',
                interval=2*1000, # in milliseconds
                n_intervals=0
            )
    ], style={'width': '60%', 'margin': 'auto'})
app.layout = html.Div(children=[
    qcs, 
    html.Br(),
    forensic_data])


@app.callback(Output('table', 'data'),
            Input('interval-component', 'n_intervals'))
def update_metrics(n):
    ret = get_qcs_from_rpc()
    return ret

@app.callback(Output('table_df', 'data'),
        Output(component_id='forensic-output', component_property='children'),
        Input('interval-component_df', 'n_intervals'))
def update_df(n):
    df = get_df_from_log(n)
    return df, "Culprits: {}".format(culprits)


if __name__ == '__main__':
    app.run_server(debug=False)
