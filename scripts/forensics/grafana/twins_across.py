from collections import defaultdict
from utils import *
from sql import *
import pandas as pd
import numpy as np
import re
import time
import datetime
import json


nodes = ["node0", "node1", "node2", "node3"]
detected = -1
culprits = []
qcs = defaultdict(dict)
qcr = dict()
conflict = 0
round_1 = 0
round_2 = 0

def check_across_view(r1, r2):
    global qcs
    qc_1 = None
    qc_2 = None
    pre_qc2_qcs = list()
    for _qc in qcs["2"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"]==r1:
            qc_1=_qc
    for _qc in qcs["4"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"]==r2:
            qc_2=_qc
    return hotstuff_forensic_across_views(qc_1,qc_2,[qc_2])


def check_round():
    global qcs, round_1, round_2, qcr
    qcs = defaultdict(dict) # block hash -> qc
    qc_pattern = re.compile(r'([0-9]+)-node-twins.*({"quorum_cert":.*})')

    libra_twins_forensic_log = './logs/libra_across.log'

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
    for _qc in qcs["2"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"] > 0:
            round_1 = _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"] + 3
            break
    for _qc in qcs["3"].values():
        if _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"] > 0:
            round_2 = _qc["signed_ledger_info"]["V0"]["ledger_info"]["commit_info"]["round"]
            break
    print(round_1, round_2)     

def get_qcs_from_log(n):
    global qcs, conflict, detected, culprits, qcr
    twin_nodes = {}
    commit_qcs = defaultdict(dict) # block id -> grandparent id (the commit block)

    df_lst = list()
    start = n*4
    for r in range(start, start+4):
        rnd_lst = [r]
        for i in range(6):
            if r == round_2:
                detected = r
                culprits = [x[:5] for x in check_across_view(round_1, round_2)]
                insert_culprits((r, "{}".format(culprits)))

            if (i,r) in qcr:
                rnd_lst.append("'"+qcr[(i,r)]+"'")
            else:
                rnd_lst.append('  null')
        df_lst.append(rnd_lst)
        insert_qcs_twins(tuple(rnd_lst))
        ts = time.time()
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        if rnd_lst[3] != rnd_lst[4]: 
            conflict += 1
        insert_conflict((timestamp, r, conflict))

    df = pd.DataFrame(np.array(df_lst), columns=['round', 'node0', 'node1', 'node2', 'node3', 'twin0', 'twin1']).to_dict('records')
    for node in nodes:
        insert_node(node, (r-2, "{}:<br>{}".format(r-2, df[0][node]), "{}:<br>{}".format(r-1,df[1][node]), "{}:<br>{}".format(r,df[2][node])))    
    return df


def update(n):
    print("update", n)
    if n > 0:
        #delete_qcs(4)
        for node in nodes:
            delete_node(node, 1)
    get_qcs_from_log(n)
    #get_logs()

if __name__ == "__main__":
    #log_files = get_log_files()
    #clear_text(nodes)
    clear_qcs_twins()
    clear_conflict()
    clear_culprits()
    check_round()
    for node in nodes:
        clear_node(node)
    cnt = 0
    while True:
        if detected > -1: break
        update(cnt)
        time.sleep(5)
        cnt += 1
        