
import yaml
import requests
import json
import mysql.connector
import threading

mydb = mysql.connector.connect(
  host="localhost",
  user="test",
  password="test",
  database="forensics"
)

mycursor = mydb.cursor()

def get_urls():
    urls = []
    for i in range(4):
        with open("/tmp/libra_swarm/{}/node.yaml".format(i), 'r') as stream:
            urls.append("http://"+yaml.safe_load(stream)['json_rpc']['address'])
    return urls

def insert(params):
    if (len(params) == 2):
        sql = "INSERT INTO qcs (round, hash) VALUES (%s, %s)"
    else:
        sql = "INSERT INTO qcs (round, node0, node1, node2, node3) VALUES (%s, %s, %s, %s, %s)"

    val = params
    mycursor.execute(sql, val)

    mydb.commit()


def delete(x=3):
    sql = "DELETE FROM qcs limit %s"
    val = (x,)
    mycursor.execute(sql, val)

    mydb.commit()

def clear(n=1):
    sql_drop = "DROP TABLE IF EXISTS qcs"
    if n == 1:
        sql_create = "CREATE TABLE qcs (round INTEGER, hash VARCHAR(10))"
    elif n == 4:
        sql_create = "CREATE TABLE qcs (round INTEGER, node0 VARCHAR(10), node1 VARCHAR(10), node2 VARCHAR(10), node3 VARCHAR(10))"
    mycursor.execute(sql_drop)
    mycursor.execute(sql_create)

    mydb.commit()


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
            insert((r, qc["vote_data"]["proposed"]["id"][:6]))
            ret.append({"round":r, "hash": qc["vote_data"]["proposed"]["id"][:6]})
    latest_round = new_latest_round
    return ret
def get_qcs_from_rpc_swarm(urls = ["http://127.0.0.1:8080"]):
    global latest_round
    ret = []
    response = requests.post(urls[0], data=json.dumps(get_latest_round_payload), headers=headers).json()
    new_latest_round = response["result"]
    for r in range(max(latest_round, new_latest_round-3)+1, new_latest_round+1):
        payload = {
                "method": "forensic_get_quorum_cert_at_round",
                "params": [r],
                "jsonrpc": "2.0",
                "id": 0,
                }
        hashes = []
        for url in urls:
            response = requests.post(url, data=json.dumps(payload), headers=headers).json()
            if len(response["result"])==0:
                break
            qc = response["result"][0]
            # check round number
            if qc["vote_data"]["proposed"]["round"] == r:
                hashes.append(qc["vote_data"]["proposed"]["id"][:6])

        insert((r, hashes[0], hashes[1], hashes[2], hashes[3]))
        ret.append({"round":r, "node0": hashes[0], "node1": hashes[1], "node2": hashes[2], "node3": hashes[3]})
    latest_round = new_latest_round
    return ret
def update():
    threading.Timer(5.0, update).start()
    delete(3)
    get_qcs_from_rpc_swarm(get_urls())

clear(4)
#get_qcs_from_rpc()
update() 
