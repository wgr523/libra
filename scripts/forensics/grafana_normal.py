
import yaml
import requests
import json
import mysql.connector
import threading
import os

mydb = mysql.connector.connect(
  host="localhost",
  user="test",
  password="test",
  database="forensics"
)

mycursor = mydb.cursor()

log_files = []
def get_log_files():
    global log_files
    log_files = []
    for i in range(4):
        log_files.append("/tmp/libra_swarm/logs/{}.log".format(i))

def get_urls():
    urls = []
    for i in range(4):
        with open("/tmp/libra_swarm/{}/node.yaml".format(i), 'r') as stream:
            urls.append("http://"+yaml.safe_load(stream)['json_rpc']['address'])
    return urls

def insert(table_name, params):
    sql = "INSERT INTO {} (round, B1, B2, B3) VALUES (%s, %s, %s, %s)".format(table_name)
    val = params
    mycursor.execute(sql, val)
    mydb.commit()

def insert_qcs(params):
    sql = "INSERT INTO qcs (round, node0, node1, node2, node3) VALUES (%s, %s, %s, %s, %s)"
    val = params
    mycursor.execute(sql, val)
    mydb.commit()

def delete(table_name, x=3):
    sql = "DELETE FROM {} WHERE round > -1 limit %s".format(table_name)
    val = (x,)
    mycursor.execute(sql, val)
    mydb.commit()

def delete_qcs(x=3):
    sql = "DELETE FROM qcs limit %s"
    val = (x,)
    mycursor.execute(sql, val)
    mydb.commit()

def clear(table_name="node0"):
    sql_drop = "DROP TABLE IF EXISTS {}".format(table_name)
    sql_create = "CREATE TABLE {} (round INTEGER, B1 VARCHAR(10), B2 VARCHAR(10), B3 VARCHAR(10))".format(table_name)
    sql_insert = "INSERT INTO {} (round, B1, B2, B3) values (%s, %s, %s, %s)".format(table_name)
    val = (-1, "1", "2","3")
    mycursor.execute(sql_drop)
    mycursor.execute(sql_create)
    mycursor.execute(sql_insert, val)
    mydb.commit()

def clear_qcs():
    sql_drop = "DROP TABLE IF EXISTS qcs"
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
nodes = ["node0", "node1", "node2", "node3"]

def clear_text():
    sql_drop = "DROP TABLE IF EXISTS text"
    sql_create = "CREATE TABLE text (id VARCHAR(20) NOT NULL, is_culprit BOOL NOT NULL, content VARCHAR(1024), PRIMARY KEY (id))"
    # init the entry with default value
    sql_insert = "INSERT INTO text (id, is_culprit) values ('culprit', 0)"
    mycursor.execute(sql_drop)
    mycursor.execute(sql_create)
    mycursor.execute(sql_insert)
    global nodes
    for node in nodes:
        sql_insert = "INSERT INTO text (id, is_culprit) values ('{}', 0)".format(node)
        mycursor.execute(sql_insert)
    mydb.commit()

def get_logs():
    global nodes
    global log_files
    bufsize = 1000
    for i, node in enumerate(nodes):
        fsize = os.stat(log_files[i]).st_size
        with open(log_files[i]) as stream:
            stream.seek(max(0,fsize-bufsize))
            the_log = stream.read()
            sql_update = "UPDATE text SET content='{}' WHERE id='{}'".format(the_log, node)
            mycursor.execute(sql_update)
    mydb.commit()

def get_qcs_from_rpc_swarm(urls):
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
            qc = response["result"][0]["qc"]
            # check round number
            if qc["vote_data"]["proposed"]["round"] == r:
                hashes.append(qc["vote_data"]["proposed"]["id"][:6])
        insert_qcs((r, hashes[0], hashes[1], hashes[2], hashes[3]))
        ret.append({"round":r, "node0": hashes[0], "node1": hashes[1], "node2": hashes[2], "node3": hashes[3]})
    latest_round = new_latest_round
    for node in nodes:
        insert(node, (r-2, ret[0][node], ret[1][node], ret[2][node]))
    return ret
def update():
    threading.Timer(5.0, update).start()
    delete_qcs(3)
    for node in nodes:
        delete(node, 1)
    get_qcs_from_rpc_swarm(get_urls())
    get_logs()

get_log_files()
clear_text()
clear_qcs()
for node in nodes:
    clear(node)
update() 
