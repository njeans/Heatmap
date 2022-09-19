import json
import zmq


from constants import enclave_url
verbose = False


def print_debug(*args):
    if verbose:
        print(*args)


def get_socket(url=enclave_url):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(url)
    return socket


def get_enclave_report():
    print_debug("enclave.get_enclave_report")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "GetEnclaveReport"
    }
    print_debug(input_data)
    socket.send(bytes(json.dumps(input_data),"utf-8"))
    output = json.loads(socket.recv())
    print_debug(output)
    if output["EnclaveReport"]["status"] != 0:
        print("enclave.get_enclave_report error ", output)
        exit(1)
    return bytes.fromhex(output["EnclaveReport"]["signing_key"])


def get_enclave_publickey():
    print_debug("enclave.get_enclave_publickey")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "GetEnclavePublicKey"
    }
    print_debug("enclave.get_enclave_publickey input_data", input_data)
    socket.send(bytes(json.dumps(input_data),"utf-8"))
    output = json.loads(socket.recv())
    print_debug("enclave.get_enclave_publickey enclave output", output)
    if output["EnclavePublicKey"]["status"] != 0:
        print("enclave.get_enclave_publickey error ", output)
        exit(1)
    return bytes.fromhex(output["EnclavePublicKey"]["encryption_key"]),bytes.fromhex(output["EnclavePublicKey"]["signature"])


def get_audit_data():
    print_debug("enclave.get_audit_data")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "GetAuditData"
    }
    print_debug("enclave.get_audit_data input_data", input_data)
    socket.send(bytes(json.dumps(input_data),"utf-8"))
    output = json.loads(socket.recv())
    print_debug("enclave.get_enclave_data enclave output", output)
    if output["AuditData"]["status"] != 0:
        print("enclave.get_enclave_data error ", output)
        exit(1)
    data = bytes.fromhex(output["AuditData"]["data"])
    sig = bytes.fromhex(output["AuditData"]["signature"])
    return data, sig


def get_enclave_data():
    print_debug("enclave.get_enclave_data")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "GetEnclaveData"
    }
    print_debug("enclave.get_enclave_data input_data", input_data)
    socket.send(bytes(json.dumps(input_data),"utf-8"))
    output = json.loads(socket.recv())
    print_debug("enclave.get_enclave_data enclave output", output)
    if output["EnclaveData"]["status"] != 0:
        print("enclave.get_enclave_data error ", output)
        exit(1)
    data = bytes.fromhex(output["EnclaveData"]["data"])
    sig = bytes.fromhex(output["EnclaveData"]["signature"])
    return data, sig


def init_user_db(user_info):
    print_debug("enclave.init_user_db")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "InitUserDB",
        "user_db": bytes(json.dumps(user_info),"utf-8").hex()
    }
    print_debug("enclave.init_user_db input_data", input_data)
    socket.send(bytes(json.dumps(input_data), "utf-8"))
    output = json.loads(socket.recv())
    print_debug("enclave.init_user_db enclave output", output)
    if output["InitUserDB"]["status"] != 0:
        print("enclave.init_user_db error ", output)
        exit(1)


def add_personal_data(userid='-----', encrypted_data=b'ffffffffffffffffffffffffffffffffffff'):#, privatekey, data):
    print_debug("enclave.add_personal_data for", userid)
    socket = get_socket(enclave_url)
    input_data = {
        "id": userid,
        "type": "AddPersonalData",
        "input": {
            "userid": userid,
            "encrypted_data": encrypted_data.hex(),
        }
    }
    print_debug("enclave.add_personal_data input_data", input_data)
    socket.send_json(input_data)
    output = json.loads(socket.recv())
    print_debug("enclave.add_personal_data enclave output", output)
    if output["type"] == "Error" or output["AddPersonalData"]["status"] != 0:
        print("enclave.add_personal_data error ", output)
        exit(1)


def get_heatmap():
    print_debug("enclave.get_heatmap")
    socket = get_socket(enclave_url)
    input_data = {
        "id": "admin",
        "type": "RetrieveHeatmap",
    }
    print_debug("enclave.get_heatmap input_data", input_data)
    socket.send_json(input_data)
    output = json.loads(socket.recv())
    print_debug("enclave.get_heatmap enclave output", output)
    if output["RetrieveHeatmap"]["status"] != 0:
        print("enclave.get_heatmap error ", output)
        exit(1)
    heatmap_bytes = bytes.fromhex(output["RetrieveHeatmap"]["heatmap"])
    heatmap = json.loads(heatmap_bytes.decode("utf-8"))
    return heatmap

# if __import__()