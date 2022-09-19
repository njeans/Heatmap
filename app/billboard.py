import json

from web3 import Web3
from solcx import compile_source

from constants import billboard_url
verbose = False


def print_debug(*args):
    if verbose:
        print(*args)


def deploy_contract(w3, solidity_paths, admin_addr, enclave_public_key, enclave_public_key_sig):
    base_path, contract_source_path, allowed = solidity_paths
    contract_id, abis, bins = compile_source_file(base_path, contract_source_path, allowed)
    contract = w3.eth.contract(abi=abis, bytecode=bins)
    tx_hash = contract.constructor(enclave_public_key, enclave_public_key_sig).transact({"from": admin_addr})
    contract_address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
    contract = w3.eth.contract(address=contract_address, abi=abis)
    print(f'Deployed {contract_id} to: {contract_address} with hash  {tx_hash}')
    return contract_address, contract, tx_hash


def compile_source_file(base_path, contract_source_path, allowed):
    with open(base_path + contract_source_path, 'r') as f:
        contract_source_path = f.read()
    compiled_sol = compile_source(contract_source_path,
                                  output_values=['abi', 'bin'],
                                  base_path=base_path,
                                  allow_paths=[allowed])
    abis = []
    bins = ""
    contract_id = ""
    for x in compiled_sol:
        contract_id += x
        contract_interface = compiled_sol[x]
        abis = abis + contract_interface['abi']
        bins = bins + contract_interface['bin']
    return contract_id, abis, bins


def setup_w3(accounts_path, bb_url=billboard_url):
    provider = Web3.HTTPProvider(bb_url, request_kwargs={'timeout': 60})
    w3 = Web3(provider)
    with open(accounts_path) as f:
        accounts_info = json.loads(f.read())
    return w3, accounts_info


def send_tx(w3, foo, user_addr, value=0):
    print_debug("billboard.send_tx func:", foo, "from:", user_addr)
    gas_estimate = foo.estimateGas()
    # print(f'\tGas estimate to transact: {gas_estimate}')

    if gas_estimate < 1000000:
        # print("\tSending transaction")
        tx_hash = foo.transact({"from": user_addr, "value": value})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # print("\tTransaction receipt mined:")
        # pprint.pprint(dict(receipt))
        # print("\tWas transaction successful?"+str(receipt["status"]))
    else:
        print("billboard.send_tx error Gas cost exceeds 1000000:", gas_estimate)
        exit(1)