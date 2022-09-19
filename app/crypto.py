import secp256k1
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from web3 import Web3
from web3.auto import w3
from eth_account.messages import encode_defunct


def derive_key_aes(other_publickey, my_privatekey):
    if len(other_publickey) == 64:
        other_publickey = b'\x04' + other_publickey
    key = secp256k1.PublicKey(other_publickey, raw=True)
    shared_key = key.ecdh(my_privatekey, hashfn=secp256k1.lib.secp256k1_ecdh_hash_function_sha256)
    return shared_key


def encrypt_aes(derived_key, data):
    cipher = AES.new(derived_key,AES.MODE_GCM,nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext+tag+cipher.nonce


def verify_secp256k1(publickey, data, signature):
    ed = encode_defunct(data)
    res = w3.eth.account.recover_message(ed, signature=signature)
    expected = convert_publickey_address(publickey.hex())
    return res == expected


def verify_ias_report(report, report_key, report_sig):
    pass


def convert_publickey_address(publickey):
    h = Web3.sha3(hexstr=publickey)
    return Web3.toChecksumAddress(Web3.toHex(h[-20:]))


def encode_defunct_str(data):
    return b'\x19Ethereum Signed Message:\n' + bytes(str(len(data)), 'utf-8') + data