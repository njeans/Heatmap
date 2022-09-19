import json

import crypto
import billboard

verbose = True


def print_debug(*args):
    if verbose:
        print(*args)


class User:

    def __init__(self, userid, address, secret_key, w3, contract, c):
        self.c = c[0]
        self.e = c[1]
        print_debug(self.c + "initialize User with userid:", userid, "address", address,self.e)
        self.userid = userid
        self.address = address
        self.w3 = w3
        self.contract = contract
        self.secret_key = secret_key
        self.audit_num = 1
        self.enclave_publickey = None

    def verify_ias(self, report, report_key, report_sig):
        print_debug(self.c + "user.verify_ias userid:", self.userid, self.e)
        crypto.verify_ias_report(report, report_key, report_sig)
        #todo reporoducible builds? here

        enclave_info = self.contract.functions.get_enclave_publickey().call({"from": self.address})
        # assert crypto.verify_secp256k1(report_key, enclave_info[0], enclave_info[1]) todo uncomment
        self.enclave_publickey = enclave_info[0]

    def verify_bb_info(self):
        '''
            check that I am included in the user list on the bb
        '''
        print_debug(self.c + "user.verify_bb_info userid:", self.userid, self.e)
        user_list = self.contract.functions.get_all_users().call({"from": self.address})
        assert self.address in user_list
        user_info = self.contract.functions.get_user(self.address, 0).call({"from": self.address})
        assert user_info[0] == self.address
        assert user_info[1] == 0  # last_audit_num
        assert user_info[2] == 0  # next_audit_num
        assert user_info[3] == b''  # user_data

    def encrypt_data(self, data):
        print_debug(self.c + "user.encrypt_data userid:", self.userid, "len(data):", len(data), self.e)
        shared_key = crypto.derive_key_aes(self.enclave_publickey, self.secret_key.private_key)
        encrypted_data = crypto.encrypt_aes(shared_key, bytes(json.dumps(data), "utf-8"))
        return encrypted_data

    def add_data_bb(self, encrypted_user_data):
        print_debug(self.c + "user.add_data_bb userid:", self.userid,self.e)
        last_audit_num = self.contract.functions.last_audit_num().call({"from": self.address})
        self.audit_num = last_audit_num+1
        print_debug(self.c + "user.add_data_bb userid:", self.userid, "for audit:",self.audit_num, self.e)
        billboard.send_tx(self.w3, self.contract.functions.add_user_data(encrypted_user_data, self.audit_num), self.address)
        user_info = self.contract.functions.get_user(self.address, self.audit_num).call({"from": self.address})
        assert user_info[0] == self.address
        assert user_info[2] == self.audit_num  # next_audit_num
        assert user_info[3] == encrypted_user_data  # user_data

    def drain(self):
        print_debug(self.c + "user.drain userid:", self.userid, self.e)
        billboard.send_tx(self.w3, self.contract.functions.drain(), self.address)

    def get_balance(self):
        return self.w3.eth.get_balance(self.address)
