import json

from web3 import Web3

import numpy as np
import matplotlib.pyplot as plt
import datetime

import billboard
import enclave
import crypto
from constants import heatmap_info_beijing

verbose = True
s = '\033[92m'
e = '\033[0m'


def print_debug(*args):
    if verbose:
        print(*args)


class Admin:

    def __init__(self, address, w3, solidity_paths):
        self.address = address
        self.w3 = w3
        self.user_ids = {}
        report, report_key, report_sig = Admin.get_ias_report()
        enclave_public_key, enclave_public_key_sig = enclave.get_enclave_publickey()
        # assert crypto.verify_secp256k1(report_key, enclave_public_key, enclave_public_key_sig)
        self.enclave_public_key = enclave_public_key
        _, self.contract, _ = billboard.deploy_contract(w3, solidity_paths,  self.address, self.enclave_public_key, enclave_public_key_sig)
        self.included_users = []
        self.audit_num = 1  # audit_nums are start at 1 srry

    @staticmethod
    def get_ias_report():
        report = ""
        report_key = ""
        sig = ""
        #todo verify report_key
        enclave_public_key = enclave.get_enclave_publickey()
        #todo verify enclave_public_key with report_key
        return report, report_key, sig

    def fund_billboard(self, amount=None):
        if amount is None:
            amount = self.contract.functions.max_penalty().call({"from": self.address})
        print_debug(s, "admin.fund_billboard ", amount, e)
        billboard.send_tx(self.w3, self.contract.functions.fund(), self.address, value=amount)

    def signup_users_enclave(self, user_info):
        print_debug(s, "admin.signup_users_enclave user_info: ", [u["userid"] for u in user_info], e)
        for u in user_info:
            addr = crypto.convert_publickey_address(u["publickey"])
            self.user_ids[addr] = u["userid"]

        enclave.init_user_db(user_info)
        data, signature = enclave.get_enclave_data()
        expected = [crypto.convert_publickey_address(u["publickey"]).lower() for u in user_info]
        assert expected == json.loads(data[13:])
        assert crypto.verify_secp256k1(self.enclave_public_key, data, signature)
        return data, signature

    def signup_users_bb(self, user_addresses, signature):
        print_debug(s+"admin.signup_users_bb user_addresses:", user_addresses)
        billboard.send_tx(self.w3, self.contract.functions.init_user_db(user_addresses, signature), self.address)
        initialized = self.contract.functions.initialized().call({"from": self.address})
        assert initialized

    def add_user_data(self, user_id, encrypted_data, omit=False):
        print_debug(s + "admin.add_user_data userid:", user_id, "omit:", omit, e)
        if user_id in self.included_users:
            return
        self.included_users.append(user_id)
        if omit:
            print_debug(s + "!! admin omitting data for user:", user_id, "!!", e)
            return
        enclave.add_personal_data(user_id, encrypted_data)

    def check_bb_data(self):
        # print_debug(s +"admin.check_bb_data for audit", self.audit_num,e)
        user_datas = self.contract.functions.get_all_user_data(self.audit_num).call({"from": self.address})
        print_debug(s + "admin.check_bb_data user_datas for audit ", self.audit_num, e)
        for user in user_datas:
            user_addr = user[0]
            if user_addr == '0x0000000000000000000000000000000000000000':
                continue
            encrypted_data = user[3]
            user_id = self.user_ids[user_addr]
            if user_id not in self.included_users:
                print_debug(s + "admin.check_bb_data found not included user", user_id, e)
                self.add_user_data(user_id, encrypted_data)

    def get_heatmap(self):
        print_debug(s + "admin.get_heatmap",e)
        heatmap = enclave.get_heatmap()
        self.save_heatmap(heatmap, self.audit_num-1)

    def get_audit_data(self):
        # print_debug(s +"admin.get_audit_data",e)
        data, signature = enclave.get_audit_data()
        print_debug(s + "admin.get_audit_data", data,e)
        assert crypto.verify_secp256k1(self.enclave_public_key, data, signature)
        return json.loads(data[11:]), signature

    def post_audit_data_bb(self, data, signature):
        print_debug(s + "admin.post_audit_data_bb data:", data, e)
        data = [Web3.toChecksumAddress(x) for x in data]
        billboard.send_tx(self.w3, self.contract.functions.admin_audit(data, signature, self.audit_num), self.address)
        last_audit_num = self.contract.functions.last_audit_num().call({"from": self.address})
        assert last_audit_num == self.audit_num
        self.included_users = []
        self.audit_num += 1

    def save_heatmap(self, hm, audit_num):
        print_debug(s + "save_heatmap", hm, e)
        max_x = heatmap_info_beijing["max_x"]
        min_x = heatmap_info_beijing["min_x"]
        max_y = heatmap_info_beijing["max_y"]
        min_y = heatmap_info_beijing["min_y"]
        x_range = max_x - min_x+1
        y_range = max_y - min_y+1
        num_bins = 10
        num_labels_x = 3*int((num_bins/3))
        num_labels_y = int(num_labels_x/.75)
        # print("num_bins", num_labels_x, num_labels_y)
        width = 9
        height = 12

        heatmap_vals_round = np.zeros((num_labels_x, num_labels_y))
        for k in hm:
            rec = [int(x) for x in k.split(",")]
            x_loc = ((rec[0])/x_range)*num_labels_x
            y_loc = ((rec[1])/y_range)*num_labels_y
            # print("round rec:",rec,"xloc:",x_loc,"yloc:",y_loc)
            heatmap_vals_round[int(x_loc)][int(y_loc)] += hm[k]
        # print(heatmap_vals_round)
        hm_info = heatmap_info_beijing
        plt.figure(figsize=(width, height))

        xtic = np.arange(0, num_labels_x, step=1)
        xlab = ['{:4f}'.format(hm_info["min_long"] + (hm_info["max_long"]-hm_info["min_long"])*(val/num_labels_x)) for val in xtic]
        plt.xticks(ticks=xtic, labels=xlab, rotation=-45)

        ytic = np.arange(0, num_labels_y, step=1)
        ylab = ['{:4f}'.format(hm_info["min_lat"] + (hm_info["max_lat"]-hm_info["min_lat"])*(val/num_labels_y)) for val in ytic]
        plt.yticks(ticks=ytic, labels=ylab)

        plt.title("tDrive Heatmap audit_num: " + str(audit_num))
        im2 = plt.imshow(heatmap_vals_round.transpose(), origin='lower', cmap='Reds', aspect='equal', extent=(0.0, width, 0.0, height))
        bmap = plt.imread(hm_info["map_file"])
        im = plt.imshow(bmap, extent=(0, width, 0, height), alpha=.3)
        plt.savefig("heatmap_{}_{}.png".format(num_bins, audit_num))

    def get_balance(self):
        return self.w3.eth.get_balance(self.address)