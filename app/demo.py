import json
import sys
import random

from web3 import Web3
import secp256k1

import billboard
import admin as admin_lib
import user as user_lib

from constants import *


def get_test_data(num_users=10, min_data=2):
    max_lat = 40.25
    max_lng = 116.75
    min_lat = 39.5
    min_lng = 116.0
    output = []
    data = []
    for j in range(min_data*4):
        lng = random.uniform(min_lng, max_lng)
        lat = random.uniform(min_lat, max_lat)
        data += [
            {
                "lat": lat,
                "lng": lng,
                "startTS": 1583067001+j,
                "endTS": 1583067601+j,
                "testResult": True,
            }
        ]
    # print("data", [d["lat"] for d in data])
    for i in range(num_users):
        data_for_user = [data[k] for k in range(min_data*((i % 4)+1))]
        output.append(data_for_user)
        print("data for user", i, [d["lat"] for d in data_for_user])
    return output


def setup_users(accounts_info, user_addresses, w3, contract):
    users = []
    user_info = []
    for i in range(len(user_addresses)):
        userid = "u{:<4}".format(i)
        user_address = user_addresses[i]
        private_key = bytes(accounts_info["addresses"][user_address.lower()]["secretKey"]["data"])
        secret_key = secp256k1.PrivateKey(private_key, raw=True)
        users.append(user_lib.User(userid, user_address, secret_key, w3, contract, [colors[i % len(colors)], end]))
        user_info.append({"userid": userid, "publickey": secret_key.pubkey.serialize(compressed=False)[1:].hex()})
    return users, user_info


def data_omission_demo(num_users=4):
    print("---------------------------- Starting Data Omission Demo ----------------------------")
    w3, accounts_info = billboard.setup_w3(accounts_path)
    account_addresses = [Web3.toChecksumAddress(x) for x in accounts_info["addresses"].keys()]

    admin_address = account_addresses[0]
    admin = admin_lib.Admin(admin_address, w3, (solidity_base_path, contract_source_path, allowed))

    user_addresses = account_addresses[1:num_users+1]
    # num_users = len(user_addresses)
    contract = admin.contract
    users_list, user_info = setup_users(accounts_info, user_addresses, w3, contract)
    test_data = get_test_data(num_users, min_data=2)
    data, signature = admin.signup_users_enclave(user_info)
    admin.signup_users_bb(user_addresses, signature)
    admin.fund_billboard()
    # print("contract balance", contract.functions.contract_balance().call({"from": admin.address}))
    # print("contract max_penalty", contract.functions.max_penalty().call({"from": admin.address}))
    report, report_key, sig = admin_lib.Admin.get_ias_report()
    omit_user = [False for _ in range(num_users)]
    omit_admin = [False for _ in range(num_users)]
    for i in range(num_users):
        user = users_list[i]
        user.verify_ias(report, report_key, sig)
        user.verify_bb_info()
        if i < num_users/4:  # quater of the users data is omitted by admin
            print(colors[i % len(colors)] + "!!!!!!!!!! admin omitting data for ", user.userid, "user should be paid after auditing !!!!!!!!!!",end)
            omit_admin[i] = True
        if i >= 3*num_users/4:  # quater of the users data is omitted by user (relevant for user trying to frame admin)
            print(colors[i % len(colors)] + "user", user.userid, " omitting data", end)
            omit_user[i] = True
    encrypted_user_data = [False for _ in range(num_users)]
    for i in range(num_users):
        user = users_list[i]
        user_data = test_data[i]
        encrypted_user_data[i] = user.encrypt_data(user_data)
        if not omit_user[i]:  # user is actually sending data to admin
            admin.add_user_data(user.userid, encrypted_user_data[i], omit=omit_admin[i])

    for i in range(num_users):
        user = users_list[i]
        if i % 2 == 0 or omit_user[i]:  # half of the users are monitoring for omissions <3
            print(colors[i % len(colors)] + "user", user.userid, "monitoring omissions", end)
            user.add_data_bb(encrypted_user_data[i])

    start_balances = [users_list[i].get_balance() for i in range(num_users)]

    admin.check_bb_data()
    admin.get_heatmap()
    audit_data, signature = admin.get_audit_data()
    admin.post_audit_data_bb(audit_data, signature)

    end_balances = [users_list[i].get_balance() for i in range(num_users)]

    # users_list[0].drain()
    # only even number users in the bottom 1/4th should get money because they were monitoring and the admin did
    # omit their data
    # print("start_balances", start_balances)
    # print("end_balances", end_balances)
    # print("contract balance", contract.functions.contract_balance().call({"from": admin.address}))
    # print("contract last_audit_data", contract.functions.last_audit_data().call({"from": admin.address}))
    for i in range(num_users):
        if i < num_users/4 and i % 2 == 0:
            print(users_list[i].c+"!!!!!!!!!! user", users_list[i].userid,
                  "was paid", end_balances[i] - start_balances[i],
                  "start_balance", start_balances[i],
                  "end_balance", end_balances[i], "!!!!!!!!!!", users_list[i].e)
            assert end_balances[i] > start_balances[i]
        else:
            print(users_list[i].c+"user", users_list[i].userid,
                  "was not paid", end_balances[i] - start_balances[i],
                  "start_balance", start_balances[i],
                  "end_balance", end_balances[i], users_list[i].e)
            assert end_balances[i] == start_balances[i]


if __name__ == '__main__':
    if len(sys.argv) == 2:
        data_omission_demo(int(sys.argv[1]))
    else:
        data_omission_demo()