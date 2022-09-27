// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.4.22 <0.9.0;

contract Heatmap {
    struct User {
        mapping (uint => bytes) user_data;//mapping data from every audit num won't necessarily be provided
        uint last_audit_num;
        uint next_audit_num;
     }

    struct AuditData {
        bytes merkle_root;
        address[] included_user_addresses;
    }

    struct UserData {
        address user_address;
        uint last_audit_num;
        uint next_audit_num;
        bytes data;
    }

    address admin_addr;

    mapping (address => User) user_info;
    address[] public user_list;

    AuditData public last_audit_data;

    uint public contract_balance;
    uint message_omission_cost;
    uint audit_delay_cost;
    uint public max_penalty;

    uint public last_audit_num;
    uint last_audit_block_num;
    uint audit_time_limit = 10;

    bool public initialized; //require that can only initialize once

    address public enclave_address;
    bytes public enclave_publickey;
    bytes public enclave_publickey_sig;

    constructor(bytes memory enclave_key, bytes memory signature) {
        admin_addr = msg.sender;
        enclave_publickey = enclave_key;
        enclave_address = address(uint160(uint256(keccak256(enclave_key))));
        initialized = false;
        enclave_publickey_sig = signature;
    }

    function fund() public payable {
        require(msg.sender == admin_addr); //good bugs..bugs that benefit you e.g. someone else funding my contract
        contract_balance+=msg.value;
    }

    function init_user_db(address[] memory user_addresses, bytes memory signature) public {
        require(msg.sender == admin_addr);
        require(initialized == false);

        bytes32 users_hash = hash_address_list("ENCLAVE_DATA:", user_addresses);
        address signer = recover(users_hash, signature);
        require(signer == enclave_address);
        tmp3 = signer;
        uint num_users = user_addresses.length;
        audit_delay_cost = 1;
        message_omission_cost = audit_delay_cost * num_users; //admin should get a lower penaly for doing the audit and ommiting a small amount of data vs not doing the audit and ghosting
        max_penalty = (message_omission_cost + audit_delay_cost) *  num_users;

        last_audit_block_num = block.number;//starts timer for next audit
        initialized = true;
        last_audit_num = 0;//valid audit nums start at 1 (sorry to the 0 indexing stans)
        user_list = user_addresses;
    }

    function add_user_data(bytes memory encrypted_command_and_data, uint audit_num) public {
        require(max_penalty <= address(this).balance);
        require(initialized);
        require(last_audit_num+1 == audit_num);//need to make sure that we are talking about the right audit otherwise we could have data inclusion errors :0

        User storage user = user_info[msg.sender];
        require(user.last_audit_num < audit_num);//can change data for current audit because admin could read data from here causing conflicts, todo add way for admin to update data based on blockchain
        user.last_audit_num = user.next_audit_num;
        user.next_audit_num = audit_num;

        //same vulnerability as secret network 0.0 but if the enclave is compromised then everything breaks anyway. for
        //ours only someone with access to that specific enclave on that machine can compromise it on theirs anyone on
        //any* machine can compromise it. the administrator is still liable if they let their enclave get compromised
        //what should they do in that case: shut down the machine and burn it to save the user data from being compromised :)

        //users can only add 1 set
        //of data per audit time period
        user.user_data[audit_num] = encrypted_command_and_data;//user user data data
//        user.user_data.push(data); //user user data data
    }

    //for every function the admin can run by themselves we need merkle tree checks e.g. recovery in pktransfer

    //host should publish audit every x number of blocks
    // check using block number
    // what happends if address eth key gets leaked?
    function admin_audit(address[] memory included_user_addresses_, bytes memory signature, uint audit_num) public {
        require(msg.sender == admin_addr);
        require(initialized);
        require(last_audit_num < audit_num);
        drain();
        last_audit_num = audit_num;
        last_audit_block_num=block.number;
        last_audit_data = AuditData("",included_user_addresses_);

        bytes32 users_hash = hash_address_list("AUDIT_DATA:", included_user_addresses_);
        address signer = recover(users_hash, signature);
        require(signer == enclave_address);
        for (uint i=0; i<user_list.length; i++) {
            address payable user_addr = payable(user_list[i]);
            User storage user = user_info[user_addr];
            if (user.next_audit_num == audit_num) {
                bool user_included = contains_address(included_user_addresses_, user_addr);
                if (!user_included) {//this is a check that your data was included not a check that it's what you want
                    // Sending back the money by simply using
                    // highestBidder.send(highestBid) is a security risk
                    // because it could execute an untrusted contract.
                    // It is always safer to let the recipients
                    // withdraw their money themselves. https://docs.soliditylang.org/en/v0.8.17/solidity-by-example.html#simple-open-auction
                    bool res = user_addr.send(message_omission_cost);
                    if (!res) {//if it failed continue because of time limit
                        revert("send money failed omission");
                    }
                    contract_balance-=message_omission_cost;
                }
            }
        }
    }

    function drain() public {
        if ((last_audit_block_num + audit_time_limit) < block.number) {
            for (uint i=0; i<user_list.length; i++) {
                address payable user_addr = payable(user_list[i]);
                bool res = user_addr.send(audit_delay_cost);
                if (!res) {
                    revert("send money failed timelimit");
                }
                contract_balance-=audit_delay_cost;
            }
        }
    }

    function get_user(address user_addr, uint audit_num) public view returns (UserData memory) {
        User storage user = user_info[user_addr];
        return UserData(user_addr, user.last_audit_num,user.next_audit_num, user.user_data[audit_num]);
    }

    function get_all_users() public view returns (address[] memory) {
        return user_list;
    }

    function get_all_user_data(uint audit_num) public view returns (UserData[] memory) {
        UserData[] memory user_datas = new UserData[](user_list.length);
        uint user_count = 0;

        for (uint i = 0; i < user_list.length; i++) {
            address addr = user_list[i];
            User storage user = user_info[addr];
            if (user.user_data[audit_num].length  != 0) {
                UserData memory user_data = UserData(addr, user.last_audit_num, user.next_audit_num, user.user_data[audit_num]);
                user_datas[user_count] = user_data;
                user_count++;
            }
        }
        return user_datas;
    }

    function get_enclave_publickey() public view returns (bytes memory, bytes memory) {
        return (enclave_publickey, enclave_publickey_sig);
    }

    function hash_address_list(bytes memory prefix, address[] memory _addresses) public returns (bytes32) {
        uint len = _addresses.length;
        bytes memory packed = abi.encodePacked(prefix,"[");
        for (uint i = 0; i < len-1; i++) {
            packed = abi.encodePacked(packed,"\"",address2string(_addresses[i]),"\"",",");
        }
        if (len > 0) {
            packed = abi.encodePacked(packed,"\"", address2string(_addresses[len-1]),"\"");
        }
        packed = abi.encodePacked(packed,"]");
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix,uint2str(packed.length),packed);

        bytes32 hash = keccak256(packed);
        return hash;
    }

    function contains_address(address[] memory list, address val) internal pure returns (bool) {
        uint len = list.length;
        for (uint i = 0; i < len; i++) {
            if (list[i] == val) {
                return true;
            }
        }
        return false;
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
                revert("ECDSA: invalid signature 's' value");
            }
            address signer = ecrecover(hash, v, r, s);
            if (signer == address(0)) {
                revert("ECDSA: invalid signature");
            }
            return signer;
        } else {
            revert("ECDSA: invalid signature length");
        }
    }

    function address2string(address addr) public pure returns(string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory data = abi.encodePacked(addr);
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint i = 0; i < data.length; i++) {
            str[2+i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[3+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    function uint2str( uint256 _i ) internal pure returns (string memory str) {
        if (_i == 0)
        {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0)
        {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0)
        {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        str = string(bstr);
    }


    function bytes2Address(bytes memory bys) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 32))
        }
    }
}
