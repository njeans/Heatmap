project_root = "/root/sgx/Heatmap/"

colors = ['\033[93m', '\033[94m', '\033[95m', '\033[96m', '\033[90m', '\033[92m']
end = '\033[0m'

heatmap_info_beijing = {
    "map_file": "beijing.png",
    "min_lat": 39.5,
    "max_lat": 40.25,
    "min_long": 116.0,
    "max_long": 116.75,
    "min_x": 12950,
    "max_x": 13025,
    "min_y": 29600,
    "max_y": 29675
}

billboard_url = 'http://billboard:8545'
enclave_url = 'tcp://localhost:5553'

solidity_base_path = project_root + 'solidity/'
contract_source_path = 'Heatmap.sol'
allowed = [] #[solidity_base_path + "openzeppelin-contracts"]
accounts_path = project_root + "app/accounts/accounts.json"