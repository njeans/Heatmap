set -x

NUM_ACCOUNTS=10
docker run --rm --name heatmap_bb -it --publish 8545:8545 trufflesuite/ganache-cli:latest --deterministic nerla --accounts $NUM_ACCOUNTS --account_keys_path accounts.json --debug &
docker exec heatmap_bb cat accounts.json > accounts.json
