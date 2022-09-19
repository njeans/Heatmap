
p=$PWD

docker run -v $PWD:/sources/ ethereum/solc:stable -o /sources/output --base-path  /sources --overwrite --abi --bin /sources/Heatmap.sol