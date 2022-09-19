docker run --rm -v $PWD/../enclave/:/root/sgx/Heatmap/enclave/ \
                  -v $PWD/../demo/:/root/sgx/Heatmap/demo/ \
                  -v $PWD/../solidity/:/root/sgx/Heatmap/solidity/ \
                  -v $PWD/../scripts/:/root/sgx/Heatmap/scripts/ \
                  -p 5553:5553 -ti heatmap_enclave /bin/bash
