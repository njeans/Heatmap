# FROM rust-sgx-docker
FROM initc3/teaclave-sgx-sdk:e8a9fc22

RUN apt-get update -y && apt-get install -y libzmq3-dev
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt install -y llvm-dev libclang-dev clang python3-dev python3-pip libjpeg-dev zlib1g-dev solc
#RUN pip3 install requests pycryptodome zmq secp256k1 numpy pandas matplotlib

RUN ln -s /opt/sgxsdk /opt/intel/sgxsdk
ENV SGX_MODE=SW
ENV SGX_SDK_RUST=/root/sgx/incubator-teaclave-sgx-sdk-master
RUN git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git \
  /root/sgx/incubator-teaclave-sgx-sdk-master \
  && cd /root/sgx/incubator-teaclave-sgx-sdk-master \
  && git checkout e8a9fc22

RUN git clone https://github.com/njeans/sgxoram.git /root/sgx/sgxoram \
      && cd /root/sgx/sgxoram \
      && git checkout sgx_sdk_compat

ENV PATH=/root/.cargo/bin/:$PATH
ENV SGX_SDK=/opt/sgxsdk
ENV PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$SGX_SDK/sdk_libs

RUN cargo install bindgen

ENV IAS_SGX_PRIMARY_KEY=""
ENV IAS_SGX_SPID=""

ENV PROJECT_ROOT=/root/sgx/Heatmap
ENV D=$PROJECT_ROOT/app
ENV E=$PROJECT_ROOT/enclave
RUN echo alias build="'cd $E && make'" >> ~/.bashrc
RUN echo alias start="'cd $E/bin && ./heatmap-app > log & '" >> ~/.bashrc
RUN echo alias reset="'rm $E/bin/*.sealed'" >> ~/.bashrc
RUN echo alias demo="'cd $D && python3 demo.py'" >> ~/.bashrc
RUN echo alias log="'cat $E/bin/log'" >> ~/.bashrc
RUN echo alias stop="'pkill heatmap-app'" >> ~/.bashrc
RUN #source ~/.bashrc

COPY ./app $PROJECT_ROOT/app
RUN pip3 install -r $D/requirements.txt

COPY ./solidity $PROJECT_ROOT/solidity
COPY ./enclave $PROJECT_ROOT/enclave
COPY ./scripts/run.sh $PROJECT_ROOT/scripts/

WORKDIR $E
RUN make clean && make

WORKDIR $PROJECT_ROOT/scripts
CMD ['./run.sh']