# Heatmap
This is a privacy preserving voluntary COVID-19 self-reporting platform for contact tracing. Users share your (encrypted) 
location history and test status, generate a heatmap of high exposure areas. 

# Demo

* build docker image in simulation mode
```bash
cd docker
docker-compose  build
```

* run ganache server for billboard
```bash
docker-compose  up -d billboard
```
* wait 2 secs for the billboard to get situated

* run demo
```bash
docker-compose up enclave
```

or 

```bash
docker-compose run --rm enclave /bin/bash
```

## Demo output
![Output of Demo](docs/demo1.png?raw=true)
* Signup 4 users
* User 1's data is omitted from processing by the admin, so they receive payout
* User 2 & 3 data was included by the admin
* User 4 data was omitted by themselves and posted to bulletin board but was includen by the admin via the bulletin board

# Based on
SafeTrace from srtlabs

[scrt/SafeTrace](https://github.com/scrtlabs/SafeTrace.git)
