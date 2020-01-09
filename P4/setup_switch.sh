#!/bin/bash

sudo pkill -f python

export http_proxy=proxy.routerlab:8080
export https_proxy=proxy.routerlab:8080
git config --global http.proxy proxy.routerlab:8080
git config --global https.proxy proxy.routerlab:8080


sudo dpkg --configure -a


cd /vagrant/P4/bf-sde-8.3.0/
source ./tools/set_sde.bash
./build_sde.sh
sudo ln -s /vagrant/P4/bf-sde-8.3.0/p4c-compilers-8.3.0-beta.1/p4c-compilers-8.3.0-beta.1.x86_64/bin/p4c-gen-bfrt-conf /usr/local/bin
sudo ln -s /vagrant/P4/bf-sde-8.3.0/p4c-compilers-8.3.0-beta.1/p4c-compilers-8.3.0-beta.1.x86_64/bin/p4c-manifest-config /usr/local/bin
source ./tools/set_sde.bash

sudo /vagrant/P4/bf-sde-8.3.0/install/bin/dma_setup.sh

