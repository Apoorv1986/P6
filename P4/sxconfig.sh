#!/bin/bash


#export SDE=/vagrant/P4/bf-sde-8.3.0
cd /vagrant/P4/bf-sde-8.3.0/
source ./tools/set_sde.bash
cd /vagrant/P4/bf-sde-8.3.0/tools/


# now build your p4 program with the p4_build script: (adjust: path to p4 program, P4_NAME)
./p4_build.sh --with-p4c=/vagrant/P4/bf-sde-8.3.0/p4c-compilers-8.3.0-beta.1/p4c-compilers-8.3.0-beta.1.x86_64/bin/p4c-barefoot /vagrant/P4/basic_tofino.p4 P4_NAME=basictofino P4PPFLAGS="-I /vagrant/P4/bf-sde-8.3.0/p4c-compilers-8.3.0-beta.1/p4c-compilers-8.3.0-beta.1.x86_64/share/p4c/p4include" P4FLAGS="--std p4-16 --target tofino --arch tna --p4runtime-file /vagrant/P4/basictofino.p4info --p4runtime-format text"

# after build is complete copy the context.json and tofino.bin from the $P4_NAME.out directory to /vagrant/P4/bf-sde-8.3.0/install/share/tofinopd/tnalpmfix/pipe/
# adjust path to $P4_NAME.bfa

/vagrant/P4/bf-sde-8.3.0/p4c-compilers-8.3.0-beta.1/p4c-compilers-8.3.0-beta.1.x86_64/bin/bfas /vagrant/P4/bf-sde-8.3.0/build/p4-build/basictofino/tofinopd/basictofino/pipe/basic_tofino.bfa
cd basic_tofino.out/
mkdir /vagrant/P4/bf-sde-8.3.0/install/share/tofinopd/basictofino/pipe/
mv * /vagrant/P4/bf-sde-8.3.0/install/share/tofinopd/basictofino/pipe/

cd /vagrant/P4/bf-sde-8.3.0/
# run tofino model with your P4 program (adjust name after -p flag)
./run_tofino_model.sh -p basictofino -f ../ports.json
