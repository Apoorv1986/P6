#!/bin/bash

cd /vagrant/P4/bf-sde-8.3.0/
source ./tools/set_sde.bash
# run run_switchd.sh (in bf-sde-8.3.0 directory)
./run_switchd.sh -p basictofino

