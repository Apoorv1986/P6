#!/bin/bash

#source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4_4/P4/basic_clone.p4'}

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_4/P4

vagrant ssh s4  -c "sudo /vagrant/P4/sxconfig.sh" &
sleep 30
vagrant ssh s4 -c "sudo /vagrant/P4/sxconfig-secondpart.sh" &
echo "Finished"
