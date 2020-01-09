#!/bin/bash

#This script calls the automated test runs for each of the application we are plannign to test

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/run_files
#Run with basic.p4
echo "Starting environment 2"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_2/P4/basic_tofino.p4 /vagrant/runtime-configurations/basic.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_3/run_files
#Run with basic_tunnel.p4
echo "Starting environment 3"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_3/P4/basic_tunnel_tofino.p4 /vagrant/runtime-configurations/basic_tunnel.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_4/run_files
#Run with advanced_tunnel
echo "Starting environment 4"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_4/P4/advanced_tunnel_tofino.p4 /vagrant/runtime-configurations/advanced_tunnel.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_5/run_files
#Run with MRI
echo "Starting environment 5"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_5/P4/mri_tofino.p4 /vagrant/runtime-configurations/mri.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_6/run_files
#Run with Netpaxos-acceptor
echo "Starting environment 6"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_6/P4/acceptor_tofino.p4 /vagrant/runtime-configurations/acceptor.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_7/run_files
#Run with Netpaxos-leader
echo "Starting environment 7"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_7/P4/leader_tofino.p4 /vagrant/runtime-configurations/leader.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_8/run_files
#Run with Netpaxos-learner
echo "Starting environment 8"
./automate_tofino_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4_8/P4/learner_tofino.p4 /vagrant/runtime-configurations/learner.json & # > /dev/null 2>&1 &

echo "Everything has been executed in the first iteration. Entering LONG SLEEP now"
#Wait until all the 10 testruns finishes
#sleep  8500 #37500 #Measurements shown that it takes 7.5 hours, which is 27000 seconds. To be save, we added an extra 10 minutes
wait

echo "Saving the results of the first iteration"
#Save all the results
cd /home/apoorv/p4rl_tarantula/RL_for_P4/results
cp /home/apoorv/p4rl_tarantula/RL_for_P4_2/results/final_results.csv ./backup/final-tofino-results-basic.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_3/results/final_results.csv ./backup/final-tofino-results-basic_tunnel.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_4/results/final_results.csv ./backup/final-tofino-results-advanced_tunnel.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_5/results/final_results.csv ./backup/final-tofino-results-mri.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_6/results/final_results.csv ./backup/final-tofino-results-acceptor.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_7/results/final_results.csv ./backup/final-tofino-results-leader.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_8/results/final_results.csv ./backup/final-tofino-results-learner.csv
