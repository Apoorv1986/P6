#!/bin/bash

#This script calls the automated test runs for each of the application we are plannign to test

#Move to the correct directory
#cd /home/apoorv/p4rl_tarantula/RL_for_P4/run_files
#First test with basic.p4
#echo "Starting environment 1"
#./automate_ipv4_baseline_tests.sh & # > /dev/null 2>&1 &
#sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/run_files
#Run with basic_tunnel.p4
echo "Starting environment 2"
./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/tutorials/exercises/basic_tunnel/solution/basic_tunnel.p4 /vagrant/runtime-configurations/basic_tunnel.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_3/run_files
#Run with advanced_tunnel.p4
echo "Starting environment 3"
./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/tutorials/exercises/p4runtime/advanced_tunnel.p4 /vagrant/runtime-configurations/advanced_tunnel.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
#cd /home/apoorv/p4rl_tarantula/RL_for_P4_4/run_files
#Run with load-balancer
#echo "Starting environment 4"
#./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/tutorials/exercises/load_balance/solution/load_balance.p4 /vagrant/runtime-configurations/load_balance.json > /dev/null 2>&1 &
#sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_5/run_files
#Run with MRI
echo "Starting environment 5"
./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/tutorials/exercises/mri/solution/mri.p4 /vagrant/runtime-configurations/mri.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_6/run_files
#Run with Netpaxos-acceptor
echo "Starting environment 6"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/acceptor.p4 /vagrant/runtime-configurations/acceptor.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_7/run_files
#Run with Netpaxos-leader
echo "Starting environment 7"
./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/leader.p4 /vagrant/runtime-configurations/leader.json & # > /dev/null 2>&1 &
sleep 15

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_8/run_files
#Run with Netpaxos-learner
echo "Starting environment 8"
./automate_ipv4_baseline_tests.sh  /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/learner.p4 /vagrant/runtime-configurations/learner.json & # > /dev/null 2>&1 &

echo "Everythign has been executed in the first iteration. Entering LONG SLEEP now"
#Wait until all the 10 testruns finishes
#sleep  8500 #37500 #Measurements shown that it takes 7.5 hours, which is 27000 seconds. To be save, we added an extra 10 minutes
wait

echo "Saving the results of the first iteration"
#Save all the results
cd /home/apoorv/p4rl_tarantula/RL_for_P4/results
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv ./backup/final-ipv4-results-basic.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_2/results/final_results.csv ./backup/final-ipv4-results-basic_tunnel.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_3/results/final_results.csv ./backup/final-ipv4-results-advanced_tunnel.csv
#cp /home/apoorv/p4rl_tarantula/RL_for_P4_4/results/final_results.csv ./backup/final-ipv4-results-load_balance.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_5/results/final_results.csv ./backup/final-ipv4-results-mri.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_6/results/final_results.csv ./backup/final-ipv4-results-acceptor.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_7/results/final_results.csv ./backup/final-ipv4-results-leader.csv
cp /home/apoorv/p4rl_tarantula/RL_for_P4_8/results/final_results.csv ./backup/final-ipv4-results-learner.csv


#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_4/run_files
#Run with switch.p4
#./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/switch_p416.p4 /vagrant/runtime-configurations/switch_p416_runtime.json > /dev/null 2>&1 &



#echo "Everything has been executed in the second iteration. Entering LONG SLEEP now"
#Wait until all the 10 testruns finishes
#sleep 27600 #Measurements shown that it takes 7.5 hours, which is 27000 seconds. To be save, we added an extra 10 minutes


#echo "Saving the results of the second iteration"
#Save all the results
#cd /home/apoorv/p4rl_tarantula/RL_for_P4_5/results
#cp ./final-results.csv ./backup/final-ipv4-results-switchp4.csv
