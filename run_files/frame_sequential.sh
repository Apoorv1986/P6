#!/bin/bash

#This script calls the automated test runs for each of the application in a sequential order
#It is heavily advised to run the script within a screen session, as the approximate runtime is 120 hours
#This script tests 7 application, with three different methods: P6, IPv4-based fuzzer and naive fuzzer
#This means an overall of 21 test, running them 10 times, and to test one program once is approximately 30 minutes

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4/run_files
#First test with basic.p4
echo "Starting basic.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic/solution/basic.p4 /vagrant/runtime-configurations/basic.json 0 0 &  # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic/solution/basic.p4 /vagrant/runtime-configurations/basic.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic/solution/basic.p4 /vagrant/runtime-configurations/basic.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_naive.csv

#Run with basic_tunnel.p4
echo "Starting basic_tunnel.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic_tunnel/solution/basic_tunnel.p4 /vagrant/runtime-configurations/basic_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_tunnel_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic_tunnel/solution/basic_tunnel.p4 /vagrant/runtime-configurations/basic_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_tunnel_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/basic_tunnel/solution/basic_tunnel.p4 /vagrant/runtime-configurations/basic_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-basic_tunnel_naive.csv

#Run with advanced_tunnel.p4
echo "Starting advanced_tunnel.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/p4runtime/advanced_tunnel.p4 /vagrant/runtime-configurations/advanced_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-advanced_tunnel_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/p4runtime/advanced_tunnel.p4 /vagrant/runtime-configurations/advanced_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-advanced_tunnel_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/p4runtime/advanced_tunnel.p4 /vagrant/runtime-configurations/advanced_tunnel.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-advanced_tunnel_naive.csv

#Run with MRI
echo "Starting mri.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/mri/solution/mri.p4 /vagrant/runtime-configurations/mri.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-mri_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/mri/solution/mri.p4 /vagrant/runtime-configurations/mri.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-mri_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/tutorials/exercises/mri/solution/mri.p4 /vagrant/runtime-configurations/mri.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-mri_naive.csv


#Run with Netpaxos-acceptor
echo "Starting netpaxos-acceptor.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/acceptor.p4 /vagrant/runtime-configurations/acceptor.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_acceptor_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/acceptor.p4 /vagrant/runtime-configurations/acceptor.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_acceptor_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/acceptor.p4 /vagrant/runtime-configurations/acceptor.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_acceptor_naive.csv

#Run with Netpaxos-leader
echo "Starting netpaxos-leader.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/leader.p4 /vagrant/runtime-configurations/leader.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_leader_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/leader.p4 /vagrant/runtime-configurations/leader.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_leader_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/leader.p4 /vagrant/runtime-configurations/leader.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_leader_naive.csv

#Run with Netpaxos-learner
echo "Starting netpaxos-learner.p4 tests"
./automate_testing.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/learner.p4 /vagrant/runtime-configurations/learner.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_learner_p6.csv
#Starting IPv4-based fuzzer tests
echo "Starting IPv4-based fuzzer tests"
./automate_ipv4_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/learner.p4 /vagrant/runtime-configurations/learner.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_learner_ipv4.csv
#Starting naive fuzzer tests
echo "Starting naive fuzzer tests"
./automate_naive_baseline_tests.sh /home/apoorv/p4rl_tarantula/RL_for_P4/P4/p4xos-public/p4-16/p4src/learner.p4 /vagrant/runtime-configurations/learner.json 0 0 & # > /dev/null 2>&1 &
wait
#Save the results
echo "Saving the results"
cp /home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv /home/apoorv/results/backup/final-results-netpaxos_learner_naive.csv

echo "Everythign has been executed"



