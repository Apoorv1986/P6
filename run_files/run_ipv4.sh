#!/bin/bash

#Defining the variables used to execute the components throughout the script
source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
test_argument=${2:-'7'}
trained=${3:-'1'}
runtime_json=${4:-'/vagrant/runtime-configurations/basic.json'}
netpaxos=${5:-0}

#Covering the scenario where no source code is provided, but only an option
if [ $# -eq 0 ]
  then
    echo "No arguments provided, executing with default values"
elif [ $# -gt 5 ]; then
  echo "Too many arguments provided. Please check the function call."
  echo "The program will exit now"
  exit
elif [ $# -lt 5 ]; then
  echo "Not all the arguments are provided. This can cause the program to misbehave. Please either provide all the arguments or none of them"
  echo "The program will exit now"
  exit
else
  echo "Executing program with the provided arguments"
fi


#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4/

#First we kill the controller and the switch
vagrant ssh controller  -c 'sudo pkill -f mycontroller_l3switch.py' &
vagrant ssh s1 -c 'sudo pkill -f simple_switch_grpc ' &
vagrant ssh agent -c 'sudo pkill -f net_' &
sleep 1 
vagrant ssh agent -c 'sudo pkill -f ipv4' &
sleep 4


#Starting switch S1
./config_scripts/s1.sh > /dev/null 2>&1 &
sleep 4

########## Setting up the environment ####################
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/actual.p4info --bmv2-json /vagrant/run_files/actual.json --runtime-json $runtime_json"  > /dev/null 2>&1 &
sleep 4


#After a small time, start the agent to run the experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/ipv4_fuzzer.py '$test_argument' '$netpaxos'" &

#Wait for the agent to produce results
sleep 540 #Worst case: all 200 packets gets dropped --> 100 seconds + a small buffer for the initialization time of the agent

#Copy the previous results somewhere
cp "./results/ipv4_fuzzer_results_$test_argument.txt" "./results/automated_results/ipv4_fuzzer_results_$test_argument"_original_run.txt

echo "RUN FINISHED"
