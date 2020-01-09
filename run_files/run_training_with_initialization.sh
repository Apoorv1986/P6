#!/bin/bash

#Defining the variables used to execute the components throughout the script
source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
test_argument=${2:-'3'}
trained=${3:-'0'}
netpaxos=${4:-0}
random_act=${5:-0}

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

#Calling the code-reader to check for defined header types
python ./build/p4_code_reader_v2.py $source_code

#Before starting any component, make sure that they are not existing anymore
./run_files/kill_processes.sh > /dev/null 2>&1 &
sleep 10


#Compiling the code
echo "Compiling P4 code"
p4c-bm2-ss --p4v 16 --p4runtime-file ~/p4rl_tarantula/RL_for_P4/run_files/actual.p4info --p4runtime-format text -o ~/p4rl_tarantula/RL_for_P4/run_files/actual.json $source_code
#Copy compile results for later usage
cp $source_code ~/p4rl_tarantula/RL_for_P4/run_files/actual.p4
sleep 5

#Starting switch S1
./config_scripts/s1.sh > /dev/null 2>&1 &
sleep 4

########## Setting up the environment ####################
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/actual.p4info --bmv2-json /vagrant/run_files/actual.json --runtime-json /vagrant/runtime-configurations/basic.json"  > /dev/null 2>&1 &
sleep 4

#Start up the receivers on each host
echo "Starting the listeners on the hosts"
vagrant ssh source -c 'sudo /vagrant/hosts/receive_h1.py "192.168.0.2" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
vagrant ssh sink1  -c 'sudo /vagrant/hosts/receive_h2.py "192.168.0.5" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
vagrant ssh sink2  -c 'sudo /vagrant/hosts/receive_h3.py "192.168.0.9" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
sleep 5

#After a small time, start the agent to run the experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained' '$netpaxos' '$random_act'" &

#Wait for the agent to produce results
sleep 180 #Worst case: all 200 packets gets dropped --> 100 seconds + a small buffer for the initialization time of the agent

#Copy the previous results somewhere
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_original_run.txt

echo "TRAINING RUN FINISHED"
