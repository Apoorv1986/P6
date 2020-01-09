#!/bin/bash
#Defining the variables used to execute the components throughout the script
source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
test_argument=${2:-'3'}
trained=${3:-'0'}
runtime_json=${4:-'/vagrant/runtime-configurations/basic.json'}
netpaxos=${5:-0}
random_act=${6:-0}

#Covering the scenario where no source code is provided, but only an option
if [ $# -eq 0 ]
  then
    echo "No arguments provided, executing with default values"
elif [ $# -gt 6 ]; then
  echo "Too many arguments provided. Please check the function call."
  echo "The program will exit now"
  exit
elif [ $# -lt 6 ]; then
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
sleep 4


#Starting switch S1
./config_scripts/s1.sh > /dev/null 2>&1 &
sleep 4

########## Setting up the environment ####################
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/actual.p4info --bmv2-json /vagrant/run_files/actual.json --runtime-json $runtime_json" > /home/apoorv/p4rl_tarantula/RL_for_P4/logs/controller_log & #   > /dev/null 2>&1 &
sleep 4

#After a small time, start the agent to run the experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained' '$netpaxos' '$random_act'" &

#Wait for the agent to produce results
sleep 180 #Worst case: all 100 packets gets dropped --> 50 seconds + a small buffer for the initialization time of the agent


#############################################################################################################################
#############################################################################################################################
########################################## PATCH PHASE  ####################################################################
#############################################################################################################################
#############################################################################################################################

#Copy the previous results somewhere
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_original_run.txt

exit

#As we have the results, now its time to apply the patch and test if it has solved the issues or not
#First we kill the controller and the switch
vagrant ssh controller  -c 'sudo pkill -f mycontroller_l3switch.py' &
vagrant ssh s1 -c 'sudo pkill -f simple_switch_grpc ' &
vagrant ssh agent -c 'sudo pkill -f net_' &
sleep 4

#Compile the patch
echo "Compiling P4 code"
p4c-bm2-ss --p4v 16 --p4runtime-file ~/p4rl_tarantula/RL_for_P4/run_files/patch.p4info --p4runtime-format text -o ~/p4rl_tarantula/RL_for_P4/run_files/patch.json ~/p4rl_tarantula/RL_for_P4/build/patch.p4

#Re-start the switch
./config_scripts/s1.sh > /dev/null 2>&1 &
sleep 4

#Re-start the controller
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/patch.p4info --bmv2-json /vagrant/run_files/patch.json --runtime-json $runtime_json"  > /dev/null 2>&1 &
sleep 4

#Start the verification experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained' '$netpaxos' '$random_act'" &
sleep 180 #Worst case: all 100 packets gets dropped --> 50 seconds + a small buffer for the initialization time of the agent


#Copy the previous results somewhere
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_patched_run.txt

echo "RUN FINISHED $test_argument"
