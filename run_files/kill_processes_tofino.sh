#!/bin/bash

#Kill the processes on the controller, switch, and the hosts
vagrant ssh s3 -c 'sudo pkill -f tofino' &
sleep 2
vagrant ssh source3 -c 'sudo pkill -f receive_h1.py' &
sleep 2
vagrant ssh sink31  -c 'sudo pkill -f receive_h2.py' &
sleep 2
vagrant ssh sink32  -c 'sudo pkill -f receive_h3.py' &
sleep 2
vagrant ssh agent3  -c 'sudo pkill -f net_agent_multi_actions_full_keras_DDQN.py' &




