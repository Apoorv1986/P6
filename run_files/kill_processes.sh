#!/bin/bash

#Kill the processes on the controller, switch, and the hosts
vagrant ssh controller  -c 'sudo pkill -f mycontroller_l3switch.py' &
sleep 2
vagrant ssh s1          -c 'sudo pkill -f simple_switch_grpc' &
sleep 2
vagrant ssh source -c 'sudo pkill -f receive_h1.py' &
sleep 2
vagrant ssh sink1  -c 'sudo pkill -f receive_h2.py' &
sleep 2
vagrant ssh sink2  -c 'sudo pkill -f receive_h3.py' &
sleep 2
vagrant ssh agent  -c 'sudo pkill -f net_agent' &
sleep 2
vagrant ssh agent  -c 'sudo pkill -f net_env' &
sleep 2





