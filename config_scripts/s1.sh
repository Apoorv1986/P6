#!/bin/bash
echo "Starting s1 ..."
vagrant ssh s1 -c 'sudo simple_switch_grpc --log-file ./s1.log -i 0@enp0s9 -i 1@enp0s10 -i 2@enp0s16 --no-p4 -- --cpu-port 64'

