########################################################################################################################
#
# The following creates the environment used for the bug finding use case problem
#
# States are defined as the set of all possible strings x on the alphabet E = {0,1}* (currently not bit but byte
# representation)
#
# Actions are applied on substrings x'
#
# Dependencies/Requirements:
# Make sure to install all packages from requirements.txt and if VirtualBox is used make sure to copy SSH key to the VM
# In order to make use of scapy use python-sudo.sh script to run pyhton interpreter as root (adapt to your environments
# paths)
########################################################################################################################

import numpy as np
from scapy.all import *
from scapy.all import Ether, ICMP, IP, TCP, UDP, Raw
import binascii
import paramiko
import json
import os
import time
import sys

############### global config ###############
SEND_PATH = "/vagrant/hosts/"
location_tarantula_module="/vagrant/build/tarantula.py"
location_tarantula_log="/vagrant/logs/tarantula_log.txt"
p4_accepted_protocols="/vagrant/build/code_reader_output.txt"
Host_IP = '0.0.0.0'
#Host_IP = '192.168.102.224'
#Host_IP = '141.23.167.7'
#Host_IP = '192.168.178.36'
header_array = []


# remove the offsets 0 and 6 to check if agent performs better
offset_list=[14,15,16,18,20,22,23,24,26,30]
packet_header_list=[]
ip_address_list=[]
other_ip_fields_list=[]
ip_to_port = {'172.16.20.100':[2], '172.16.30.100':[3]}
port_to_mac = {2:'00:00:00:00:04:10', 3:'00:00:00:00:04:12'}

vers_len_ip_list=[]
tos_id_ip_list=[]
len_id_ip_list=[]
id_flags_ip_list=[]
flags_proto_ip_list=[]
ttl_chksum_ip_list=[]



valid_dst_ips = ['172.16.20.100', '172.16.30.100']
invalid_dst_ips = []
valid_macs = ['00:00:00:00:01:01', '00:00:00:00:01:02']


################################## main() only used for testing #######################################################
def main():
    env = networkEnv(4, True)
    #env.reset()
    reward_list=[]

    #for i in range(0,100):
    #    _, reward = env.execute(0)
    #    reward_list.append(reward)
        #time.sleep(1)
    #    env.reset()
        #time.sleep(1)
    #    print("########### Reward over time: ", sum(reward_list))


    #ime.sleep(1)
    #env.reset()


################################## Class for network environment #######################################################
    # Creates the environment the agent will interact with
    # States are defined as a "substring" of a packet header
    # Actions are pre-defined in action_set
    # As start state a header out of header_array is randomly chosen and a random sample with size width is chosen as
    # "substring" describing the initial state
    # Input:
    #   width: number of bytes (size of the states)
    # Returns:
    #   environment for agents to use
class networkEnv():
    def __init__(self, width, verbose,loc=True, netp=False):
        #self.x = header_array[initHeader_index]
        self.actions = 2
        self.netpaxos = netp
        self.x = bytearray()
        self.width = width
        self.offset = 0
        self.debug = verbose
        self.right_boundary = 1
        self.state = bytes()
        self.header_field = bytes()
        self.offset_list = []
        self.valid_dst_ips_temp = []
        self.valid_macs_temp = []
        self.ip_to_port = {}
        self.port_to_dstmac = {}
        self.match_to_port = {}
        self.table_entries = {}
        self.receive_stop = False
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_server_tread = threading.Thread(target=self.socket_server).start()
        self.accepted_protocols = []
        self.initialize_lists()
        self.reset()
        self.reward_system = rewardSys(verbose=verbose, loc=loc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        #print("cleaning now")
        #self.reward_system.cleanup()
        return

    def __del__(self):
        print("Network Env deleted")

    def clean_up(self):
        print("cleaning now")
        self.reward_system.cleanup()
        time.sleep(1)
        del self.reward_system

    def socket_server(self):
        #udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.udp is None:
            print("udp is None")
        try:
            print("starting UDP server")
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp.bind((Host_IP, 9988))
        except:
            print("Nope the UDP socket couldnt be bound")

        input_ = [self.udp]
        verbose = self.debug
        def parse_json(msg):
            self.receive_stop = True
            self.udp=None
            json_msg = json.loads(msg, encoding = "ISO-8859-1")
            print("got to json parser")
            print(json_msg)
            self.table_entries = json_msg
            for entry in json_msg['table_entries']:
                if 'port' in entry['action_params']:
                    for key in entry['action_params'].keys():
                        if ('addr' in key) or ('Addr' in key):
                            print("key: ", key)
                            print('addr in key: ', ('addr' in key) or ('Addr' in key))
                            self.port_to_dstmac[int.from_bytes(entry['action_params']['port'].encode(), byteorder='big')] = entry['action_params'][key]
                            #if entry['action_params'][key] != '00:00:00:00:01:01':
                            self.valid_macs_temp.append(entry['action_params'][key])
                    for val in entry['match'].keys():
                        if 'ip' in val:
                            self.ip_to_port[entry['match'][val]] = int.from_bytes(entry['action_params']['port'].encode(), byteorder='big')
                            if entry['match'][val]!= '10.0.1.1':
                                self.valid_dst_ips_temp.append(entry['match'][val])

        def receive_stop():
            self.receive_stop = True
        ######################## UDP and TCP corresponding clients ############################
        # UDP client to receive the messages
        # Parameters:
        #   Input:
        #   Output:
        class Client(Thread):
            def __init__(self, socket, address, sock_type):
                Thread.__init__(self)
                self.sock = socket
                self.addr = address
                self.type = sock_type
                self.start()

            def run(self):

                while 1:
                    if verbose:
                        print("Client sent:")
                    if self.type == "udp":
                        try:
                            msg, address = self.sock.recvfrom(1024)
                            print(address)
                        except OSError:
                            msg = None
                            print("OS Error: ", OSError)

                        if verbose:
                            print("message:", msg)
                        if msg is None:
                            break
                        else:
                            parse_json(msg)
                            receive_stop()
                        break
                    else:
                        break
        if self.debug:
            print("server started and is listening")

        nothing_recv=True
        while not self.receive_stop:
            if self.udp is None:
                print("udp is None")
                break

            # check for TCP or UDP connection and call the right client
            s = None
            try:
                inputready, outputready, exceptready = select(input_, [], [])
                for s in inputready:
                    if s == self.udp:
                        Client(s, None, "udp")

            except KeyboardInterrupt:
                if s:  # <---
                    s.close()
                break  # <---
            except ValueError:
                print("Value error: ", ValueError)
                if s:  # <---
                    s.close()
                if self.udp:
                    self.udp.close()
                break  # <---

        print("shutdown and close executed")
        try:
            self.udp.shutdown(2)
            self.udp.close()
        except:
            return

    def initialize_lists(self):
        
        protocols= open(p4_accepted_protocols)
        for line in protocols:
            if "ipv4" in line:
                self.accepted_protocols.append("ipv4")
            if "ethernet" in line:
                self.accepted_protocols.append("ethernet")
        protocols.close()

        if "ipv4" not in self.accepted_protocols or "ethernet" not in self.accepted_protocols:
            sys.exit("not possible")
        time.sleep(10)
        if self.udp is not None:
            try:
                self.udp.shutdown(2)
            except OSError:
                print("OS Error: ", OSError)
                pass
            self.udp.close()
            time.sleep(1)
            self.udp = None
            print("watned to delete")

        #valid_dst_ips.extend(self.valid_dst_ips_temp)
        rand_ip_list = []
        for i in range(1000):
            rand_ip = np.random.randint(low=0, high=256,size=4)
            rand_ip_list.append("{}.{}.{}.{}".format(rand_ip[0], rand_ip[1], rand_ip[2], rand_ip[3]))

        invalid_dst_ips.extend(rand_ip_list)
        #valid_macs.extend(self.valid_macs_temp)

#
        netp_ip_to_port = {'172.16.20.100':[2], '172.16.30.100':[2]}
        netp_port_to_mac = {2:'00:00:00:00:04:10', 3:'00:00:00:00:04:12'}
        netp_valid_macs = ['00:00:00:00:01:01']
        
        no_netp_ip_to_port = {'172.16.20.100':[2], '172.16.30.100':[3]}
        no_netp_port_to_mac = {2:'00:00:00:00:04:10', 3:'00:00:00:00:04:12'}
        no_netp_valid_macs = ['00:00:00:00:01:01', '00:00:00:00:01:02']

        if self.netpaxos:    
            ip_to_port.update(netp_ip_to_port)
            port_to_mac.update(netp_port_to_mac)
        else:
            ip_to_port.update(no_netp_ip_to_port)
            port_to_mac.update(no_netp_port_to_mac)
        #if self.port_to_dstmac:
        #    port_to_mac.update(self.port_to_dstmac)
        print("self.table_entries: ", self.table_entries)
        print("self.ip_to_port: ", self.ip_to_port)
        print("self.port_to_mac: ", self.port_to_dstmac)
        print("valid_ips: ", valid_dst_ips)
        print("valid_macs: ", valid_macs)
        print("ip_to_port: ", ip_to_port)
        print("port_to_mac: ", port_to_mac)
        for elem in valid_dst_ips:
            if elem in invalid_dst_ips:
                invalid_dst_ips.remove(elem)
        
        packet_header_list.clear()
        ip_address_list.clear()
        other_ip_fields_list.clear()
        vers_len_ip_list.clear()
        tos_id_ip_list.clear()
        len_id_ip_list.clear()
        id_flags_ip_list.clear()
        flags_proto_ip_list.clear()
        ttl_chksum_ip_list.clear()
        header_array.clear()
        header_array.append(bytes(Ether(src='00:00:00:00:00:02', dst='10:00:00:00:00:01') /
                                  IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=5000, dport=5111)))
        for i in range(0, 1000):

            pkt = Ether(src=valid_macs[np.random.randint(0, len(valid_macs))], dst=valid_macs[np.random.randint(0, len(valid_macs))]) / \
                      IP(version=np.random.choice([4, np.random.randint(0, 16)], p=[0.8, 0.2]),
                         ihl=np.random.choice([np.random.randint(4,6), np.random.randint(0, 15)], p=[0.8, 0.2]),
                         tos=np.random.randint(0, 256),
                         len=np.random.choice([np.random.randint(19, 21), np.random.choice(range(0,61,4)), np.random.randint(0, 65536)], p=[0.4,0.4, 0.2]),
                         id=np.random.randint(0, 65536),
                         flags=np.random.randint(0, 8),
                         frag=np.random.randint(0, 8192),
                         ttl=np.random.choice([np.random.randint(0,2), np.random.randint(0,256)], p=[0.9,0.1]),
                         proto=np.random.randint(0, 256),
                         src=valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                         dst=valid_dst_ips[np.random.randint(0, len(valid_dst_ips))]) / np.random.bytes(40)#TCP(sport=5678, dport=1234)/ TCP(sport=5678, dport=1234)

            pkt_2 = Ether(src=valid_macs[np.random.randint(0, len(valid_macs))], dst=valid_macs[np.random.randint(0, len(valid_macs))]) / \
                      IP(version=np.random.choice([4, np.random.randint(0, 16)], p=[0.95, 0.05]),
                         ihl=np.random.choice([5, np.random.randint(6, 15)], p=[0.95, 0.05]),
                         tos=np.random.randint(0, 256),
                         len=np.random.choice([np.random.randint(40, 80), np.random.randint(20, 65536)], p=[0.95, 0.05]),
                         id=np.random.randint(0, 65536),
                         flags=np.random.randint(0, 8),
                         frag=np.random.randint(0, 8192),
                         ttl=np.random.choice([np.random.randint(0, 2), np.random.randint(0, 256)], p=[0.001, 0.999]),
                         proto=np.random.randint(0, 256),
                         src=np.random.choice([valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                                               invalid_dst_ips[np.random.randint(0, len(invalid_dst_ips))]], p=[0.9,0.1]),
                         dst=np.random.choice([valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                                               invalid_dst_ips[np.random.randint(0, len(invalid_dst_ips))]], p=[0.9,0.1])) / TCP(sport=5678, dport=1234)

            try:
                #pkt[IP].show2()
                pkt = Ether(bytes(pkt))
                #print(pkt[IP].chksum)
                pkt = bytes(pkt)
                pkt_2 = Ether(bytes(pkt_2))
                pkt_2 = bytes(pkt_2)
                #print("packet in hex: ", binascii.hexlify(pkt))
                packet_header_list.append(pkt_2)
                ip_address_list.append(pkt[26:30])
                ip_address_list.append(pkt[30:34])
                other_ip_fields_list.append(pkt[14:18])
                other_ip_fields_list.append(pkt[15:19])
                other_ip_fields_list.append(pkt[16:20])
                other_ip_fields_list.append(pkt[18:22])
                other_ip_fields_list.append(pkt[20:24])
                other_ip_fields_list.append(pkt[22:26])

                vers_len_ip_list.append(pkt[14:18])
                tos_id_ip_list.append(pkt[15:19])
                len_id_ip_list.append(pkt[16:20])
                id_flags_ip_list.append(pkt[18:22])
                flags_proto_ip_list.append(pkt[20:24])
                ttl_chksum_ip_list.append(pkt[22:26])

                #print(pkt[26:30])
            except:
                print("didnt work")
        print("vers_len_ip_list length: ", len(vers_len_ip_list))
        print("len_id_ip_list length: ", len(len_id_ip_list))
        print("flags_proto_ip_list length: ", len(flags_proto_ip_list))
        time.sleep(3)
            # pkt.show()

################################## reset network environment ###########################################################
    # Resets the state of the environment by chosing random sample from header_array and randomly choose a "substring"
    # with size width
    # Input:
    #   -
    # Returns:
    #   resetted environment
    def reset(self):
        self.offset_list = []
        self.x = bytearray(bytes(packet_header_list[np.random.randint(0,len(packet_header_list))]))
        #self.offset = np.random.choice(offset_list)
        #self.right_boundary = self.offset+self.width
        if self.debug:
            print("offset: ", self.offset)
            print("right_boundary: ", self.right_boundary)
            print("type offset: " , type(self.offset))
            print("type right_boundary: ", type(self.right_boundary))
        x_1 = self.x[14:34]
        state = x_1
        self.state = state
        if self.debug:
            print("length of state is: ", len(state))
        return state

################################## apply action chosen by agent ########################################################
    # Applies action chosen by agent in current step by calling execute() and evaluates its reward by calling
    # check_reward()
    # Input:
    #   action: action_set index defining the action to be executed
    # Returns:
    #   reward: reward of the agent after executing action
    def apply_action(self, action):
        result = self.execute(action)

        reward = self.check_reward()
        return reward

################################## retrieve agent's reward #############################################################
    # Creates packet with modified header and sends it to P4 program to be tested
    # Calculates reward for agent
    # Input:
    #   -
    # Returns:
    #   reward: reward of the agent after executing action
    def check_reward(self):
        x = self.x
        #x[self.offset:self.right_boundary] = self.header_field

        # recalculate checksum if fields are modified at an offset that does not include the IP checksum
        if (22 in self.offset_list) or (23 in self.offset_list) or (24 in self.offset_list):
            #print("came to no checksum recalc")
            #print("Offset List: ", self.offset_list)
            pkt = Ether(bytes(x))
        # if checksum field is specifically modified dont recalculate checksum to trigger sent_checksum bug
        else:
            #print("came into the checksum recalc")
            #print("Offset List: ", self.offset_list)
            pkt = Ether(bytes(x))
            del pkt[IP].chksum
            pkt = Ether(bytes(pkt))

        reward = self.reward_system.send_packet_and_generate_reward(pkt)

        return reward

    def check_random_reward(self):
        x = np.random.bytes(80)
        pkt = Ether(bytes(x))
        reward = self.reward_system.send_packet_and_generate_reward(pkt)
        return reward

    def copy_bytes_from_ether_list(self):
        result = 0
        return result

    def copy_bytes_from_other_ip_fields_list(self):
        result = np.random.choice(other_ip_fields_list)
        return result

    def copy_bytes_from_vers_len_ip_list(self):
        result = np.random.choice(vers_len_ip_list)
        return result

    def copy_bytes_from_tos_id_ip_list(self):
        result = np.random.choice(tos_id_ip_list)
        return result

    def copy_bytes_from_len_id_ip_list(self):
        result = np.random.choice(len_id_ip_list)
        return result

    def copy_bytes_from_id_flags_ip_list(self):
        result = np.random.choice(id_flags_ip_list)
        return result

    def copy_bytes_from_flags_proto_ip_list(self):
        result = np.random.choice(flags_proto_ip_list)
        return result

    def copy_bytes_from_ttl_chksum_ip_list(self):
        result = np.random.choice(ttl_chksum_ip_list)
        return result

    def copy_bytes_from_ip_address_list(self):
        result = np.random.choice(ip_address_list)
        return result

################################## execute chosen action ###############################################################
    # Execute specified action to modify the given part of the header
    # Input:
    #   action: string retrieved from action_set defining the action to be executed
    # Returns:
    #   modified header part
    def execute(self, action):
        reward = None
        if action == 0:
            self.offset = 14
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 1:
            self.offset = 15
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 2:
            self.offset = 16
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 3:
            self.offset = 18
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 4:
            self.offset = 20
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 5:
            self.offset = 22
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 6:
            self.offset = 23
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 7:
            self.offset = 24
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 8:
            self.offset = 26
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 9:
            self.offset = 14
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_vers_len_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 10:
            self.offset = 15
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_tos_id_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 11:
            self.offset = 16
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_len_id_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 12:
            self.offset = 18
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_id_flags_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 13:
            self.offset = 20
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_flags_proto_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 14:
            self.offset = 22
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ttl_chksum_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 15:
            self.offset = 26
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ip_address_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 16:
            self.offset = 30
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ip_address_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 17:
            pass
        elif action == 18:
            reward = self.check_reward()
        elif action == 19:
            pass
        # TODO: implement more Actions
        return self.state, reward



################################## Class for reward system #############################################################
    # Uses SSH client to connect to specified VirtualBox VM and sends a given packet using send.py script (scapy)
    # Receives Mininet Egress Packet and compares it using defined comparison rules to generate the Agent's reward
    #
    # Input:
    #   packet: packet to be sent to the Mininet network
    # Returns:
    #   reward: Int; indicating agent's reward
class rewardSys():

    def __init__(self, verbose, loc=True):

        self.debug = verbose
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_server_tread = threading.Thread(target=self.socket_server).start()
        self.sshC = sshClient(verbose=verbose)
        self.sshC.connect()
        self.dropped = False
        self.bug = False
        self.loc=loc
        # adjustable parameter for agent execution testing for different conditions
        self.run = 0
        log_file=open(location_tarantula_log,"w")
        log_file.close()
        self.received_packet = None
        self.recv_port = None
        #self.sniff_thread = threading.Thread(target=self._sniff).start()
        #self._sniff()
        self.localize_counter=0
        self.bug_loc=False
        self.reward = None
        self.valid_ips = []
        self.valid_macs = []
        time.sleep(2)

    def __enter__(self):
        return self

    def __del__(self):
        print("reward sys deleted")

    def cleanup(self):
        print("came to cleanup")
        #self.q.put("bla", timeout=5)
        #print(self.q.qsize())
        #self.q.task_done()
        print("signal set to false")
        time.sleep(0.1)
        print("slept 0.1 secs")
        self.sshC.disconnect()
        del self.sshC
        try:
            self.udp.shutdown(2)
        except OSError:
            print("OS Error: ", OSError)
            pass
        self.udp.close()
        time.sleep(1)
        self.udp = None
        print("sshc disconnected")
        #print("Queue size: ", self.q.qsize())

    def send_packet_and_generate_reward(self, pkt):
        self.received_packet = None
        self.recv_port = None
        self.bug = False
        self.sshC.send_packet(pkt)
        reward = self.generate_reward()
        return reward

    def generate_reward(self):
        i=50
    #    start = time.time()
       # while self.received_packet is None:
        #    pass

        while self.received_packet is None:
            time.sleep(0.01)
            if i>0:
                i-=1
            else:
                self.dropped=True
                break
   #     print(self.received_packet)
  #      end = time.time()
 #       exectime = end-start
#        print("waited for %s seconds" % exectime)
        recv_packet = self.received_packet
        egr_port= self.recv_port
        reward = self.compare_packets(recv_packet, egr_port)
        if self.debug:
            print("Reward: ", reward)
        return reward

    # TODO: Define comparison rules and implement them and based on that generate rewards
    def compare_packets(self, pkt, port):
        egr_port = port
        reward = 0
        self.received_packet = pkt
        if self.received_packet:
            self.received_packet = Ether(bytes(self.received_packet))
            
            #TODO: write output of self.received_packet[0] to a file
        bug_type='passed'
        #print(received_packet[IP].show2)
        sent_packet = self.sshC.sent_packet
        sent_packet_loc = sent_packet
        if self.debug:
            print("sent packet: ")
            sent_packet.show2()
        if self.debug:
            print("sent_ihl: ", self.sshC.sent_packet[IP].ihl)
        if pkt:
            self.dropped = False
        else:
            self.dropped = True
        if self.debug:
            print("self.dropped: ", self.dropped)
        # Parse received packet:
        recv_src_mac = 0
        recv_dst_mac = 0
        recv_ether_type = 0
        recv_src_ip = 0
        recv_dst_ip = 0
        recv_ttl = 0
        recv_ihl = 0
        recv_chksum = 0
        recv_proto = 0
        recv_tos = 0
        recv_version = 0
        recv_len = 0
        recv_id = 0
        if self.received_packet and Ether in self.received_packet:
            recv_src_mac = self.received_packet[Ether].src
            recv_dst_mac = self.received_packet[Ether].dst
            recv_ether_type = self.received_packet[Ether].type
        if self.received_packet and IP in self.received_packet:
            recv_src_ip = self.received_packet[IP].src
            recv_dst_ip = self.received_packet[IP].dst
            recv_ttl = self.received_packet[IP].ttl
            recv_ihl = self.received_packet[IP].ihl * 4
            recv_version = self.received_packet[IP].version
            recv_chksum = self.received_packet[IP].chksum
            recv_proto = self.received_packet[IP].proto
            recv_tos = self.received_packet[IP].tos
            recv_len = self.received_packet[IP].len
            recv_id = self.received_packet[IP].id

        # Parse sent packet:
        sent_src_mac = None
        sent_dst_mac = None
        sent_ether_type = None
        sent_src_ip = None
        sent_dst_ip = None
        sent_ttl = None
        sent_version = None
        sent_ihl = None
        sent_chksum = None
        sent_proto = None
        sent_tos = None
        sent_len = None
        sent_id = None

        if Ether in sent_packet:
            sent_src_mac = sent_packet[Ether].src
            sent_dst_mac = sent_packet[Ether].dst
            sent_ether_type = sent_packet[Ether].type
        if IP in sent_packet:
            if self.debug:
                print("went to sent_packet ip header")
            sent_src_ip = sent_packet[IP].src
            sent_dst_ip = sent_packet[IP].dst
            sent_ttl = sent_packet[IP].ttl
            sent_ihl = sent_packet[IP].ihl
            sent_version = sent_packet[IP].version
            sent_chksum = sent_packet[IP].chksum
            sent_proto = sent_packet[IP].proto
            sent_tos = sent_packet[IP].tos
            sent_len = sent_packet[IP].len
            sent_id = sent_packet[IP].id
        if self.debug:
            print("sent_ihl: ", sent_ihl)
            print("sent_src_ip: ", sent_src_ip)
            print("sent_version: ", sent_version)

        if self.received_packet:

            if self.debug:
                print("recv_version: ", self.received_packet[IP].version)
        # recalculate the checksum to see if its correct in case a packet is received
        if not self.dropped:
            if self.debug:
                print("recv_chksum: ", recv_chksum)
            del self.received_packet.chksum
            self.received_packet = Ether(bytes(self.received_packet))
            correct_recv_cksum = self.received_packet[IP].chksum
            if self.debug:
                print("correct checksum: ", correct_recv_cksum)
                print("self.dropped: ", self.dropped)
                print("comparison: ", recv_chksum!=correct_recv_cksum)
                print("compare with dropped: ", (recv_chksum!=correct_recv_cksum) and not self.dropped)
            actual_recv_len = len(self.received_packet)
        else:
            correct_recv_cksum = 0
            actual_recv_len = 0
        # recalculate the checksum to see if its correct
        if IP in sent_packet:
            del sent_packet[IP].chksum
            sent_packet = Ether(bytes(sent_packet))
        # Rule 1: Check if initial TTL was high enough to reach the Egress and if yes check if the decrement worked
            correct_sent_chksum = sent_packet[IP].chksum
        else:
            correct_sent_chksum = None
        if self.debug:
            print("actual sent checksum: ", sent_chksum)
            print("correct sent checksum: ", correct_sent_chksum)


        # TODO: Test learning with different configurations of bug detection
        if self.dropped and IP not in sent_packet:
            reward = 0
            return reward
        if self.run == 1:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.chksum != calcChksum(), egr.egress_port == False,)
            if (sent_chksum != correct_sent_chksum) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'chksum'
   #             if self.debug:
                print("It was the incorrect sent checksum")
        elif self.run == 2:
            # egr.hdr.ipv4.chksum == calcChksum() &
            if (recv_chksum != correct_recv_cksum) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'chksum_e'
  #              if self.debug:
                print("It was the incorrect recv checksum")

        elif self.run == 3:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.ver != 4, egr.egress_port == False,)
            if (sent_version != 4 or recv_version != sent_version) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'version'
                print("It was the wrong ip version")
                if self.debug:
                    print("It was the wrong ip version")

        elif self.run == 4:
            # (ing.hdr.ipv4 & [ing.hdr.ipv4.ihl < 4 | ing.hdr.ipv4.ihl > 15], egr.egress_port == False,)
            if sent_ihl < 5 and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'ihl'
                #if self.debug:
                print("It was the ihl out of bounds")

        elif self.run == 5:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.len != ing.hdr.ipv4.ihl * 4, egr.egress_port == False,)
            if ((sent_len < sent_ihl * 4) or (sent_len < 20)) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'len'
                #if self.debug:
                print("It was the len != ihl*4, or len<20")

        elif self.run == 6:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.ttl < 2, egr.egress_port == False,)
            if sent_ttl < 2 and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'ttl_1'
 #               if self.debug:
                print("sent_ttl: ", sent_ttl)
                print("recv_ttl: ", recv_ttl)
                print("It was the sent_ttl")

        elif self.run == 7:
            # egr.hdr.ipv4.ttl == ing.hdr.ipv4.ttl - 1 &
            if (recv_ttl != sent_ttl - 1) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type = 'ttl'
#                if self.debug:
                print("sent_ttl: ", sent_ttl)
                print("recv_ttl: ", recv_ttl)
                print("It was the recv_ttl")

        elif self.run == 8:
            # egr.hdr.eth.srcAddr == ing.hdr.eth.dstAddr &
            if (recv_src_mac != sent_dst_mac) and not self.dropped:
                self.bug = True
                reward = 1
                bug_type='mac_swap'
                print("recv_src_mac: ", recv_src_mac)
                print("sent_dst_mac: ", sent_dst_mac)

        elif self.run == 9:
            # egr.hdr.eth.dstAddr == table_val() &
            # egr.egress_port == table_val(),)
            try:
                #if (ip_to_port[recv_dst_ip] != egr_port) and not self.dropped:
                if (not egr_port in ip_to_port[recv_dst_ip]) and not self.dropped:
                    self.bug = True
                    reward = 1
                    bug_type='port'
                    print("it was the ip_to_port: %s, %s" % (ip_to_port[recv_dst_ip],egr_port))
                if (recv_dst_mac != port_to_mac[egr_port]) and not self.dropped:
                    self.bug = True
                    reward = 1
                    bug_type='dst_mac'
                    print("it was the dst_mac: %s, %s" % (recv_dst_mac, port_to_mac[egr_port]))
            except KeyError as e:
                if not self.dropped:
                    self.bug = True
                    reward = 1
                    if self.debug:
                        print("packet with invalid ip still forwarded: %s " % str(e))
                   # print("it was the ip_to_port: %s, %s" % (ip_to_port[recv_dst_ip],egr_port))
                   # print("it was the dst_mac: %s, %s" % (recv_dst_mac, port_to_mac[egr_port]))
        elif self.run == 10:
            try:
                if (not egr_port in ip_to_port[recv_dst_ip]) and not self.dropped:
                    self.bug = True
                    reward = 1
                    bug_type='clone port'
                    print("it was the ip_to_port: %s, %s" % (ip_to_port[recv_dst_ip],egr_port))
            except KeyError as e:
                if not self.dropped:
                    self.bug = True
                    reward = 1
                    print("egress port: ", egr_port)
#                    if self.debug:
                    print("packet with invalid ip still forwarded: %s " % str(e))

        # general safety checks but were never hit, maybe delete them?
        #if (recv_dst_ip != sent_dst_ip or recv_src_ip != sent_src_ip) and not self.dropped:
         #   self.bug = True
          #  reward += 1
            #if self.debug:
           # print("It was the somehow changed IPs")

        # Check if packet with not valid dst IP was dropped
        #if (sent_dst_ip not in valid_dst_ips) and not self.dropped:
         #   self.bug = True
          #  reward += 1
            # if self.debug:
           # print("It was not known dst_ip and not dropped")


        if self.bug:
            result_loc='f'
            self.bug_loc=True
            reward += 0
        else:
            result_loc='p'
            reward = 0
        #print(bug_type)
        #print(self.dropped)
        if self.loc and self.run!=10:
            self.write_to_tarantula_log(sent_packet_loc,result_loc, bug_type)
#TODO: for each iteration save sent packet, passed or failed, which bug it triggered, seperate via ';' 
#TODO: add counter to call tarantula every 10 iterations
        self.localize_counter += 1
        return reward

#TODO: create function to call tarantula localization and write packets with their error to file 
    def write_to_tarantula_log(self, pkt, result, error_triggered):
        str_packet = pkt.show(dump = True)
        str_pkt = str_packet.replace('\n',' ')
 #       if self.localize_counter >10:
        log_file=open(location_tarantula_log,"a")
        log_file.write("%s;%s;%s \n" %(result, error_triggered, str_pkt))
        log_file.close()
        if self.bug_loc:
            self.localize()
            self.bug_loc=False
        #self.localize_counter=0
#        else:
#            log_file=open(location_tarantula_log,"a")
#            log_file.write("%s;%s;%s \n" %(result,error_triggered,str_pkt))

    def localize(self):
        os.system("%s %s %.5f" %(location_tarantula_module, location_tarantula_log, time.time()))


    def socket_server(self):
        #udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.udp is None:
            print("udp is None")
        try:
            print("starting UDP server port 9988")
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp.bind(('0.0.0.0', 9977))
            print("started UDP server on port 9988")
        except:
            print("Nope the UDP socket couldnt be bound")

        input_ = [self.udp]
        verbose = self.debug
        def parse_packet(pkt):
            pkt = bytearray(pkt)
            if self.debug:
                print(pkt[0:4])
                print(pkt[4:])

            self.recv_port = struct.unpack('I', pkt[0:4])[0]
            pkt = Ether(bytes(pkt[4:]))
            if self.debug:
                print(pkt)
            self.received_packet = pkt
            # uncomment to test comparison
            #self.compare_packets(pkt)
            if self.debug:
                pkt.show2()
        ######################## UDP and TCP corresponding clients ############################
        # UDP client to receive the messages
        # Parameters:
        #   Input:
        #   Output:
        class Client(Thread):
            def __init__(self, socket, address, sock_type):
                Thread.__init__(self)
                self.sock = socket
                self.addr = address
                self.type = sock_type
                self.start()

            def run(self):

                while 1:
                    if verbose:
                        print("Client sent:")
                    if self.type == "udp":
                        try:
                            msg, address = self.sock.recvfrom(1024)

                        except OSError:
                            msg = None
                            print("OS Error: ", OSError)
     #                   print("message received: ", msg)
                        if verbose:
                            print("message:", msg)
                        if msg is None:
                            break
                        else:
                            parse_packet(msg)
                        break
                    else:
                        break
        if self.debug:
            print("server started and is listening")
        # print
        # self.get_own_ip()
        #t = threading.currentThread()
        #while getattr(t, "do_run", True):
        #def run_server():

        while 1:
            if self.udp is None:
                print("udp is None")
                break

            # check for TCP or UDP connection and call the right client
            s = None
            try:
                inputready, outputready, exceptready = select(input_, [], [])
                for s in inputready:
                    if s == self.udp:
                        Client(s, None, "udp")
            except KeyboardInterrupt:
                if s:  # <---
                    s.close()
                break  # <---
            except ValueError:
                print("Value error: ", ValueError)
                if s:  # <---
                    s.close()
                if self.udp:
                    self.udp.close()
                break  # <---

        print("shutdown and close executed")

        try:
            self.udp.close()
        except:
            return



class sshClient():
    def __init__(self, verbose):
        self.hostname = "192.168.0.1"
        self.password = "p4"
        self.command = None
        self.username = "vagrant"
        self.port = 2222
        self.client = None
        self.sent_packet = None
        self.debug = verbose
        privatekeyfile = os.path.expanduser('~/vagrant_private_key')
        self.mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)


    def __del__(self):
        print("sshC deleted")

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy)
#        self.client.connect(self.hostname, port=self.port, username=self.username, password=self.password)
        self.client.connect(self.hostname, username=self.username, pkey=self.mykey)
    def disconnect(self):
        self.client.close()

    def send_packet(self, packet):
        if self.debug:
            print("SSHclient sent_chksum: ", packet[IP].chksum)
        self.sent_packet = packet
        packet = binascii.hexlify(bytes(packet))
        self.command = 'sudo ' + SEND_PATH + 'send.py "%s"' % packet
    #    print(self.command)
        stdin, stdout, stderr = self.client.exec_command(self.command)
if __name__ == '__main__':
    main()
