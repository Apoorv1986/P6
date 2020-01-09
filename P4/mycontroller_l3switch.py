#!/usr/bin/env python2
import argparse
import os
import sys
import pickle
import json
import socket
import struct
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
#sys.path.append(
  #  os.path.join(os.path.dirname(os.path.abspath(__file__)),
  #               '../../utils/'))
#sys.path.append(os.path.expanduser("/usr/local/lib/python2.7/dist-packages/"))
#sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'/usr/local/lib/python2.7/dist-packages/p4/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2



SWITCH_TO_HOST1_PORT = 0
SWITCH_TO_HOST2_PORT = 1
SWITCH_TO_HOST3_PORT = 2
TARGET_IP_DEFAULT = "192.168.0.13"
SWITCH_IP_DEFAULT = "10.10.1.100"
TARGET_PORT_DEFAULT = 9988

def configure_clone(p4info_helper, sw, entry):
    sess_id = entry['session_id']
    egr_port = entry['replicas']['egress_port'] # None if not found
    inst = entry['replicas']['instance']
    service = entry['class_of_service']
    packet_len = entry['packet_length_bytes']
#    p4runtime_egr = p4runtime_pb2. 
#    request = p4runtime_pb2.CloneSessionEntry()
    request = p4runtime_pb2.Update()
#    request.device_id = sw.device_id
 #   request.election_id.low = 1
 #   update = request.updates.add()
    request.type = p4runtime_pb2.Update.INSERT
#    update.entity = update.entities.add()
#    clone_entry = request.update.entity.packet_replication_engine_entry
    replic = p4runtime_pb2.Replica()
    replic.egress_port=egr_port
    replic.instance = inst
    #request.entity.packet_replication_engine_entry.clone_session_entry.session_id = sess_id
#    request.entity.packet_replication_engine_entry.clone_session_entry.replicas.instance = inst
 #   request.entity.packet_replication_engine_entry.clone_session_entry.replicas.egress_port = egr_port
  #  request.entity.packet_replication_engine_entry.clone_session_entry.replicas.instance = inst
    request.entity.packet_replication_engine_entry.clone_session_entry.class_of_service = service
    request.entity.packet_replication_engine_entry.clone_session_entry.replicas.extend([replic])
    request.entity.packet_replication_engine_entry.clone_session_entry.packet_length_bytes = packet_len
    request.entity.packet_replication_engine_entry.clone_session_entry.session_id = sess_id
    print "replicas coming"
    print request.entity.packet_replication_engine_entry.clone_session_entry.replicas

#    clone_entry = clone_entry.clone_session_entry    
#    clone_entry.session_id = sess_id
#    clone_entry.replicas.egress_port=egr_port
#    clone_entry.replicas.instance = inst
 ##   clone_entry.class_of_service = service
 #   clone_entry.packet_length_bytes = packet_len
    print "sending request: %s" % request
    sw.client_stub.Write(request)



def writeTunnelRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr, mask, egr_port):
    """
    Installs three rules:
    1) An tunnel ingress rule on the ingress switch in the ipv4_lpm table that
       encapsulates traffic into a tunnel with the specified ID
    2) A transit rule on the ingress switch that forwards traffic based on
       the specified ID
    3) An tunnel egress rule on the egress switch that decapsulates traffic
       with the specified ID and sends it to the host

    :param p4info_helper: the P4Info helper
    :param ingress_sw: the ingress switch connection
    :param egress_sw: the egress switch connection
    :param tunnel_id: the specified tunnel ID
    :param dst_eth_addr: the destination IP to match in the ingress rule
    :param dst_ip_addr: the destination Ethernet address to write in the
                        egress rule
    """
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": egr_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % ingress_sw.name


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    table_entries={}
    table_entries['table_entries']=[]
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
	    match = {}
	    for m in entry.match:
                match_name=p4info_helper.get_match_field_name(table_name, m.field_id)
		print match_name,
		match_value=p4info_helper.get_match_field_value(m)
                print '%r' % (p4info_helper.get_match_field_value(m),),
		if 'ip' in match_name:
		    if type(match_value) == tuple:
			match[str(match_name)]=get_ip_from_bytes(match_value[0])
		    else:
		        match[str(match_name)]=get_ip_from_bytes(match_value)
		elif 'dstAddr' in match_name:
		    match[str(match_name)]=get_mac_from_bytes(match_value)
		else:
		    match[str(match_name)]=match_value

            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
	    action_params = {}
            for p in action.params:
		action_param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
		if 'ip' in action_param_name:
                    if type(match_value) == tuple:
			action_params[str(action_param_name)]=get_ip_from_bytes(p.value[0])
		    else:
			action_params[str(action_param_name)]=get_ip_from_bytes(p.value)
                elif 'dstAddr' in action_param_name:
                    action_params[str(action_param_name)]=get_mac_from_bytes(p.value)
                else:
		    action_params[str(action_param_name)]=p.value
            print
	    table_entries['table_entries'].append({'table': str(table_name), 'match': match, 'action_name': str(action_name), 'action_params': action_params})
    print table_entries
    return table_entries

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def get_mac_from_bytes(mac):
    nice_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",mac)
    return nice_mac

def get_ip_from_bytes(ip):
    nice_ip=socket.inet_ntoa(ip)
    return nice_ip

def get_int_from_bytes(number):
    nice_int =7
    return nice_int

# Method for sending table rules to P4RL
def send_table_rules(p4info_helper, s1):
    table_rules = readTableRules(p4info_helper, s1)
    table_rules_json = json.dumps(table_rules, encoding = "ISO-8859-1")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(table_rules_json,(TARGET_IP_DEFAULT, TARGET_PORT_DEFAULT))
    sock.close()

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)



# object hook for josn library, use str instead of unicode object
# https://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-of-unicode-from-json
def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify),
                    ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data





def insertTableEntry(sw, flow, p4info_helper):
    table_name = flow['table']
    match_fields = flow.get('match') # None if not found
    action_name = flow['action_name']
    default_action = flow.get('default_action') # None if not found
    action_params = flow['action_params']
    priority = flow.get('priority')  # None if not found

    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        default_action=default_action,
        action_name=action_name,
        action_params=action_params,
        priority=priority)
    print(table_entry)
    try:
        sw.WriteTableEntry(table_entry)
    except Exception as e:
        print(e)



def program_switch(switch, sw_conf_file, workdir, proto_dump_fpath, bmv2_file_path):
    sw_conf = json_load_byteified(sw_conf_file)
    print "came to program swithc"
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(workdir)

    target = sw_conf['target']

    if 'table_entries' in sw_conf:
        table_entries = sw_conf['table_entries']
        for entry in table_entries:
            insertTableEntry(switch, entry, p4info_helper)
    print "finished tables"
#    if 'clone_session_entries' in sw_conf:
 #       print "came to if"
  #      clone_entries = sw_conf['clone_session_entries']
   #     for entry in clone_entries:
    #        configure_clone(p4info_helper, switch, entry)




def main(p4info_file_path, bmv2_file_path,runtime_json):
    # Instantiate a P4 Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Create a switch connection object for s1;
    # this is backed by a P4 Runtime gRPC connection.
    # Also, dump all P4Runtime messages sent to switch to given txt files.
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address=SWITCH_IP_DEFAULT+':50051',
        device_id=0,
        proto_dump_file='/vagrant/logs/s1-p4runtime-requests.txt')

    # Send master arbitration update message to establish this controller as
    # master (required by P4Runtime before performing any other write operation)
    s1.MasterArbitrationUpdate()

    # Install the P4 program on the switches
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path=bmv2_file_path)
    print "Installed P4 Program using SetForwardingPipelineConfig on s1"


    # Write the necessary rules to the switch
    # dst_eth_addr, dst_eth_addr_2, dst_eth_addr_3, dst_ip_addr, dst_ip_addr_2, dst_ip_addr_3
    #writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip_addr="172.16.20.100", mask=30, egr_port=1)
    #writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:02", dst_ip_addr="172.16.30.100", mask=30, egr_port=2)
#    writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:03", dst_ip_addr="172.16.40.100", mask=30, egr_port=3)


    # TODO Uncomment the following line to read table entries from s1
    readTableRules(p4info_helper, s1)

    #Install the control plane configuration from the given JSON file
    if os.path.exists(args.runtime_json):
      try:
        print('Configuring switch s1 using P4Runtime with file %s' %runtime_json)
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '/vagrant/logs/s1-p4runtime-requests.txt'
            program_switch( switch=s1,
                sw_conf_file=sw_conf_file,
                workdir=p4info_file_path,
                proto_dump_fpath=outfile,
                bmv2_file_path=bmv2_file_path)
      except KeyboardInterrupt:
        print " Shutting down."
  #    except grpc.RpcError as e:
  #      printGrpcError(e)



    # send the table contents every 10 seconds to P4RL
    try:
        while True:
            sleep(10)
            print '\n----- Reading table contents ------'
            send_table_rules(p4info_helper, s1)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    parser.add_argument('--runtime-json', help='RuntimeJSON file of the switch',  #Zsolt
                        type=str, action="store", required=False, default='')     #Zsolt
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)

    main(args.p4info, args.bmv2_json, args.runtime_json)
