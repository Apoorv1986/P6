import os
import sys
import argparse
import socket
import random
import struct

from scapy.all import Packet
from scapy.all import BitField
from scapy.all import bind_layers
from scapy.all import Ether, IP, UDP, TCP, Dot1Q, GRE, IPv6

class roce_header(Packet):
    name = "roce_header"
    fields_desc = [ BitField("ib_grh", 0, 320),
                    BitField("ib_bth", 0, 96)]

class roce_v2_header(Packet):
    name = "roce_v2_header"
    fields_desc = [ BitField("ib_bth", 0, 96)]

class fcoe_header(Packet):
    name = "fcoe_header"
    fields_desc = [ BitField("version", 0, 4),
                    BitField("type_", 0, 4),
                    BitField("sof", 0, 8),
                    BitField("rsvd1", 0, 32),
                    BitField("ts_upper", 0, 32),
                    BitField("ts_lower", 0, 32),
                    BitField("size_", 0, 32),
                    BitField("eof", 0, 8),
                    BitField("rsvd2", 0, 23) ]

class ieee802_1ah(Packet):
    name = "ieee802_1ah"
    fields_desc = [ BitField("pcp", 0, 3),
                    BitField("dei", 0, 1),
                    BitField("uca", 0, 1),
                    BitField("reserved", 0, 3),
                    BitField("i_sed", 0, 23) ]

class mpls(Packet):
    name = "mpls"
    fields_desc = [ BitField("label", 0, 20),
                    BitField("exp", 0, 3),
                    BitField("bos", 0, 1),
                    BitField("ttl", 0, 8) ]

class sctp(Packet):
    name = "sctp"
    fields_desc = [ BitField("srcPort", 0, 16),
                    BitField("dstPort", 0, 16),
                    BitField("verifTag", 0, 32),
                    BitField("checksum", 0, 32) ]

class nvgre(Packet):
    name = " nvgre"
    fields_desc = [ BitField("tni", 0, 23),
                    BitField("flow_id", 0, 8) ]

class erspan_header_t3(Packet):
    name = "erspan_header_t3"
    fields_desc = [ BitField("version", 0, 4),
                    BitField("vlan", 0, 12),
                    BitField("priority", 0, 6),
                    BitField("span_id", 0, 10),
                    BitField("timestamp", 0, 32),
                    BitField("sgt", 0, 16),
                    BitField("ft_d_other", 0, 16) ]

class arp_rarp(Packet):
    name = "arp_rarp"
    fields_desc = [ BitField("hwType", 0, 16),
                    BitField("protoType", 0, 16),
                    BitField("hwAddrLen", 0, 8),
                    BitField("protoAddrLen", 0, 8),
                    BitField("opcode", 0, 16) ]

class arp_rarp_ipv4(Packet):
    name = "arp_rarp_ipv4"
    fields_desc = [ BitField("srcHwAddr", 0, 48),
                    BitField("srcProtoAddr", 0, 32),
                    BitField("dstHwAddr", 0, 48),
                    BitField("dstProtoAddr", 0, 32) ]

class eompls(Packet):
    name = "eompls"
    fields_desc = [ BitField("zero", 0, 4),
                    BitField("reserved", 0, 12),
                    BitField("seqNo", 0, 16) ]

class vxlan(Packet):
    name = "vxlan"
    fields_desc = [ BitField("flags", 0, 8),
                    BitField("reserved", 0, 24),
                    BitField("vni", 0, 24),
                    BitField("reserved2", 0, 8) ]

class vxlan_gpe(Packet):
    name = "vxlan_gpe"
    fields_desc = [ BitField("flags", 0, 8),
                    BitField("reserved", 0, 26),
                    BitField("next_proto", 0, 8),
                    BitField("vni", 0, 24),
                    BitField("reserved2", 0, 8) ]

class nsh(Packet):
    name = "nsh"
    fields_desc = [ BitField("oam", 0, 1),
                    BitField("context", 0, 1),
                    BitField("flags", 0, 6),
                    BitField("reserved", 0, 8),
                    BitField("protoType", 0, 16),
                    BitField("spath", 0, 24),
                    BitField("sindex", 0, 8) ]

class nsh_context(Packet):
    name = "nsh_context"
    fields_desc = [ BitField("network_platform", 0, 32),
                    BitField("network_shared", 0, 32),
                    BitField("service_platform", 0, 32),
                    BitField("service_shared", 0, 32) ]

class vxlan_gpe_int_header(Packet):
    name = "vxlan_gpe_int_header"
    fields_desc = [ BitField("int_type", 0, 8),
                    BitField("rsvd", 0, 8),
                    BitField("len", 0, 8),
                    BitField("next_proto", 0, 8) ]

class genv(Packet):
    name = "genv"
    fields_desc = [ BitField("ver", 0, 2),
                    BitField("optLen", 0, 6),
                    BitField("oam", 0, 1),
                    BitField("critical", 0, 1),
                    BitField("reserved", 0, 6),
                    BitField("protoType", 0, 16),
                    BitField("vni", 0, 24),
                    BitField("reserved2", 0, 8) ]

class genv_opt_A(Packet):
    name = "genv_opt_A"
    fields_desc = [ BitField("optClass", 0, 16),
                    BitField("optType", 0, 8),
                    BitField("reserved", 0, 3),
                    BitField("optLen", 0, 15),
                    BitField("data", 0, 32) ]

class genv_opt_B(Packet):
    name = "genv_opt_B"
    fields_desc = [ BitField("optClass", 0, 16),
                    BitField("optType", 0, 8),
                    BitField("reserved", 0, 3),
                    BitField("optLen", 0, 15),
                    BitField("data", 0, 64) ]

class genv_opt_C(Packet):
    name = "genv_opt_C"
    fields_desc = [ BitField("optClass", 0, 16),
                    BitField("optType", 0, 8),
                    BitField("reserved", 0, 3),
                    BitField("optLen", 0, 15),
                    BitField("data", 0, 32) ]
class trill(Packet):
    name = "trill"
    fields_desc = [ BitField("version", 0, 2),
                    BitField("reserved", 0, 2),
                    BitField("multiDestination", 0, 1),
                    BitField("optLength", 0, 5),
                    BitField("hopCount", 0, 6),
                    BitField("egressRbridge", 0, 16),
                    BitField("ingressRbridge", 0, 16) ]

class lisp(Packet):
    name = "lisp"
    fields_desc = [ BitField("flags", 0, 8),
                    BitField("nonce", 0, 24),
                    BitField("lsbsInstanceId", 0, 32) ]


class vntag(Packet):
    name = "vntag"
    fields_desc = [ BitField("direction", 0, 1),
                    BitField("pointer", 0, 1),
                    BitField("destVif", 0, 14),
                    BitField("looped", 0, 1),
                    BitField("reserved", 0, 1),
                    BitField("version", 0, 2),
                    BitField("srcVif", 0, 12) ]

class bfd(Packet):
    name = "bfd"
    fields_desc = [ BitField("version", 0, 3),
                    BitField("diag", 0, 5),
                    BitField("state", 0, 2),
                    BitField("p", 0, 1),
                    BitField("f", 0, 1),
                    BitField("c", 0, 1),
                    BitField("a", 0, 1),
                    BitField("d", 0, 1),
                    BitField("m", 0, 1),
                    BitField("detecMult", 0, 8),
                    BitField("len", 0, 8),
                    BitField("myDiscriminator", 0, 32),
                    BitField("yourDiscriminator", 0, 32),
                    BitField("desiredMinTxInterval", 0, 32),
                    BitField("requiredMinRxInterval", 0, 32),
                    BitField("requiredMinEchoRxInterval", 0, 32) ] 

class sflow_hdr(Packet):
    name = "sflow_hdr"
    fields_desc = [ BitField("version", 0, 32),
                    BitField("addrType", 0, 32),
                    BitField("ipAddress", 0, 32),
                    BitField("subAgentId", 0, 32),
                    BitField("seqNumber", 0, 32),
                    BitField("uptime", 0, 32),
                    BitField("numSamples", 0, 32) ]

class sflow_sample(Packet):
    name = "sflow_sample"
    fields_desc = [ BitField("enterprise", 0, 20),
                    BitField("format", 0, 12),
                    BitField("sampleLength", 0, 32),
                    BitField("seqNumber", 0, 32),
                    BitField("srcIdType", 0, 8),
                    BitField("srcIdIndex", 0, 24),
                    BitField("samplingRate", 0, 32),
                    BitField("samplePool", 0, 32),
                    BitField("numDrops", 0, 32),
                    BitField("inputIfindex", 0, 32),
                    BitField("outputIfindex", 0, 32),
                    BitField("numFlowRecords", 0, 32) ]

class sflow_raw_hdr_record(Packet):
    name = "sflow_raw_hdr_record"
    fields_desc = [ BitField("enterprise", 0, 20),
                    BitField("format", 0, 12),
                    BitField("flowDataLength", 0, 32),
                    BitField("headerProtocol", 0, 32),
                    BitField("frameLength", 0, 32),
                    BitField("bytesRemoved", 0, 32),
                    BitField("headerSize", 0, 32) ] 

class sflow_sample_cpu(Packet):
    name = "sflow_sample_cpu"
    fields_desc = [ BitField("sampleLength", 0, 16),
                    BitField("samplePool", 0, 32),
                    BitField("inputIfindex", 0, 16),
                    BitField("outputIfindex", 0, 16),
                    BitField("numFlowRecords", 0, 8),
                    BitField("sflow_session_id", 0, 3),
                    BitField("pipe_id", 0, 2) ] 

class fabric_header(Packet):
    name = "fabric_header"
    fields_desc = [ BitField("packetType", 0, 3),
                    BitField("headerVersion", 0, 2),
                    BitField("packetVersion", 0 ,2),
                    BitField("pad1", 0, 1),
                    BitField("fabricColor", 0, 3),
                    BitField("fabricQos", 0, 5),
                    BitField("dstDevice", 0, 8),
                    BitField("dstPortOrGroup", 0,16) ]

class fabric_header_unicast(Packet):
    name = "fabric_header_unicast"
    fields_desc = [ BitField("routed", 0, 1),
                    BitField("outerRouted", 0, 1),
                    BitField("tunnelTerminate", 0, 1),
                    BitField("ingressTunnelType", 0, 5),
                    BitField("nexthopIndex", 0, 16) ]

class fabric_header_multicast(Packet):
    name = "fabric_header_multicast"
    fields_desc = [ BitField("routed", 0, 1),
                    BitField("outerRouted", 0, 1),
                    BitField("tunnelTerminate", 0, 1),
                    BitField("ingressTunnelType", 0, 5),
                    BitField("ingressIfindex", 0, 16),
                    BitField("ingressBd", 0, 16),
                    BitField("mcastGrp", 0, 16) ]

class fabric_header_mirror(Packet):
    name = "fabric_header_mirror"
    fields_desc = [ BitField("rewriteIndex", 0, 16),
                    BitField("egressPort", 0, 10),
                    BitField("egressQueue", 0, 5),
                    BitField("pad", 0, 1) ]

class fabric_header_cpu(Packet):
    name = "fabric_header_cpu"
    fields_desc = [ BitField("egressQueue", 0, 5),
                    BitField("txBypass", 0, 1),
                    BitField("reserved", 0, 2),
                    BitField("ingressPort", 0, 16),
                    BitField("ingressIfindex", 0, 16),
                    BitField("ingressBd", 0, 16),
                    BitField("reasonCode", 0, 16),
                    BitField("mcast_grp", 0, 16) ]

class fabric_header_sflow(Packet):
    name = "fabric_header_sflow"
    fields_desc = [ BitField("sflow_session_id", 0, 16),
                    BitField("sflow_egress_ifindex", 0, 16) ]

class fabric_payload_header(Packet):
    name = "fabric_payload_header"
    fields_desc = [ BitField("etherType", 0, 16) ]

class int_header(Packet):
    name = "int_header"
    fields_desc = [ BitField("ver", 0, 2),
                    BitField("rep", 0, 2),
                    BitField("c", 0, 1),
                    BitField("e", 0, 1),
                    BitField("rsvd1", 0, 5),
                    BitField("ins_cnt", 0, 5),
                    BitField("max_hop_cnt", 0, 8),
                    BitField("total_hop_cnt", 0, 8),
                    BitField("instruction_mask_0003", 0, 4),
                    BitField("instruction_mask_0407", 0, 4),
                    BitField("instruction_mask_0811", 0, 4),
                    BitField("instruction_mask_1215", 0, 4),
                    BitField("rsvd2", 0, 16) ]

class int_switch_id_header(Packet):
    name = "int_switch_id_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("switch_id", 0, 31) ]

class int_ingress_port_id_header(Packet):
    name = "int_ingress_port_id_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("ingress_port_id_1", 0, 15),
                    BitField("ingress_port_id_0", 0, 16) ]

class int_hop_latency_header(Packet):
    name = "int_hop_latency_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("hop_latency", 0, 31) ]

class int_q_occupancy_header(Packet):
    name = "int_q_occupancy_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("q_occupancy_1", 0, 7),
                    BitField("q_occupancy_0", 0, 24) ]

class int_ingress_tstamp_header(Packet):
    name = "int_ingress_tstamp_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("ingress_tstamp", 0, 31) ]

class int_egress_port_id_header(Packet):
    name = "int_egress_port_id_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("egress_port_id", 0, 31) ]

class int_q_congestion_header(Packet):
    name = "int_q_congestion_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("q_congestion", 0, 31) ]

class int_egress_port_tx_utilization_header(Packet):
    name = "int_egress_port_tx_utilization_header"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("egress_port_tx_utilization", 0, 31) ]

class int_value(Packet):
    name = "int_value"
    fields_desc = [ BitField("bos", 0, 1),
                    BitField("value", 0, 31) ]

class bindings():
  #Binding the new protocols to the appropriate layers
  #Bindig layers to Ethernet
  bind_layers(Ether, roce_header, type=0x8915)
  bind_layers(Ether, fcoe_header, type=0x8906)
  bind_layers(Ether, mpls, type=0x8847)
  bind_layers(Ether, arp_rarp, type=0x8035)
  bind_layers(Ether, nsh, type=0x894f)
  bind_layers(Ether, trill, type=0x22f3)
  bind_layers(Ether, vntag, type=0x8926)
  bind_layers(Ether, fabric_header, type=0x9005)

  #Binding fabric types
  bind_layers(fabric_header, fabric_header_unicast, packetType=1)
  bind_layers(fabric_header, fabric_header_multicast, packetType=2)
  bind_layers(fabric_header, fabric_header_mirror, packetType=3)
  bind_layers(fabric_header, fabric_header_sflow, packetType=4)
  bind_layers(fabric_header, fabric_header_cpu, packetType=5)

  #Binding mpls label
  bind_layers(mpls, mpls, bos=0)
  bind_layers(mpls, IP, bos=1)
  bind_layers(mpls, IPv6, bos=1)
  bind_layers(mpls, eompls, bos=1)

  #Binsing layers to UDP
  bind_layers(UDP, bfd, dport=3785)
  bind_layers(UDP, lisp, dport=4341)
  bind_layers(UDP, vxlan, dport=4789)
  bind_layers(UDP, vxlan_gpe, dport=4790)
  bind_layers(UDP, roce_v2_header, dport=4791)
  bind_layers(UDP, genv, dport=6081)
  bind_layers(UDP, sflow_hdr, dport=6343)

  #Binding layers to GRE
  #bind_layers(GRE, nvgre, ???=0x20006558)
  #bind_layers(GRE, erspan_header_t3, ???=0x22EB)

  #Binding layers to nsh
  bind_layers(nsh, IP, protoType=0x0800)
  bind_layers(nsh, IPv6, protoType=0x86dd)

#The following parts of the code were generated during tests by our p4_code_reader.py script



class fabric_payload_header(Packet):
  name = "fabric_payload_header"
  fields_desc = [ BitField("etherType", 0, 16)]

class binding_fabric_payload_header():
  bind_layers(fabric_header_cpu, fabric_payload_header, reasonCode=0x5)

class paxos(Packet):
  name = "paxos"
  fields_desc = [ BitField("msgtype", 0, 16),
                  BitField("inst", 0, 32),
                  BitField("rnd", 0, 16),
                  BitField("vrnd", 0, 16),
                  BitField("acptid", 0, 16),
                  BitField("paxoslen", 0, 32),
                  BitField("paxosval", 0, 256)]

class binding_paxos():
  bind_layers(UDP, paxos, dstPort=8888)

class myTunnel(Packet):
  name = "myTunnel"
  fields_desc = [ BitField("proto_id", 0, 16),
                  BitField("dst_id", 0, 16)]

class binding_myTunnel():
  bind_layers(Ether, myTunnel, type=TYPE_MYTUNNEL)

class ipv4_option(Packet):
  name = "ipv4_option"
  fields_desc = [ BitField("copyFlag", 0, 1),
                  BitField("optClass", 0, 2),
                  BitField("option", 0, 5),
                  BitField("optionLength", 0, 8)]

class binding_ipv4_option():
  bind_layers(IP, ipv4_option, ihl=default)

class mri(Packet):
  name = "mri"
  fields_desc = [ BitField("count", 0, 16)]

class binding_mri():
  bind_layers(ipv4_option, mri, option=IPV4_OPTION_MRI)

class switch(Packet):
  name = "switch"
  fields_desc = [ BitField("qdepth_t", 0, 32)]
