#include <core.p4>
#include <v1model.p4>

#ifndef _HEADERS_P4_
#define _HEADERS_P4_

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address_t;
typedef bit<9> PortId;

// Physical Ports
const PortId DROP_PORT = 0xF;
// UDP Ports
const bit<16> ACCEPTOR_PORT = 0x8889;
const bit<16> LEARNER_PORT = 0x8890;
const bit<16> APPLICATION_PORT = 56789;
// standard headers
header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Address_t srcAddr;
    IPv4Address_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// Headers for Paxos
#define PAXOS_1A 0
#define PAXOS_1B 1
#define PAXOS_2A 2
#define PAXOS_2B 3

#define MSGTYPE_SIZE    16
#define INSTANCE_SIZE   32
#define ROUND_SIZE      16
#define DATAPATH_SIZE   16
#define VALUELEN_SIZE   32
#define VALUE_SIZE      256
#define INSTANCE_COUNT  65536


header paxos_t {
    bit<MSGTYPE_SIZE>   msgtype;    // indicates the message type e.g., 1A, 1B, etc.
    bit<INSTANCE_SIZE>  inst;       // instance number
    bit<ROUND_SIZE>     rnd;        // round number
    bit<ROUND_SIZE>     vrnd;       // round in which an acceptor casted a vote
    bit<DATAPATH_SIZE>  acptid;     // Switch ID
    bit<VALUELEN_SIZE>  paxoslen;   // the length of paxos_value
    bit<VALUE_SIZE>     paxosval;   // the value the acceptor voted for
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    paxos_t paxos;
}

struct paxos_metadata_t {
    bit<ROUND_SIZE> round;
    bit<1> set_drop;
    bit<8> ack_count;
    bit<8> ack_acceptors;
}

struct metadata {
    paxos_metadata_t   paxos_metadata;
}

#endif



#ifndef _PARSER_P4_
#define _PARSER_P4_


#define ETHERTYPE_IPV4 16w0x0800
#define UDP_PROTOCOL 8w0x11
#define PAXOS_PROTOCOL 16w0x8888

parser TopParser(packet_in b, out headers p, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        b.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_ipv4 {
        b.extract(p.ipv4);
        transition select(p.ipv4.protocol) {
            UDP_PROTOCOL : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        b.extract(p.udp);
        transition select(p.udp.dstPort) {
            PAXOS_PROTOCOL : parse_paxos;
            default : accept;
        }
    }

    state parse_paxos {
        b.extract(p.paxos);
        transition accept;
    }
}

control TopDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.paxos);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(false,{hdr.ipv4.version,
                               hdr.ipv4.ihl,
                               hdr.ipv4.diffserv,
                               hdr.ipv4.totalLen,
                               hdr.ipv4.identification,
                               hdr.ipv4.flags,
                               hdr.ipv4.fragOffset,
                               hdr.ipv4.ttl,
                               hdr.ipv4.protocol,
                               hdr.ipv4.srcAddr,
                               hdr.ipv4.dstAddr
                          },hdr.ipv4.hdrChecksum,HashAlgorithm.csum16);
  }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true,
                      { hdr.ipv4.version,
                        hdr.ipv4.ihl,
                        hdr.ipv4.diffserv,
                        hdr.ipv4.totalLen,
                        hdr.ipv4.identification,
                        hdr.ipv4.flags,
                        hdr.ipv4.fragOffset,
                        hdr.ipv4.ttl,
                        hdr.ipv4.protocol,
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr },
                        hdr.ipv4.hdrChecksum,
                        HashAlgorithm.csum16);
    }
}

#endif


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<ROUND_SIZE>>(INSTANCE_COUNT) registerRound;
    register<bit<VALUE_SIZE>>(INSTANCE_COUNT) registerValue;
    register<bit<8>>(INSTANCE_COUNT) registerHistory2B;

    action _drop() {
        mark_to_drop();
    }

    action read_round() {
//        registerRound.read(meta.paxos_metadata.round, hdr.paxos.inst);
        meta.paxos_metadata.set_drop = 0;
//        registerHistory2B.read(meta.paxos_metadata.ack_acceptors, hdr.paxos.inst);
    }

    action handle_2b() {
        registerRound.write(hdr.paxos.inst, hdr.paxos.rnd);
        registerValue.write(hdr.paxos.inst, hdr.paxos.paxosval);
        // Limit to 8 bits for left shift operation
        bit<8> acptid = 8w1 << (bit<8>)hdr.paxos.acptid;
        meta.paxos_metadata.ack_acceptors = meta.paxos_metadata.ack_acceptors | acptid;
        registerHistory2B.write(hdr.paxos.inst, meta.paxos_metadata.ack_acceptors);
    }

    table learner_tbl {
        key = {hdr.paxos.msgtype : exact;}
        actions = {
            handle_2b;
        }
        size = 1;
        default_action = handle_2b;
    }

    action handle_new_value() {
        registerRound.write(hdr.paxos.inst, hdr.paxos.rnd);
        registerValue.write(hdr.paxos.inst, hdr.paxos.paxosval);
        bit<8> acptid = 8w1 << (bit<8>)hdr.paxos.acptid;
        registerHistory2B.write(hdr.paxos.inst, acptid);
    }

    table reset_consensus_instance {
        key = {hdr.paxos.msgtype : exact;}
        actions = {
            handle_new_value;
        }
        size = 1;
        default_action = handle_new_value;
    }

    action forward(PortId port, bit<16> learnerPort) {
        standard_metadata.egress_spec = port;
        hdr.udp.dstPort = learnerPort;
    }

    table transport_tbl {
        key = { meta.paxos_metadata.set_drop : exact; }
        actions = {
            _drop;
             forward;
        }
        size = 2;
        default_action =  _drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
//            if (hdr.paxos.isValid()) {
                read_round();
//                if (hdr.paxos.rnd > meta.paxos_metadata.round) {
//                    reset_consensus_instance.apply();
//                }
//                else if (hdr.paxos.rnd == meta.paxos_metadata.round) {
//                    learner_tbl.apply();
//                }
//                // TODO: replace this with counting number of 1 in Binary
//                // e.g count_number_of_1_binary(paxos_metadata.acceptors) == MAJORITY
//                if (meta.paxos_metadata.ack_acceptors == 6       // 0b110
//                    || meta.paxos_metadata.ack_acceptors == 5    // 0b101
//                    || meta.paxos_metadata.ack_acceptors == 3)   // 0b011
//                {
                    // deliver the value
                    transport_tbl.apply();
//                }
//            }
        }
        else {
            mark_to_drop();
            exit;
           }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
//    table place_holder_table {
//        actions = {
//            NoAction;
//        }
//        size = 2;
//        default_action = NoAction();
//    }
    apply {
//        place_holder_table.apply();
    }
}

V1Switch(TopParser(), verifyChecksum(), ingress(), egress(), computeChecksum(), TopDeparser()) main;
