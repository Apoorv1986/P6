#include <core.p4>
#include <tna.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

const bit<16> ACCEPTOR_PORT = 0x8889;
const bit<16> LEARNER_PORT = 0x8890;
const bit<16> APPLICATION_PORT = 56789;

const PortId_t PORTA = 0x1;
const bit<16> LEARNER = 0x8765;


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
    IPv4Address srcAddr;
    IPv4Address dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


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
    bit<16>   msgtype;    // indicates the message type e.g., 1A, 1B, etc.
    bit<32>  inst;       // instance number
    bit<16>     rnd;        // round number
    bit<16>     vrnd;       // round in which an acceptor casted a vote
    bit<32>  acptid;     // Switch ID
    bit<16>  paxoslen;   // the length of paxos_value
    bit<16>     paxosval;   // the value the acceptor voted for
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    paxos_t paxos;
}

struct paxos_metadata_t {
    bit<16> round;
    bit<1> set_drop;
    bit<8> ack_count;
    bit<8> ack_acceptors;
}

struct metadata {
    paxos_metadata_t   paxos_metadata;
}

#define ETHERTYPE_IPV4 16w0x0800
#define UDP_PROTOCOL 8w0x11
#define PAXOS_PROTOCOL 16w0x8888

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(64);
        transition accept;
    }
}







parser MyParser(packet_in b, out headers p, out metadata meta, out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(b, ig_intr_md);
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


control MyIngress(inout headers hdr, inout metadata meta, in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action _drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action increase_instance() {
//        registerInstance.read(hdr.paxos.inst, 0);
//        hdr.paxos.inst = hdr.paxos.inst + 1;
//        registerInstance.write(0, hdr.paxos.inst);
        meta.paxos_metadata.set_drop = 0;

    }

    action reset_instance() {
        //registerInstance.write(0, 0);
        // Do not need to forward this message
        meta.paxos_metadata.set_drop = 1;
    }

    table leader_tbl {
        key = {hdr.paxos.msgtype : exact;}
        actions = {
            increase_instance;
            reset_instance;
            _drop;
        }
        default_action = _drop();
    }


    action forward() {
        ig_intr_tm_md.ucast_egress_port = PORTA;
//        hdr.udp.dstPort = acceptorPort;
    }

    table transport_tbl {
        key = { meta.paxos_metadata.set_drop : exact; }
        actions = {
            _drop;
             forward;
        }
        default_action =  _drop();
        const entries = {
            0x0 : forward();

        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
//            if (hdr.paxos.isValid()) {
//                leader_tbl.apply();
                increase_instance();
                transport_tbl.apply();
//            }
        }
        else {
            _drop();
            
           }
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    apply {
        hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});
       /* pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);*/
        pkt.emit(hdr);

    }
}


parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}




/***********************  D E P A R S E R  *******************************
*************************************************************************/
// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out headers hdr,
        out metadata eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;


     }
}




control EmptyEgress<H, M>(
        inout H hdr,
        inout M eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

control EmptyEgressDeparser<H, M>(
        packet_out pkt,
        inout H hdr,
        in M eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(MyParser(),
         MyIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         EmptyEgress<headers, metadata>(),
         EmptyEgressDeparser<headers, metadata>()) pipe;

Switch(pipe) main;



