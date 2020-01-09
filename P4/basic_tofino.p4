/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

const bit<16> TYPE_IPV4 = 0x800;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const macAddr_t MAC = 0x010000000101;
const PortId_t PORT = 0x2;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
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

parser MyParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition parse_ethernet;
    }


    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(
        inout headers hdr,
        inout metadata ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {



    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }
    action hit() {
        ig_intr_tm_md.ucast_egress_port = 2;
    }
    

    action forward() {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = MAC;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        ig_intr_tm_md.ucast_egress_port = 2;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
            hit;
        }
        default_action = drop();
        const entries = {
            0xac101e64 : forward();
/*            0xac101e64 : forward(0x102, 2);*/
        }

    }

    apply{
        ipv4_lpm.apply();
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
