/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_FILTER = 146;
const bit<8> PROTO_UDP = 17;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

// TODO: Define the filter and UDP headers here.
header filter_t {
    bit<8>  susp;  // Suspicious flag
    bit<8>  proto; // Next protocol, typically set to 17 (UDP)
}

header udp_t {
    bit<16> srcPort;  // Source port
    bit<16> dstPort;  // Destination port
    bit<16> length;   // Length of the UDP packet
    bit<16> checksum; // Checksum
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;

    // TODO: instantiate the filter and udp headers here
    filter_t     filter;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
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
        transition select(hdr.ipv4.protocol) {
            PROTO_FILTER: parse_filter; // Parse filter if protocol is 146
            default: accept;
        }
    }

    // Parser state for parsing the filter header
    state parse_filter {
        packet.extract(hdr.filter);
        transition select(hdr.filter.proto) {
            PROTO_UDP: parse_udp;  // Parse UDP if filter.proto is 17
            default: accept;
        }
    }

    // Parser state for parsing the UDP header
    state parse_udp {
        packet.extract(hdr.udp); // Extract UDP header
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Action to set the susp field in the filter header */
    action mark_suspicious() {
        hdr.filter.susp = 1;  // Set the suspicious flag to 1
    }

    /* Table that matches on source IP address and UDP source port, and applies actions */
    table filter_table {
        key = {
            hdr.ipv4.srcAddr: exact;  // Match on source IP address
            hdr.udp.srcPort: exact;   // Match on source UDP port
        }
        actions = {
            mark_suspicious;          // Mark the packet as suspicious
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /* Apply the filter table if the filter and UDP headers have been parsed */
            if (hdr.filter.isValid() && hdr.udp.isValid()) {
                filter_table.apply();
            }

            ipv4_exact.apply();  // Proceed with IP forwarding
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        if (hdr.filter.isValid()) {
            packet.emit(hdr.filter); // Emit filter header if valid
        }
        if (hdr.udp.isValid()) {
            packet.emit(hdr.udp);    // Emit UDP header if valid
        }
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
