#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def writeForwardingRule(p4info_helper, sw, dst_ip_addr, src_eth_addr,
                         dst_eth_addr, port):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param dst_ip_addr: the destination IP to match
    :param dst_eth_addr: the destination Ethernet address to write in the packet
    :param port: the port to forward the packet out of 
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_exact",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "srcAddr": src_eth_addr,
            "port": port,
        })
    sw.WriteTableEntry(table_entry)
    print("Installed forwarding rule to %s on %s" % (dst_ip_addr, sw.name))

def writeAllForwardingRules(p4info_helper, sw_list):
    s1, s2, s3, s4 = sw_list

def writeAllForwardingRules(p4info_helper, sw_list):
    s1, s2, s3, s4 = sw_list

    # Write forwarding rules for s1
    writeForwardingRule(p4info_helper, sw=s1, dst_ip_addr="10.0.1.1", 
                         dst_eth_addr="08:00:00:00:01:11", src_eth_addr="08:00:00:00:01:01", port=1) 

    writeForwardingRule(p4info_helper, sw=s1, dst_ip_addr="10.0.2.2", 
                         dst_eth_addr="08:00:00:00:02:22", src_eth_addr="08:00:00:00:01:01", port=2) 

    writeForwardingRule(p4info_helper, sw=s1, dst_ip_addr="10.0.3.3", 
                         dst_eth_addr="08:00:00:00:03:00", src_eth_addr="08:00:00:00:01:01", port=3) 

    writeForwardingRule(p4info_helper, sw=s1, dst_ip_addr="10.0.4.4", 
                         dst_eth_addr="08:00:00:00:04:00", src_eth_addr="08:00:00:00:01:01", port=4) 

    # Write forwarding rules for s2
    writeForwardingRule(p4info_helper, sw=s2, dst_ip_addr="10.0.1.1",
                         dst_eth_addr="08:00:00:00:03:00", src_eth_addr="08:00:00:00:02:01", port=4)
    
    writeForwardingRule(p4info_helper, sw=s2, dst_ip_addr="10.0.2.2",
                         dst_eth_addr="08:00:00:00:04:00", src_eth_addr="08:00:00:00:02:01", port=3) 

    writeForwardingRule(p4info_helper, sw=s2, dst_ip_addr="10.0.3.3",
                         dst_eth_addr="08:00:00:00:03:33", src_eth_addr="08:00:00:00:02:01", port=1)

    writeForwardingRule(p4info_helper, sw=s2, dst_ip_addr="10.0.4.4",
                         dst_eth_addr="08:00:00:00:04:44", src_eth_addr="08:00:00:00:02:01", port=2)

    # Write forwarding rules for s3
    writeForwardingRule(p4info_helper, sw=s3, dst_ip_addr="10.0.1.1",
                         dst_eth_addr="08:00:00:00:01:00", src_eth_addr="08:00:00:00:03:01", port=1)
    
    writeForwardingRule(p4info_helper, sw=s3, dst_ip_addr="10.0.2.2",
                         dst_eth_addr="08:00:00:00:01:00", src_eth_addr="08:00:00:00:03:01", port=1) 

    writeForwardingRule(p4info_helper, sw=s3, dst_ip_addr="10.0.3.3",
                         dst_eth_addr="08:00:00:00:02:00", src_eth_addr="08:00:00:00:03:01", port=2)

    writeForwardingRule(p4info_helper, sw=s3, dst_ip_addr="10.0.4.4",
                         dst_eth_addr="08:00:00:00:02:00", src_eth_addr="08:00:00:00:03:01", port=2)

    # Write forwarding rules for s4
    writeForwardingRule(p4info_helper, sw=s4, dst_ip_addr="10.0.1.1",
                         dst_eth_addr="08:00:00:00:01:00", src_eth_addr="08:00:00:00:04:01", port=2)
    
    writeForwardingRule(p4info_helper, sw=s4, dst_ip_addr="10.0.2.2",
                         dst_eth_addr="08:00:00:00:01:00", src_eth_addr="08:00:00:00:04:01", port=2) 

    writeForwardingRule(p4info_helper, sw=s4, dst_ip_addr="10.0.3.3",
                         dst_eth_addr="08:00:00:00:02:00", src_eth_addr="08:00:00:00:04:01", port=1)

    writeForwardingRule(p4info_helper, sw=s4, dst_ip_addr="10.0.4.4",
                         dst_eth_addr="08:00:00:00:02:00", src_eth_addr="08:00:00:00:04:01", port=1) 



def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")
        
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s4")

        sw_list = [s1, s2, s3, s4]
        # Write forwarding rules
        writeAllForwardingRules(p4info_helper, sw_list);  

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/forwarding.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/forwarding.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
