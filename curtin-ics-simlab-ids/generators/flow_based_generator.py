#!/usr/bin/env python3

# FILE:     flow_based_generator.py
# PURPOSE:  Takes in a PCAP and builds a custom dataset with extracted features. The
#           dataset is constructed with flow-based features. "pyflowmeter" is used to
#           generate the dataset.

import argparse
import datetime
from pyflowmeter.sniffer import create_sniffer



# Function: flag_flow
# Purpose: Checks if a flow is malicious.
#   Malicious flows are either IP or ARP flows with source or
#   destination of 192.168.0.1
def flag_flow(packet):
    # initialise fields to search with
    hacker_ip = "192.168.0.1"
    is_attack = False
    
    # for IP layer packets
    if 'IP' in packet:
        ip_layer = packet['IP']

        # check if packets is to or from the hacker (192.168.0.1)
        if ip_layer.src == hacker_ip or ip_layer.dst == hacker_ip:
            is_attack = True
    
    # for ARP packets
    if 'ARP' in packet:
        arp_layer = packet['ARP']

        # check if it's an ARP request and the target IP matches
        if arp_layer.src.proto_ipv4 == hacker_ip:  # 1 is ARP request
            is_attack = True
    
    return is_attack



# Function: get_attack_data
# Purpose: Uses the timestamp file to label each attack packet
def get_attack_data(packet, timestamp_file):
    # get and format packet time
    pkt_time = packet.sniff_time

    file = open(timestamp_file, 'r')
    lines = file.readlines()

    prev_items = []
    for line in lines:
        items = line.split(" : ")

        # get latest objective
        if "objective" in items[0]:
            obj = items[0]
        else:
            # convert the timestamp in the file to a datetime
            att_time = datetime.strptime(items[2].strip(), "%H:%M:%S.%f")

            # find the first items timestamp that is greater than the packets timestamp
            if att_time.time() > pkt_time.time():
                # get the attack from the previous line 
                attack = prev_items[0]
                
                # get corresponding attack category
                attack_num = ''.join(filter(str.isdigit, attack))

                # get objective number
                obj_num = ''.join(filter(str.isdigit, obj))
                return attack_num, obj_num
        prev_items = items
    return "N/A", "N/A"



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True)
    parser.add_argument("-o", "--output", required=True)

    args = parser.parse_args()
    pcap_file = args.pcap
    output_file = args.output

    print(f"PCAP file: {pcap_file}")
    print(f"DATASET (OUTPUT) file: {output_file}")
    print()
    print(f"Creating dataset from these files")

    # create CSV dataset (without labels)
    print("<1/1> Creating initial CSV dataset")

    sniffer = create_sniffer(
        input_file=pcap_file,
        to_csv=True,
        output_file=output_file,
    )

    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt:
        print('Stopping the sniffer')
        sniffer.stop()
    finally:
        sniffer.join()

    print("Finished!")