#!/usr/bin/env python3

# FILE:     flow_based_generator.py
# PURPOSE:  Takes in a PCAP and builds a custom dataset with extracted features. The
#           dataset is constructed with flow-based features. "pyflowmeter" is used to
#           generate the dataset.

import argparse
from pyflowmeter.sniffer import create_sniffer


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True)
    #parser.add_argument("-t", "--timestamps", required=True)
    parser.add_argument("-o", "--output", required=True)

    args = parser.parse_args()
    pcap_file = args.pcap
    #timestamp_file = args.timestamps
    output_file = args.output

    print(f"PCAP file: {pcap_file}")
    print(f"DATASET (OUTPUT) file: {output_file}")
    print()
    print(f"Creating dataset from these files")

    # create dataset
    print("<1/1> Creating CSV dataset")

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