#!/usr/bin/env python3

# FILE:     auto_attacker.py
# PURPOSE:  Executes attacks from the "attacker.py" script. The attacks
#           are executed in procedures to simulate staged attacks, similar to
#           how it's done in the real-world.


import attacker
import random
import time
import subprocess
import datetime
import pyshark
import threading
import os
import argparse
import sys
from datetime import timezone

# constants
FILEPATH = os.path.dirname(os.path.abspath(__file__))
PCAP_FILE = FILEPATH + "/../data/pcap/" + datetime.datetime.now(timezone.utc).strftime('%d-%H:%S-output.pcap')
TIMESTAMP_FILE = FILEPATH + "/../data/timestamp/" + datetime.datetime.now(timezone.utc).strftime('%d-%H:%S-timestamps.txt')
DOCKER_PATH = None


# Objective 1: Reconnaissance
def recon():
    # port/address scan
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(5)

    # found Modbus devices
    write_timestamp('attack2 : start')
    attacker.function_code_scan(ip_addresses)
    write_timestamp('attack2 : end')
    time.sleep(5)

    # device identification - function code 0x08
    write_timestamp('attack3 : start')
    attacker.device_identification_attack(ip_addresses)
    write_timestamp('attack3 : end')
    time.sleep(5)

    # naively read sensor values to find used coils/registers
    write_timestamp('attack4 : start')
    attacker.naive_sensor_read(ip_addresses)
    write_timestamp('attack4 : end')



# Objective 2: Sporadic Injection
def sporadic_injections():
    # port/address scan
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(5)

    # naively read sensor values to find used coils/registers
    write_timestamp('attack4 : start')
    scanned_addresses = attacker.naive_sensor_read(ip_addresses)
    write_timestamp('attack4 : end')

    # inject values sporadically to all found devices
    write_timestamp('attack5 : start')
    attacker.sporadic_sensor_measurement_injection(ip_addresses, scanned_addresses)
    write_timestamp('attack5 : end')
    
    # reset damaged devices
    time.sleep(1)
    write_timestamp('reset : start')
    reset_devices(ip_addresses)
    write_timestamp('reset : end')



# Objective 3: Disable service through Force Listen Mode
def disable_devices():
    # scan network
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(5)

    # force listen mode on found Modbus devices
    write_timestamp('attack6 : start')
    attacker.force_listen_mode(ip_addresses)
    write_timestamp('attack6 : end')

    # reset damaged devices
    time.sleep(30)
    write_timestamp('reset : start')
    reset_devices(ip_addresses)
    write_timestamp('reset : end')



# Objective 4: Disable service through Restart Communication
def disable_devices_through_restarting():
    # scan network
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(5)

    # send multiple Restart Communication requests
    write_timestamp('attack7 : start')
    attacker.restart_communication(ip_addresses)
    write_timestamp('attack7 : end')

    # reset damaged devices
    time.sleep(30)
    write_timestamp('reset : start')
    reset_devices(ip_addresses)
    write_timestamp('reset : end')



# Objective 5: DOS Servers
def dos():
    # scan network
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(2)

    # flood with connection requests
    write_timestamp('attack9 : start')
    attacker.connection_flood_attack(ip_addresses)
    write_timestamp('attack9 : end')
    time.sleep(5)

    # flood with random modbus read requests
    write_timestamp('attack8 : start')
    attacker.data_flood_attack(ip_addresses)
    write_timestamp('attack8 : end')



# Objective 6: Attempt to find device-related exploits
def find_exploits():
    # address scan to find Modbus devices
    write_timestamp('attack1 : start')
    ip_addresses = attacker.address_scan("192.168.0.0/24")
    write_timestamp('attack1 : end')
    time.sleep(5)

    # device identification attack for device-related exploits
    write_timestamp('attack3 : start')
    attacker.device_identification_attack(ip_addresses)
    write_timestamp('attack3 : end')



# FUNCTION: reset_devices
# PURPOSE:  Resets Docker containers given their ip addresses
def reset_devices(ip_addresses):
    containers = []
    for ip in ip_addresses:
        # find the containers name just given it's ip address
        find_container_name_process = subprocess.run(
            f"docker inspect $(docker ps -q) | grep -B 300 '\"IPAddress\": \"{ip}\"' | grep '\"Name\": \"/' | sed 's/.*\"Name\": \"//;s/\",//;s/\\///'",
            check=True,
            capture_output=True,
            text=True,
            shell=True
        )
        container_name = find_container_name_process.stdout
        containers.append(container_name.strip())

    # reset the containers
    services = ' '.join(containers)
    reset_container_process = subprocess.run(
        f"docker compose -f {DOCKER_PATH} restart {services}",
        check=True,
        capture_output=True,
        text=True,
        shell=True
    )
    print(reset_container_process.stdout)
    print(reset_container_process.stderr)
    print(f"Reset devices {containers}, ips: {ip_addresses}")



# FUNCTION: write_timestamp
# PURPOSE:  Creates a timestamp into a timestamp file
def write_timestamp(text):
    # print to file timestamping when attack starts
    #dt = datetime.datetime.now(timezone.utc)
    dt = datetime.datetime.now()
    formatted_time = dt.strftime('%H:%M:%S') + f'.{dt.microsecond}'

    with open(TIMESTAMP_FILE, 'a') as file:
        file.write(f'{text} : {formatted_time}\n')



# FUNCTION: start_attack
# PURPOSE:  Runs a given attack and logs the time stamp
def start_attack(func, objective_number):
        # print to file timestamping when attack starts
        write_timestamp(f'objective{objective_number} : start')

        # perform attack
        print(f"\n\nObjective {objective_number} started\n\n")
        func()
        print(f"\n\nObjective {objective_number} finished\n\n")

        # print to file timestamping when attack ends
        write_timestamp(f'objective{objective_number} : end')



# FUNCTION: start_capture
# PURPOSE:  Will start sniffing packets from the specified network
#           and builds a PCAP file (similar to wireshark)
def start_capturing(interface,):
    capture = pyshark.LiveCapture(
        interface=interface,
        output_file=PCAP_FILE
    )
    capture.set_debug()

    print(f"Starting capture on {interface} and saving to {os.path.abspath(PCAP_FILE)}")
    try:
        capture.sniff()
    except KeyboardInterrupt:
        print("Capture interupted")
    finally:
        capture.close()



# FUNCTION: start_attacking
# PURPOSE:  Thread function to start the attack cycles
def start_attacking():
    # extra: only perform dos attack once total to avoid data bias

    time.sleep(10)

    start_attack(sporadic_injections, 2)
    sys.exit()

    time.sleep(45)
    start_attack(dos, 6)

    while True:
        selections = list(range(1, 6))

        while selections:
            # perform a random attack, ensuring each attack is performed once
            selection = random.choice(selections)
            selections.remove(selection)

            min_time = 1
            max_time = 2
            print(f"Waiting a random amount of time ({min_time} to {max_time} minutes) before next attack...")
            wait_time = random.randint(min_time * 60, max_time * 60)
            time.sleep(wait_time)

            # perform attack
            if selection == 1:
                start_attack(recon, 1)
            elif selection == 2:
                start_attack(sporadic_injections, 2)
            elif selection == 3:
                start_attack(disable_devices, 3)
            elif selection == 4:
                start_attack(disable_devices_through_restarting, 4)
            elif selection == 5:
                start_attack(find_exploits, 5)



if __name__ == "__main__":
    print(r"""\
    \            _    _            _
     \          | |  | |          | |
      \\        | |__| | __ _  ___| | __
       \\       |  __  |/ _` |/ __| |/ /
        >\/7    | |  | | (_| | (__|   <
    _.-(6'  \   |_|  |_|\__,_|\___|_|\_\
   (=___._/` \         _   _
        )  \ |        | | | |
       /   / |        | |_| |__   ___
      /    > /        | __| '_ \ / _ \
     j    < _\        | |_| | | |  __/
 _.-' :      ``.       \__|_| |_|\___|
 \ r=._\        `.
<`\\_  \         .`-.          _____  _                  _   _
 \ r-7  `-. ._  ' .  `\       |  __ \| |                | | | |
  \`,      `-.`7  7)   )      | |__) | | __ _ _ __   ___| |_| |
   \/         \|  \'  / `-._  |  ___/| |/ _` | '_ \ / _ \ __| |
              ||    .'        | |    | | (_| | | | |  __/ |_|_|
               \\  (          |_|    |_|\__,_|_| |_|\___|\__(_)
                >\  >
            ,.-' >.'
           <.'_.''
             <''
             """)
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-d", "--dockerpath", required=True)

    args = parser.parse_args()
    interface = args.interface
    DOCKER_PATH = args.dockerpath

    # setup directories
    os.makedirs(FILEPATH + "/../data/pcap", exist_ok=True)
    os.makedirs(FILEPATH + "/../data/timestamp", exist_ok=True)

    # start thread for running attacks
    attacker_thread = threading.Thread(target=start_attacking, args=(), daemon=True)
    attacker_thread.start()

    # start recording packet data
    start_capturing(interface)

    # block on thread
    attacker_thread.join()