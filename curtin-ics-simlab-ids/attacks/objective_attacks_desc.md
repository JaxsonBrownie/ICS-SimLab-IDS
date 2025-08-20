# Objective-Based Attacks
Real-world cyber-attacks do happen in isolation. Different attacks are perform at different stages to achieve an overall goal. The following objectives represent procedures of cyber-attacks performed in unison to achieve an overall goal. 

The procedure attack use attacks defined in the python attack script `attacker.py`.

`auto_attacker.py` contains code to run certain attacks within these objectives.

Each attack objective is classified by a level of sophistication.

---
## Level 1 - Basic

### Objective 1: Reconnaissance
1. address scan for PLCs
2. function code scans for valid Modbus function codes
3. device identification attack
3. naive sensor read to find used registers

### Objective 2: Sporadic Injections
1. address scan for PLCs
2. naive sensor read to find used registers
3. sporadic sensor measurement

### Objective 3: Disable service through Force Listen Mode
1. address scan
2. force listen mode to found IPs

### Objective 4: Disable service through Restart Communication
1. address scan
2. restart communication attack to found IPs

## Level 2 - Attacks on Network Layer
### Objective 5: DOS Servers
1. connection flood attack
2. data flood attack

### Objective 6: Attempt to find device-related exploits
1. address scan
2. device identification attack


---
# Simulation Specific Attacks
The following are attacks that are specific to a simulation type. They cannot be used against different ICS types.

## Level 3 - Intent to damage system

### Objective 7: Cause power outage for a house ??
1. address scan for PLCs
2. function code scan to obtain valid Modbus function codes
3. perform naive sensor read to find unique values
4. alter values in a unique way to cause damage

### Objective 8: Burn out transfer switch ??
1. address scan for PLCs
2. function code scan
3. naive sensor read
4. altered actuator state repeatedly in quick sucession

## Level 4 - Intent to Mask Proper System Operation
### Objective 9: Replay captured data to mask broken sensors ??
1. turn off HIL to simulate damaged/malfunctioned device
2. replay measurement injection

### Objective 10: Simulate greater-than-normal solar power generation ??
1. turn off HIL to simulate damaged/malfunctioned device
2. calculated sensor measurement injection