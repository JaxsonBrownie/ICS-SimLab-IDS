# Specific Attacks
These are all the ICS attacks implemented in `attacker.py`. We given them a number to categories them in the datasets.

1. address scan
2. function code scan
3. device identification attack
4. naive sensor read
5. sporadic sensor measurement injection
6. force listen mode
7. restart communication
8. data flood attack
9. connection flood attack

---
# Objective-Based Attacks
Real-world cyber-attacks do not happen in isolation. Different attacks are perform at different stages to achieve an overall goal. The following objectives represent procedures of cyber-attacks performed in unison to achieve an overall goal. 

The procedure attack use attacks defined in the python attack script `attacker.py`.

`auto_attacker.py` contains code to run certain attacks within these objectives.

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

### Objective 5: Attempt to find device-related exploits
1. address scan
2. device identification attack

### Objective 6: DOS Servers
1. connection flood attack
2. data flood attack
