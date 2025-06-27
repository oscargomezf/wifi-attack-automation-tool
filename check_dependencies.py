#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# /**
#  * @file check_dependencies.py
#  * @author Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @modified Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @date 2025-06-23 17:39:37 
#  * @version 1.0
#  * @section DESCRIPTION
#  *     This library verifies all the required Python package dependencies and tools
#  *     necessary to run the wifi-attack_automation-tool
#  */
# -----------------------------------------------------------------------------

import shutil
import importlib.util
import sys
from print_helper_logger import Print_Helper, Severity_Level

def check_required_packages(ph):
	"""
	Verifies required Python packages and internal modules.
	Displays success or failure per package.
	"""
	external_packages = ['print_helper_logger', 'scapy']
	missing_packages = []

	ph.print_inf(f"Verifying required Python packages:\n")
	for package in external_packages:
		if importlib.util.find_spec(package) is not None:
			ph.print_inf(f"{package} is installed\n")
		else:
			ph.print_err(f"{package} is missing\n")
			missing_packages.append(package)

	# Check internal module (deauth_lib must be in the PYTHONPATH or current dir)
	try:
		import deauth_lib
		ph.print_inf(f"deauth_lib is available\n")
	except ImportError:
		ph.print_err(f"Internal module 'deauth_lib' not found\n")
		ph.print_err(f"Make sure the 'deauth_lib' folder is in your current directory or PYTHONPATH\n")
		return False

	if missing_packages:
		ph.print_err(f"Please install the missing packages before running this application again\n")
		return False
	else:
		ph.print_inf(f"All required Python packages are ready\n")
		return True

def check_required_tools(ph):
	"""
	Verifies whether required system tools are installed:
	- airodump-ng
	- hcxpcapngtool
	"""

	required_tools = ["iw", "ifconfig", "iwconfig", "airodump-ng", "hcxpcapngtool", "hashcat"]
	missing = []

	ph.print_inf(f"Verifying required tools:\n")
	for tool in required_tools:
		if shutil.which(tool) is not None:
			ph.print_inf(f"{tool} found\n")
		else:
			ph.print_err(f"{tool} not found\n")
			missing.append(tool)

	if missing:
		ph.print_err(f"Required tools are missing. Please install them before re-running this application\n")
		return False
	else:
		ph.print_inf(f"All tools are ready. System check passed\n")
		return True
