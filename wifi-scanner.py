#!/usr/bin/python

from scapy.all import *
import sys
import signal
import os

#Function to handle Crtl+C
def signal_handler(signal, frame):
	print('\n=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def signal_exit(signal, frame):
	print "Signal exit"
	sys.exit(1)

def usage():
	if len(sys.argv) < 3:
		print("\nUsage:")
		print("\twifi-scanner.py -i <interface>\n")
		sys.exit(1)

def sniffpackets(packet):
	try:
		SRCMAC = packet[0].addr2
		DSTMAC = packet[0].addr1
		BSSID = packet[0].addr3
	except:
		print("Cannot read MAC address")
		print(str(packet).encode("hex"))
		sys.exc_clear()

	try:
		SSIDSize = packet[0][Dot11Elt].len
		SSID = packet[0][Dot11Elt].info
	except:
		SSID = ""
		SSIDSize = 0

	if packet[0].type == 0:
		ST = packet[0][Dot11].subtype
		if str(ST) == "8" and SSID != "" and DSTMAC.lower() == "ff:ff:ff:ff:ff:ff":
			p = packet[Dot11Elt]
			cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}" 
							  "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
			channel = None
			crypto = set()
			while isinstance(p, Dot11Elt):
				try:
					if p.ID == 3:
						channel = ord(p.info)
					elif p.ID == 48:
						crypto.add("WPA2")
					elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
						crypto.add("WPA")
				except:
					pass
				p = p.payload
			if not crypto:
				if 'privacy' in cap:
					crypto.add("WEP")
				else:
					crypto.add("OPN")
			if SRCMAC not in ssid_list.keys():
				if '0050f204104a000110104400010210' in str(packet).encode("hex"):
					crypto.add("WPS")
				print("[+] New AP {0:5}\t{1:20}\t{2:20}\t{3:5}".format(channel, BSSID, ' / '.join(crypto), SSID))
				ssid_list[SRCMAC] = SSID

def init_process ():
	global ssid_list
	ssid_list = {}
	global s
	s = conf.L2socket(iface=newiface)

def setup_monitor (iface):
	print("Setting up sniff options...")
	os.system('ifconfig ' + iface + ' down')
	try:
		os.system('iwconfig ' + iface + ' mode monitor')
	except:
		print("Failed to setup monitor mode")
		sys.exit(1)
	os.system('ifconfig ' + iface + ' up')
	return iface

def check_root():
	if not os.geteuid() == 0:
		print("Run as root.")
		exit(1)

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	usage()
	check_root()
	parameters ={sys.argv[1]:sys.argv[2]}
	if "mon" not in str(parameters["-i"]):
		newiface = setup_monitor(parameters["-i"])
	else:
		newiface = str(parameters["-i"])
	init_process()
	print("Sniffing on interface " + str(newiface) + "...\n")
	sniff(iface=newiface, prn=sniffpackets, store=0)
