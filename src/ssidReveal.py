from scapy.all import *
import requests, time, threading, sys, netifaces, argparse

# Args parsing
parser = argparse.ArgumentParser(prog="Scapy Hidden SSID reveal",
                                 usage="%(prog)s -i mon0",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()

Hidden_bssids = []

bssid_to_ssid = {}


# We sniff all Dot11 probe response and beacon packets, we store for each empty beacon, the bssid associated with the AP, and for each probe response, the ssid associated with the BSSID of the AP. When we have a packet in both maps, we display the ssid of the hidden AP that we discovered.
def packetHandler(p):
    if p.haslayer(Dot11Beacon) and (p.info == b"" or p.ID != 0) and str(p.addr3) not in Hidden_bssids:
        Hidden_bssids.append(str(p.addr3))
        if str(p.addr3) in bssid_to_ssid:
            displayHiddenAP(str(p.addr3), bssid_to_ssid[str(p.addr3)])
    
    if p.haslayer(Dot11ProbeResp) and str(p.addr3) not in bssid_to_ssid:
        print(p.info)
        bssid_to_ssid[str(p.addr3)] = p.info
        if str(p.addr3) in Hidden_bssids:
            displayHiddenAP(str(p.addr3), bssid_to_ssid[str(p.addr3)])
        

# Diplay function, run every time a new AP is found
def displayAP(bssid, ssid):
    print("%s %s" % (bssid, ssid))
    print("Press CTRL+C to stop scanning",end = "\r")

SSIDs = []


print("List of hidden SSIDs uncovered (BSSID -> SSID) : ")



# Use a separate thread to sniff, so we can stop it later and can run the detection section forever
e = threading.Event()

def _sniff(e):
    a = sniff(iface=args.Interface, prn=packetHandler, stop_filter=lambda p: e.is_set())


t = threading.Thread(target=_sniff, args=(e,))
t.start()

# Infinite loop, until the user keyboard interrupts the script with CTRL+C
try:
    while True:
        time.sleep(1)
except (KeyboardInterrupt, SystemExit):
    e.set()

    while t.is_alive():
        t.join(2)
