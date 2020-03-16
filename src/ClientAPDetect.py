from scapy.all import *
import requests, time, threading, sys, netifaces, argparse

# Args parsing
parser = argparse.ArgumentParser(prog="Client Access point ",
                                 usage="%(prog)s -i mon0",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False, help="The BSSID of the Wireless Access Point you want people to connect to (Will default to interface's mac if not specified)", default="")


args = parser.parse_args()

# Basic sanity check before attempting to insert into the dictionary
def insertStaToBssid(sta, bssid):
    if sta not in STA_to_BSSIDs:
        STA_to_BSSIDs[sta] = []
    if bssid in STA_to_BSSIDs[sta]:
        return
    if bssid == "ff:ff:ff:ff:ff:ff" or sta == "ff:ff:ff:ff:ff:ff":
        return

    if bssid == "00:00:00:00:00:00":
        return

    STA_to_BSSIDs[sta].append(bssid)
    DisplayFunc(sta, bssid)


# We sniff all Dot11 probe request packets, and store 1 packet per AP bssid
def packetHandler(p):
    if p.FCfield & 0x1 != 0 or p.FCfield & 0x2 != 0:
        return
    
    if p.haslayer(Dot11Elt) and str(p.addr3) not in BSSID_to_SSID and len(p.info) > 0:
        BSSID_to_SSID[str(p.addr3)] = p.info

    if str(p.addr3) == "ff:ff:ff:ff:ff:ff" or str(p.addr3) == "None" or (p.addr2 == p.addr3 and str(p.addr1) == "ff:ff:ff:ff:ff:ff"):
        return

    if p.addr3 == p.addr2:
        insertStaToBssid(str(p.addr1), str(p.addr3))
    else:
        insertStaToBssid(str(p.addr2), str(p.addr3))
    
        

# Diplay function, run every time a new AP is found
def DisplayFunc(sta, bssid):
    print("%s    %s" % (sta, bssid ))
    

BSSID_to_SSID = {}

STA_to_BSSIDs = {}



print("STAs                 APs      ")



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




