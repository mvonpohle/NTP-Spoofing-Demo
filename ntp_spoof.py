'''

Python code that receives packets from linux ip tables and modifies NTP server
response packets in transit

Task Division:
#3 & #4 - Check_ntp(/*packet from netfilter queue) - Karthik
	• Checks that ntp packet & that it's an ntp server response
	• Passes ntp payload to modify_ntp()
	• Checks status code
	• Handles udp manipulation - updating checksum
	• Returns packet to netfilterqueue
#5 - Modfy_ntp(/*ntp payload */) - Michael
	• Modifies the appropriate ntp packet fields
	• Returns a status code
#1 & #2 - main() - siddharth
	• Setup arp spoofing, ip forwarding, kamene(scapy), netfilterqueue
	• Print status messages handle clean up

'''


def check_ntp():  # argument is packet from netfilter queue
    print("check_ntp")
    #calls modify_ntp

def modify_ntp():  # argument is ntp payload
    print("modify_ntp")


def main():  # no arguments
    print("main")
    #calls check_ntp

main()
