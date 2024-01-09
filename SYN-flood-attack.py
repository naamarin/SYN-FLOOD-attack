#by Naama Iluz ID 212259204
from scapy.all import *


SUSPICIES_NUM_OF_SYN = 8        #If the number is higher than 8 it does not contain all the addresses in the file and if it is lower than 8 it adds additional addresses
ATTACK_IP = "100.64"            #the start of the attacked ip address
SYN_ATTACKS = []                #to save the suspicies ips addresses
SYN_PACKETS = {}                #to save for every ip the number of SYN
SYN_FLAG = 2                    #The numerical value of SYN flag
ACK_FLAG = 16                   #The numerical value of ACK flag


def create_file():
    # Create the text file
    with open("attack addresses.txt", "w") as file:
        content = "\n".join(SYN_ATTACKS)
        file.write(content)


def SYNFlood(pcapFile):
    for packet in pcapFile:
        if packet.haslayer(TCP): #three-way-handshake its part of protocol tcp
            if packet[TCP].flags == SYN_FLAG and packet[IP].src not in SYN_PACKETS and (packet[IP].dst).startswith(ATTACK_IP):
                """If the SYN flag is on and the destination IP is 100.64 and this is the first time this address sends a SYN, we will add it to the dictionary"""
                SYN_PACKETS[packet[IP].src] = 0
            elif packet[TCP].flags == SYN_FLAG and packet[IP].src in SYN_PACKETS and (packet[IP].dst).startswith(ATTACK_IP):
                """If the SYN flag is on and the destination IP is 100.64 and this is not the first time that this address sends a SYN, we will add in the dictionary the number of times the SYN was sent"""
                SYN_PACKETS[packet[IP].src] += 1
                if SYN_PACKETS[packet[IP].src] > SUSPICIES_NUM_OF_SYN and packet[IP].src not in SYN_ATTACKS:
                    """If the number of times this address sent a SYN request is greater than 9, then we will add it to the list of suspicious addresses"""
                    SYN_ATTACKS.append(packet[IP].src)
            elif packet[TCP].flags == ACK_FLAG and packet[IP].src in SYN_PACKETS and (packet[IP].dst).startswith(ATTACK_IP):
                """If an ACK request has arrived from an address that is in the dictionary to an address that starts with 100.64, we will remove it from the dictionary"""
                SYN_PACKETS.pop(packet[IP].src)


def main():
    try:
        pcapFile = rdpcap("SYNflood.pcapng")
    except:
        print("There is no such file!")
    SYNFlood(pcapFile)
    create_file()


if __name__ == "__main__":
    main()