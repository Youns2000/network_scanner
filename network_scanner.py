##############################################################################################
################################### NETWORK SCANNER ##########################################
##############################################################################################
#######################         AUTHOR: Younes Benreguieg          ###########################
#######################            DATE: June 2021                 ###########################
#######################     Algebra University College, Hrvatska   ###########################
##############################################################################################

from scapy.all import *
import argparse
import socket
import requests

#GET_ARGS() : Parsing the script arguments to run the right methods
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--arp', dest='arp', help='Target IP Address/Adresses')
    parser.add_argument('-i', '--icmp', dest='icmp', help='Target IP Address/Adresses')
    parser.add_argument('-t', '--tcp', dest='tcp', help='Target IP Address/Adresses')
    parser.add_argument('-u', '--udp', dest='udp', help='Target IP Address/Adresses')
    parser.add_argument('-p', dest='ports', help='Target Port/Ports')

    options = parser.parse_args()

    #if no arguments have been entered, the script run an error.
    if not (options.arp or options.icmp or options.tcp or options.udp):
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")

    #the "-p" ports option is available only for the tcp and the udp scan
    if (options.arp or options.icmp) and options.ports:
        parser.error("[-] Ports argument (-p) only available for -t or -u.")
        
    return options

#FORMAT_PORTS(): formating the ip adresses entered
#exemple : network_scanner.py -a 192.168.8.1-192.168.8.5
# is arp scanning for each ip adresses from 192.168.8.1 to 192.168.8.5
def format_ip(inputs):
    target_ip = []

    if '-' in inputs:
        ips = inputs.split('-')

        first_bits = ""
        for i in range(3):
            first_bits += ips[0].split('.')[i]+"."

        first = int(ips[0].split('.')[3])
        last = int(ips[1].split('.')[3])

        for i in range(first,last+1):
            target_ip.append(first_bits+str(i))

    else:
        target_ip.append(inputs)

    return target_ip

#FORMAT_PORTS(): formating the ports entered in the -p option of tcp and udp scan
#exemple : -p 22,80-443 is checking the port 22 and the ports between 80 and 443
def format_ports(inputs):
    target_ports = []
    ports = inputs.split(',')
    for p in ports:
        if '-' in p:
            ranges = p.split('-')
            for r in ranges:
                r.replace(' ','')
            for i in range(int(ranges[0]),int(ranges[1])+1):
                target_ports.append(i)
        else:
            target_ports.append(int(p))
    return target_ports

#GET_MAC_DETAILS(): get manufactures informations of a device using its MAC adresse
def get_mac_details(mac_address):
      
    # We will use an API to get the manufactures name
    url = "https://api.macvendors.com/"
      
    # Use get method to fetch details
    response = requests.get(url+mac_address)
    if response.status_code != 200:
        return 0
    return response.content.decode()   

#BANNER_GRABBER(): connect to an open port of the target_ip, send a message and grab the ban from the response
def banner_grabber(ip,port):

    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #TCP

    sock.connect((str(ip),int(port)))
    message = 'GET HTTP/1.1 \r\n'
    sock.send(message.encode())
    ret = sock.recv(1024)
    sock.close()
    return ret


#ARP(): arp scan for the target_ip
def arp(target_ip):
    #creating the packet for every MAC adresses on the target_ip
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip) 

    #sending the packets with srp() and getting only the answered results ([0] for the answered and [1] for the unanswered)
    result = srp(packet, timeout=2, verbose=0)[0] 

    clients = []
    for sent, received in result:
        #adding in the client array the ip and the mac adress of the targets that responded
        clients.append({'ip': received.psrc, 'mac': received.hwsrc}) 

    for client in clients:
        mac_details = get_mac_details(client['mac'])
        if(mac_details != 0):
            print("{:16}    {} ({})".format(client['ip'], client['mac'], mac_details ))
        else:
            print("{:16}    {} (Unknown)".format(client['ip'], client['mac'] ))

#ICMP(): icmp scan for the target_ip
def icmp(target_ip):
    try:
        ans,unans = sr(IP(dst=target_ip) / ICMP(), timeout=1, verbose=0)
    except:
        raise Exception("Error!")
    # print('Answers:\n')
    for sent,received in ans:
        print("{} is alive".format(received.src))

#TCP(): tcp scan for the target_ip and the ports
def tcp(target_ip,ports):
    try:
        packet = IP(dst=target_ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))
    except KeyboardInterrupt:
        print("Keyboard interruption")

    ans, unans = sr(packet, timeout=1, retry=1, verbose=0)

    print("\n\n"+target_ip)
    print("PORT" + " "*16+"STATUT"+ " "*14+"SERVICE")
    for sent, received in ans:
        if received[TCP].flags == "SA":
            print("{:16}    {:16}     {}".format(str(received[TCP].sport)+"/tcp", "opened" , socket.getservbyport(received[TCP].sport , "tcp")))
            try:
                print("Banner Grabbing...")
                print(banner_grabber(target_ip,received[TCP].sport))
            except:
                pass

        else:
            try:
                print("{:16}    {:16}     {}".format(str(received[TCP].sport)+"/tcp", "closed" , socket.getservbyport(received[TCP].sport, "tcp")))
            except:
                print("{:16}    {:16}     {}".format(str(received[TCP].sport)+"/tcp", "closed" , ""))

#UDP(): udp scan for the target_ip and the ports
def udp(target_ip,ports):
    try:
        packet = IP(dst=target_ip) / UDP(dport=ports)
        ans, unans = sr(packet, timeout=1, retry=1, verbose=0)
    except KeyboardInterrupt:
        print("Keyboard interruption")
    except:
        raise ValueError('Hostname {} could not be resolved.'.format(target_ip))
    if ans:
        for s,r in ans:
            if r[ICMP].type == 3 and r[ICMP].code == 3:
                print("{}:{} is closed".format(r[IP].src,r['UDP in ICMP'].dport))
            elif r.haslayer(UDP):
                print("{}:{} is opened".format(r[IP].src,r['UDP'].dport))
                try:
                    print("Banner Grabbing...")
                    print(banner_grabber(r[IP].src,r['UDP'].dport))
                except:
                    pass
    else:
        print("{} no open ports".format(target_ip))

if __name__ == "__main__":

    options = get_args()

    if options.arp:
        print("*********************************************")
        print("******************** ARP ********************")
        print("*********************************************")
        ips = format_ip(options.arp)
        print("Available devices in the network:")
        print("IP" + " "*18+"MAC")
        for ip in ips:
            arp(ip)

    if options.icmp:
        print("*********************************************")
        print("******************** ICMP *******************")
        print("*********************************************")
        ips = format_ip(options.icmp)
        for ip in ips:
            icmp(ip)

    if options.tcp:
        if options.ports:
            print("*********************************************")
            print("******************** TCP ********************")
            print("*********************************************")
            ips = format_ip(options.tcp)
            target_ports = format_ports(options.ports)
            for ip in ips:
                tcp(ip,target_ports)

    if options.udp:
        if options.ports:
            print("*********************************************")
            print("******************** UDP ********************")
            print("*********************************************")
            ips = format_ip(options.udp)
            target_ports = format_ports(options.ports)
            for ip in ips:
                udp(str(ip),target_ports)