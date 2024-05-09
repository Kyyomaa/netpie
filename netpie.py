from scapy.all import sniff, IP, TCP, UDP
import socket
import argparse
import os
from prettytable import PrettyTable

class Sniffer:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.ip_addr = socket.gethostbyname(self.hostname)
        self.contact_ips = set()

        self.protocols = {
            1: ("ICMP", '\033[93m'),   # Yellow
            6: ("TCP", '\033[32m'),    # Green
            17: ("UDP", '\033[94m')    # Blue
        }
        self.colors = {
            "incoming": '\033[1;31m',  # Bold Red
            "outgoing": '\033[93m',    # Yellow
            "reset": '\033[0m'         # Reset
        }
    def banner(self):
        # Clear the terminal
        os.system('clear')
        print(f"""



                               █████             █████               █████   
                              ░░███             ░░███               ░░███    
 ████████  ████████   ██████  ███████    ██████  ░███████   ██████  ███████  
░░███░░███░░███░░███ ███░░███░░░███░    ███░░███ ░███░░███ ███░░███░░░███░   
 ░███ ░███ ░███ ░░░ ░███ ░███  ░███    ░███ ░███ ░███ ░███░███ ░███  ░███    
 ░███ ░███ ░███     ░███ ░███  ░███ ███░███ ░███ ░███ ░███░███ ░███  ░███ ███
 ░███████  █████    ░░██████   ░░█████ ░░██████  ████████ ░░██████   ░░█████ 
 ░███░░░  ░░░░░      ░░░░░░     ░░░░░   ░░░░░░  ░░░░░░░░   ░░░░░░     ░░░░░  
 ░███                                                                        
 █████                                                                       
░░░░░                                                                        


        """)
    def get_hostname(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return ""

    def packet_handler(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if src_ip != self.ip_addr:
                self.contact_ips.add(packet[IP].src)
            if dst_ip != self.ip_addr:
                self.contact_ips.add(packet[IP].dst)       
            
            protocol = packet[IP].proto
            src_hostname = self.get_hostname(src_ip)
            dst_hostname = self.get_hostname(dst_ip)
            
            src_port = dst_port = None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            if protocol in self.protocols:
                proto_name, proto_color = self.protocols[protocol]
                direction = "outgoing" if src_ip == self.ip_addr else "incoming"
                print(f"{self.colors[direction]}{direction.capitalize()} {self.colors['reset']} {proto_name} Packet: "
                      f"{src_ip} {src_port} | {proto_color}{src_hostname}{self.colors['reset']} -> {dst_ip} {dst_port} | "
                      f"{proto_color}{dst_hostname}{self.colors['reset']}")
        '''
        iptot = []
        if src_ip not in iptot:
            iptot.append(src_ip)
            lenIpTot = len(iptot)
            return lenIpTot
        prototot = []
        duration = 0
        pactoto = []
        '''

    def start_sniffing(self, filter_protocols=None, filter_direction=None, filter_ip=None, filter_port=None):
       
        filters = ["ip"]
        # Protocol filter
        if filter_protocols:
            protocol_map = {'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp'}
            protocol_filters = [protocol_map[proto] for proto in filter_protocols if proto in protocol_map]
            if protocol_filters:
                filters.append(f"({' or '.join(protocol_filters)})")
        
        # Direction filter
        if filter_direction:
            direction_filters = []
            if 'in' in filter_direction:
                direction_filters.append(f"dst host {self.ip_addr}")
            if 'out' in filter_direction:
                direction_filters.append(f"src host {self.ip_addr}")
            if direction_filters:
                filters.append(f"({' or '.join(direction_filters)})")
                
        # IP filter
        if filter_ip:
            filters.append(f"host {filter_ip}")

        # Port filter
        if filter_port:
            filters.append(f"port {filter_port}")

            
        # Combine filters into a single string
        filter_str = ' and '.join(filters)
        print(f"Using filter: {filter_str}")  # Debugging line to check filter
        sniff(prn=self.packet_handler, filter=filter_str, store=0)
        

        
    def table(self):
        total_ips = len(self.contact_ips)
        table = PrettyTable()
        table.field_names = ["Total IPs Contacted", "Protocols", "Duration", "Nr of Packets"]
        table.add_row([total_ips, "TBD", "TBD", "TBD"])  # Placeholder values for protocols, duration, and nr of packets
        print(self.contact_ips)
        print(table)

def main():
    s = Sniffer()
    s.banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--protocols", nargs='+', choices=['tcp', 'udp', 'icmp'],
                        help="shows only specified protocols (tcp, udp, icmp)", default=[])
    parser.add_argument("-d", "--direction", nargs='+', choices=['out', 'in'],
                        help="shows only the specified direction", default=[])
    #to implement#####################################
    parser.add_argument("-i", "--ip", help="filter by IP address")
    #to implement<###################################
    parser.add_argument("-t", "--port", type=int, help="filter by port number")
    
    
    args = parser.parse_args()
    s.start_sniffing(filter_protocols=args.protocols, filter_direction=args.direction, filter_ip=args.ip, filter_port=args.port)
    s.table()




if __name__ == '__main__':
    main()

'''
TO ADD

- ADD AN OPTION TO HAVE IT IN TABLE FORM FOR STATISTIC PURPOSES
- ADD PORTS TO TABLE
- ADD PROTOCOLS TO TABLE
- ADD DURATION TO TABLE
- MAKE TABLE STAY STILL
- SESSION RECOGNIZER AND COUNTER

'''
