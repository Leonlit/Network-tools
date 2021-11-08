from scapy.all import sr1, sr, IP, TCP, RandShort, ICMP
import socket, sys


# port - port number in integer form
# return: array
#            type:
#               # False - closed
#               # 2 - open
#            1 - port, integer number of port
#            2 - serv, service name of the port is providing
def tcp_scan_port(port, target_ip):
    src_port = RandShort()
    try:
        pkt = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                serv = socket.getservbyport(port, "tcp")
                if pkt[TCP].flags == 20:    # port closed
                    return [False]
                elif pkt[TCP].flags == 18: # port open
                    send_rst = sr1(IP(dst=target_ip)/TCP(sport=src_port,dport=port,flags="AR"),timeout=3, verbose=0)
                    return [2, port, serv]
            else: # unknown response
                print(pkt.summary()) 
                return [False]
        else:
            return [False]
    except:
        return [False]

# port - port number in integer form
# return: array
#            type:
#               # False - closed
#               # 2 - open
#               # 3 - filtered
#            1 - port, integer number of port
#            2 - serv, service name of the port is providing
def stealth_scan_port(port, target_ip):
    src_port = RandShort()
    try:
        pkt = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                serv = socket.getservbyport(port, "tcp")
                if pkt[TCP].flags == 20:    # port closed
                    return [False]
                elif pkt[TCP].flags == 18: # port open
                    send_rst = sr1(IP(dst=target_ip)/TCP(sport=src_port,dport=port,flags="R"),timeout=3, verbose=0)
                    return [2, port, serv]
                elif (int(pkt.getlayer(ICMP).type)==3 and int(pkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return [3, port, serv]
            else: # unknown response
                print(pkt.summary()) 
                return [False]
        else:
            return [False]
    except:
        return [False]

# port - port number in integer form
# return: array
#            type:
#               # False - closed
#               # 2 - open
#               # 3 - filtered
#               # 4 - open | filtered
#            1 - port, integer number of port
#            2 - serv, service name of the port is providing
def xmas_scan_port(port, target_ip):
    src_port = RandShort()
    try:
        pkt = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="FPU"), timeout=2, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                serv = socket.getservbyport(port, "tcp")
                if pkt[TCP].flags == 20:    # port closed
                    return [False]
                elif (int(pkt.getlayer(ICMP).type)==3 and int(pkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    return [3, port, serv]
            else: # unknown response
                print(pkt.summary()) 
                return [False]
        else:
            serv = socket.getservbyport(port, "tcp")
            return [4, port, serv]
    except:
        return [False]

def get_scan_type():
    thismodule = sys.modules[__name__]
    while True:
        print("\nPlease choose which scan to perform onto the target")
        print(" 1. TCP scan")
        print(" 2. SYN scan")
        print(" 3. XMAS scan")
        print(" 4. FIN scan")
        print(" 4. NULL scan")
        print("")
        option = input ("Please choose one of them: ")
        option = option.replace(" ", "")
        if option !="" and isinstance(int(option), int):
            option = int(option)
            if (0 < int(option) < 5):
                if option == 1:
                    return getattr(thismodule, 'tcp_scan_port')
                elif option == 2:
                    return getattr(thismodule, 'stealth_scan_port')
                elif option == 3:
                    return getattr(thismodule, 'xmas_scan_port')
                elif option == 4:
                    return [0, 1024]
        print("Invalid option, please try again!")