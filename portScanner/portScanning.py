import socket, re, concurrent.futures, sys, os, time
from datetime import datetime, timedelta
from scapy.all import sr1, IP, ICMP, TCP, RandShort

''' todo 
    - finding blocked/filtered port [x]
    - find the service that's for that port [x]
    - save result into file [x]
    - get OS detail
    - check if the machine is reachable
    - support scan for common ports in get port options
    - print result file content after finish

'''

'''
Copyright © 2021 LeonLit

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
documentation files (the “Software”), to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

IP_REGEX = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
PORT_REGEX = re.compile("([0-9]+)-([0-9]+)")
PORT_LIMITS = [0, 65535]
target_ip = ""
RESULT_DIRECTORY = "results"

def banner():
    print("")
    print("╔═════════════════════════════════════════════════════════════════════════╗")
    print("║|═══════════════════════════════════════════════════════════════════════|║")
    print("║| ╔╗                                                               ╔╗   |║")
    print("║| ╚╝     ██╗     ███████╗ ██████╗ ███╗   ██╗██╗     ██╗████████╗   ╚╝   |║")
    print("║|        ██║     ██╔════╝██╔═══██╗████╗  ██║██║     ██║╚══██╔══╝        |║")
    print("║|        ██║     █████╗  ██║   ██║██╔██╗ ██║██║     ██║   ██║           |║")
    print("║|        ██║     ██╔══╝  ██║   ██║██║╚██╗██║██║     ██║   ██║           |║")
    print("║|        ███████╗███████╗╚██████╔╝██║ ╚████║███████╗██║   ██║           |║")
    print("║| ╔╗     ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝      ╔╗   |║")
    print("║|_╚╝_______________________________________________________________╚╝___|║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print("")
    print(" Welcome user, this is a simple tools for you to scan for an open port for an IP address.")
    print(" This tool will also show you the type of service that's provided by the port")
    print(" As well as the ports that block or drop packets")
    print("")
    print("You can quit the program by inserting 'exit' and press the 'ctrl + c' button to interupt the program")
    print("")

# checks for valid IP address
def is_ip_valid(ip):
    valid = IP_REGEX.search(ip)
    return valid

# checks for the port number range 
def is_port_valid(port):
    valid = PORT_REGEX.search(port)
    return valid

# return the target ip to scan, in string form
def get_ip_address():
    while True:
        ip = input("Please enter an IP to scan its open ports: ")
        if ip == "exit":
            print("Exiting program")
            exit()
        ip = ip.replace(" ", "")
        ipValid = is_ip_valid(ip)
        if ipValid:
            return ip
        print("Invalid IP address, please try again")
        print("Example of valid address are, 192.158.0.0\n")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_port_range():
    while True:
        print("Please enter the range of ports you want to scan in separated by dash, 1000-1200 (Between " + str(PORT_LIMITS[0]) + " and " + str(PORT_LIMITS[1]) + ")")
        ports = input("Enter the port range that you want to scan: ")
        ports_valid = PORT_REGEX.search(ports.replace(" ",""))
        if ports_valid:
            portRange = ports.split("-")
            if portRange[0] > portRange[1]:
                print("The minimum port can't be higher than maximum port number!")
            return [int(ports_valid.group(1)), int(ports_valid.group(2)) + 1]
        print("Invalid port range, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_max_port():
    while True:
        print("Please enter the port that you want the program to scan to from 0 (zero), example: 22 (max is " + str(PORT_LIMITS[1]) + ")")
        ports = input("Enter the port to scan until: ")
        ports = ports.replace(" ","")
        if ports != "" and isinstance(int(ports), int):
            ports = int(ports)
            ports_valid = int(ports) in range(PORT_LIMITS[0], PORT_LIMITS[1] + 1)
            if ports_valid:
                return [0, int(ports) + 1]
            print("Invalid port number, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_single_port():
    while True:
        print("Please enter a single port that you want the program to scan (inclusion), example: 22 (choose between " + str(PORT_LIMITS[0]) + " is " + str(PORT_LIMITS[1]) + ")")
        port = input("Enter the port that you want to scan: ")
        port = port.replace(" ", "")
        if port !="" and isinstance(int(port), int):
            port = int(port)
            port_valid = int(port) in range(PORT_LIMITS[0], PORT_LIMITS[1])
            if port_valid:
                return [int(port), int(port) + 1]
        print("Invalid port number, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_ports():
    while True:
        print("Please choose an option for the type of port to be scanned")
        print(" 1. Port range")
        print(" 2. Enter one port and scan from 0 to it")
        print(" 3. Scan single port")
        print("")
        option = input ("Please choose one of them: ")
        option = option.replace(" ", "")
        if option !="" and isinstance(int(option), int):
            option = int(option)
            if (0 < int(option) < 4):
                if option == 1:
                    return get_port_range()
                elif option == 2:
                    return get_max_port()
                else:
                    return get_single_port()
        print("Invalid option, please try again!")

# port - port number in integer form
# return: array
#            0 - boolean, if the port is open can be connected or not
#            1 - port, integer number of port
#            2 - serv, service name of the port is providing
def connect_port(port):
    try:
        pkt = sr1(IP(dst=target_ip)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                serv = socket.getservbyport(port, "tcp")
                if pkt[TCP].flags == 20:    # port closed
                    return [False]
                elif pkt[TCP].flags == 18: # port open
                    return [2, port, serv]
            elif pkt.haslayer(ICMP):
                return [4, port]
            else: # unknown response
                print(pkt.summary()) 
                return [False]
        else:
            serv = socket.getservbyport(port, "tcp")
            return [3, port, serv]
    except:
        return [False]

# making sure that the result directory exists
# return true or false to indicate the directory existence 
# parameter:
#           directory = path to the directory
def make_directory(directory):
    isExists = os.path.isdir(directory)
    try:
        if not isExists:
            print("Result directory not found, creating one using the configuration set (upper part of the file)")
            os.mkdir(directory)
        return True
    except Exception as ex:
        print("Error! Can't create directory to save results!")
        if hasattr(ex, 'message'):
            print(ex.message)
        else:
            print(ex)
    return False

def formatTime(time):
    separated = time.split(".")
    separated[1] = separated[1][:4]
    return ".".join(separated)

# ip - string value of ip
# opens, filtered, icmp:
#       - array
#           0 - port number
#           1 - service name
# scanRange 
#       - integer array
#           0 - min range
#           1 - max range
# startTime - start time of the operations
# timeTaken - time taken by the operations

def save_result(ip, opens, filtered, icmp, scanRange, startTime, timeTaken):
    directory = os.path.join(os.getcwd(), RESULT_DIRECTORY)
    print(directory)
    directoryExists = make_directory(directory)
    if directoryExists:
        range = str(scanRange[0]) + "-" + str(scanRange[1] - 1)
        if abs(scanRange[1] - scanRange[0]) == 1:
            range = scanRange[0]
        
        timeTakenFormatted = formatTime(str(timedelta(seconds=timeTaken)))
        startTimeFormatted = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime(startTime))
        fileName = os.path.join(directory, f"{ip}_{range}_{str(startTimeFormatted[:10])}.txt")
        print(fileName)
        
        try:
            with open(fileName, "w+") as file:
                file.write("Scan result for IP: " + ip +"\n")
                file.write("Time of scan: " + startTimeFormatted + "\n")
                file.write("Scan Range: " + range + "\n")
                file.write(f"Time taken: {timeTakenFormatted}")
                file.write("\n\nOpen ports:\n")

                for index, [port, service] in enumerate(opens):
                    file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")
                
                if len(filtered) != 0:
                    file.write("\n\nFiltered ports:\n")
                    for index, [port, service] in enumerate(filtered):
                        file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")
                
                if len(icmp) != 0:
                    file.write("\n\nICMP responded:\n")
                    for index, [port, service] in enumerate(icmp):
                        file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")

                file.close()
        except Exception as ex:
            print("Failed to write results into file specified")
            if hasattr(ex, 'message'):
                print(ex.message)
            else:
                print(ex)


# ip - ip in string form
# ports - port range in array: [min, max]
def scan_ports(ip, ports):
    global target_ip
    target_ip = ip
    openPorts = []
    filteredPorts = []
    icmpResponse = []

    start_time = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for result in executor.map(connect_port, range(ports[0], ports[1])):
                flag = result[0]
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if flag == 2:
                    print(f"[{timestamp}] -> Port {str(result[1])} is open ({str(result[2])})")
                    openPorts.append([result[1], result[2]])
                elif flag == 3:
                    print(f"[{timestamp}] -> Port {str(result[1])} is filtered ({str(result[2])})")
                    filteredPorts.append([result[1], result[2]])
                elif flag == 4:
                    print(f"[{timestamp}] -> ICMP packet responded or filtered")
                    icmpResponse.append(result[1])
        save_result(ip, openPorts, filteredPorts, icmpResponse, ports, start_time, (time.time() - start_time))
    except Exception as ex:
        print("Can't scan the port using scapy")
        if hasattr(ex, 'message'):
            print(ex.message)
        else:
            print(ex)
    

def main():
    banner()
    ip = get_ip_address()
    ports = get_ports()
    scan_ports(ip, ports)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted, exiting program.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

