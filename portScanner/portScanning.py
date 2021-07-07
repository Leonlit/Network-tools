import socket, io, re, concurrent.futures,sys,os

''' todo 
    - finding blocked/filtered port
    - find the service that's for that port
    - save result into file

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

ip_regex = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_regex = re.compile("([0-9]+)-([0-9]+)")
portLimits = [0, 65535]
target_ip = ""

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

def is_ip_valid(ip):
    valid = ip_regex.search(ip)
    return valid

def is_port_valid(port):
    valid = port_regex.search(port)
    return valid

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

def get_port_range():
    while True:
        print("Please enter the range of ports you want to scan in separated by dash, 1000-1200 (Between " + str(portLimits[0]) + " and " + str(portLimits[1]) + ")")
        ports = input("Enter the port range that you want to scan: ")
        ports_valid = port_regex.search(ports.replace(" ",""))
        if ports_valid:
            return [int(ports_valid.group(1)), int(ports_valid.group(2)) + 1]
        print("Invalid port range, please try again!")

def get_max_port():
    while True:
        print("Please enter the port that you want the program to scan to from 0 (zero), example: 22 (max is " + str(portLimits[1]) + ")")
        ports = input("Enter the port to scan until: ")
        ports = ports.replace(" ","")
        if ports is not "" and isinstance(int(ports), int):
            ports = int(ports)
            ports_valid = int(ports) in range(portLimits[0], portLimits[1] + 1)
            if ports_valid:
                return [0, int(ports) + 1]
            print("Invalid port number, please try again!")

def get_single_port():
    while True:
        print("Please enter a single port that you want the program to scan (inclusion), example: 22 (choose between " + str(portLimits[0]) + " is " + str(portLimits[1]) + ")")
        port = input("Enter the port that you want to scan: ")
        port = port.replace(" ", "")
        if port is not "" and isinstance(int(port), int):
            port = int(port)
            port_valid = int(port) in range(portLimits[0], portLimits[1])
            if port_valid:
                return [int(port), int(port) + 1]
        print("Invalid port number, please try again!")

def get_ports():
    while True:
        print("Please choose an option for the type of port to be scanned")
        print(" 1. Port range")
        print(" 2. Enter one port and scan from 0 to it")
        print(" 3. Scan single port")
        print("")
        option = input ("Please choose one of them: ")
        option = option.replace(" ", "")
        if option is not "" and isinstance(int(option), int):
            option = int(option)
            if (0 < int(option) < 4):
                if option == 1:
                    return get_port_range()
                elif option == 2:
                    return get_max_port()
                else:
                    return get_single_port()
        print("Invalid option, please try again!")

def connect_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.6)
            s.connect((target_ip, port))
            return [True, port]
    except:
        return [False, port]

def print_open_ports (status):
    if status[0] is True:
        print("The port " + str(status[1]) + " is open")

def scan_ports(ip, ports):
    global target_ip
    target_ip = ip
    # portStatus = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for result in executor.map(connect_port, range(ports[0], ports[1])):
            print_open_ports(result)

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

