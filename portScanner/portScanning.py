import socket, re, concurrent.futures, sys, os, time, struct

''' todo 
    - finding blocked/filtered port [x]
    - find the service that's for that port [x]
    - save result into file [x]
    - get OS detail

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.6)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1,0))
            result = s.connect_ex((target_ip, port))    # targe_ip is a global variable
            serv = socket.getservbyport(port, "tcp")
            if result == 0:
                return [True, port, serv]
            elif result == 110:
                return [2, port, serv]
            elif result == 111:
                return [3, port, serv]
    except Exception as e:
        if type(e) == socket.timeout:
            serv = socket.getservbyport(port, "tcp")
            return [2, port, serv]
        else:
            print("Error Occured when connecting to port using socket!")
    return [False]
    

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


# ip - string value of ip
# items - array
#           0 - port number
#           1 - service name
def save_result(ip, opens, filtered, scanRange, timeTaken):
    directory = os.path.join(os.getcwd(), RESULT_DIRECTORY)
    print(directory)
    directoryExists = make_directory(directory)
    if directoryExists:
        fileName = os.path.join(directory, ip + ".txt")
        print(fileName)
        try:
            with open(fileName, "w+") as file:
                file.write("Scan result for IP: " + ip + "\n")
                file.write("Time of scan: " + time.ctime() + "\n")
                file.write("Scan Range: " + str(scanRange[0]) + " - " + str(scanRange[1]) + "\n")
                file.write(f"Time taken: {timeTaken:.2f}")
                file.write("\n\nOpen ports:\n")
                for index, [port, service] in enumerate(opens):
                    file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")
                if len(filtered) != 0:
                    file.write("\n\nFiltered ports:\n")
                    for index, [port, service] in enumerate(filtered):
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

    start_time = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for result in executor.map(connect_port, range(ports[0], ports[1])):
                print(result[0])
                if result[0] is True:
                    print("The port " + str(result[1]) + " is open (" + str(result[2]) + ")")
                    openPorts.append([result[1], result[2]])
                elif result[0] == 2:
                    print("The port " + str(result[1]) + " is closed (" + str(result[2]) + ")")
                elif result[0] == 3:
                    print("The port " + str(result[1]) + " is filtered (" + str(result[2]) + ")")
        save_result(ip, openPorts, filteredPorts, ports, (time.time() - start_time))
    except Exception as ex:
        print("Can't scan the ports using socket")
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

