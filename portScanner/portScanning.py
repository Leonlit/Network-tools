import re, concurrent.futures, sys, os, time, subprocess, platform
from datetime import datetime, timedelta
from itertools import repeat

import modules.scan_types as scan_types
import modules.get_ports as get_ports

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

# used to check if the machine is online or not using ping
def device_online(ip):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    command = ['ping', param, '1', "-4" , ip]
    try:
        result = subprocess.call(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )

    except Exception:
        print(f"Could not PING {ip}")
        return False
    if (result == 0):
        print(f"\nPing operation for [{ip}] is sucessful, target is online")
        return True
    else:
        print(f"\nPing operation failed, the target might be offline or rejected connection from your device")
        print("Or there's no device that's using this IP address currently\n\n")
        return False

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
            device_online(ip)
            return ip
        print("Invalid IP address, please try again")
        print("Example of valid address are, 192.158.0.0\n")

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


def display_result(fileName):
    print("\n\n")
    with open(fileName) as file:
        print(file.read())

# ip - string value of ip
# opens, filtered:
#       - array
#           0 - port number
#           1 - service name
# scanRange 
#       - integer array
#           0 - min range
#           1 - max range
# startTime - start time of the operations
# timeTaken - time taken by the operations

def save_result(ip, opens, filtered, scanRange, startTime, timeTaken):
    directory = os.path.join(os.getcwd(), RESULT_DIRECTORY)
    directoryExists = make_directory(directory)
    if directoryExists:
        range = str(scanRange[0]) + "-" + str(scanRange[1] - 1)
        if abs(scanRange[1] - scanRange[0]) == 1:
            range = str(scanRange[0])
        
        timeTakenFormatted = formatTime(str(timedelta(seconds=timeTaken)))
        startTimeFormatted = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime(startTime))
        fileName = os.path.join(directory, f"{ip}_{range}_{str(startTimeFormatted[:10])}.txt")
        try:
            with open(fileName, "w+") as file:
                file.write("Scan result for IP: " + ip +"\n")
                file.write("Time of scan: " + startTimeFormatted + "\n")
                file.write("Scan Range: " + range + "\n")
                file.write(f"Time taken: {timeTakenFormatted} \n")
                file.write(f"Number of available ports: ({len(opens) + len(filtered)})\n")
                if len(opens) == len(filtered) == 0:
                    file.write("\n Nothing to be shown\n")

                if len(opens) != 0:
                    file.write("\n\nOpen ports:\n")
                    for index, [port, service] in enumerate(opens):
                        file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")
                
                if len(filtered) != 0:
                    file.write("\n\nFiltered ports:\n")
                    for index, [port, service] in enumerate(filtered):
                        file.write(str(index + 1) + ". \t" + str(port) + "\t(" + service + ")" +"\n")

                file.close()
                print(f"\nSaved scan result into:\n {fileName}")
                display_result(fileName)
        except Exception as ex:
            print("Failed to write results into file specified")
            if hasattr(ex, 'message'):
                print(ex.message)
            else:
                print(ex)


# ip - ip in string form
# ports - port range in array: [min, max]
def scan_ports(ip, ports, scan_type):
    global target_ip
    target_ip = ip
    openPorts = []
    filteredPorts = []

    start_time = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for result in executor.map(scan_type, range(ports[0], ports[1]), repeat(target_ip)):
                flag = result[0]
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if flag == 2:
                    print(f"[{timestamp}] -> Port {str(result[1])} is open ({str(result[2])})")
                    openPorts.append([result[1], result[2]])
                elif flag == 3:
                    print(f"[{timestamp}] -> Port {str(result[1])} is filtered ({str(result[2])})")
                    filteredPorts.append([result[1], result[2]])
        
        save_result(ip, openPorts, filteredPorts, ports, start_time, (time.time() - start_time))
    except Exception as ex:
        print("Can't scan the port using scapy")
        if hasattr(ex, 'message'):
            print(ex.message)
        else:
            print(ex)
    

def main():
    banner()
    ip = get_ip_address()
    scan_type = scan_types.get_scan_type()
    ports = get_ports.get_ports()
    scan_ports(ip, ports, scan_type)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted, exiting program.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

