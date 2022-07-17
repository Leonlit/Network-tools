import re

PORT_REGEX = re.compile("([0-9]+)-([0-9]+)")
PORT_LIMITS = [0, 65535]

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_port_range():
    while True:
        print("Please enter the range of ports you want to scan in separated by dash, 1000-1200 (Between " + str(PORT_LIMITS[0]) + " and " + str(PORT_LIMITS[1]) + ")")
        try:
            ports = input("Enter the port range that you want to scan: ")
            ports_valid = PORT_REGEX.search(ports.replace(" ",""))
            if ports_valid:
                portRange = ports.split("-")
                if portRange[0] > portRange[1]:
                    print("The minimum port can't be higher than maximum port number!")
                return [int(ports_valid.group(1)), int(ports_valid.group(2)) + 1]
        except Exception as ex:
            print(ex.message)
        print("Invalid port number, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_max_port():
    while True:
        print("Please enter the port that you want the program to scan to from 0 (zero), example: 22 (max is " + str(PORT_LIMITS[1]) + ")")
        try:
            ports = input("Enter the port to scan until: ")
            ports = ports.replace(" ","")
            if ports != "" and isinstance(int(ports), int):
                ports = int(ports)
                ports_valid = int(ports) in range(PORT_LIMITS[0], PORT_LIMITS[1] + 1)
                if ports_valid:
                    return [0, int(ports) + 1]
        except Exception as ex:
            print(ex.message)
        print("Invalid port number, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_single_port():
    while True:
        print("Please enter a single port that you want the program to scan, example: 22 (choose between " + str(PORT_LIMITS[0]) + " is " + str(PORT_LIMITS[1]) + ")")
        try:
            port = input("Enter the port that you want to scan: ")
            print("\n")
            port = port.replace(" ", "")
            if port !="" and isinstance(int(port), int):
                port = int(port)
                port_valid = int(port) in range(PORT_LIMITS[0], PORT_LIMITS[1])
                if port_valid:
                    return [int(port), int(port) + 1]
        except Exception as ex:
            print(ex.message)
        print("Invalid port number, please try again!")

# return - port range in array
#           0 - minimum port number
#           1 - maximum port number to scan (plus 1 as later on I'll use the range function for loops)
def get_ports():
    while True:
        print("\nPlease choose an option for the type of port to be scanned")
        print(" 1. Port range")
        print(" 2. Enter one port and scan from 0 to it")
        print(" 3. Scan single port")
        print(" 4. Scan common ports (0 - 1023 ports)")
        print("")
        option = input ("Please choose one of them: ")
        option = option.replace(" ", "")
        if option !="" and isinstance(int(option), int):
            option = int(option)
            if (0 < int(option) < 5):
                if option == 1:
                    return get_port_range()
                elif option == 2:
                    return get_max_port()
                elif option == 3:
                    return get_single_port()
                elif option == 4:
                    return [1, 1024]
        print("Invalid option, please try again!")
