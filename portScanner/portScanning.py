from ast import parse
import sys, os, argparse
import modules.scan_types as scan_types
import modules.get_ports as get_ports
import modules.utils as utils
from argparse import RawTextHelpFormatter

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
    print("║| ╚╝                                                               ╚╝   |║")
    print("║|═══════════════════════════════════════════════════════════════════════|║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print("")
    print(" Welcome user, this is a simple tools for you to scan for an open port for an IP address.")
    print(" This tool will also show you the type of service that's provided by the port")
    print(" As well as the ports that block or drop packets")
    print("")
    print("You can quit the program by inserting 'exit' and press the 'ctrl + c' button to interupt the program")
    print("")


def main():
    

    port_type_help = '''Which port option to scan\n
 1. x-y to scan from port x until y (including x and y).
 2. x to scan from port 0 to x.
 3. x to scan only port x
 4. Scan common ports (0 - 1023 ports) [default]
    '''

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--interactive', nargs='?', type=int, help="Enable interactive mode.")
    group.add_argument('-ip', '--ip-address', nargs='?', type=str, help="Specify the ip address to scan ports.\n")
    parser.add_argument('-s', '--scan-type', nargs='?', type=int, default=1, help="Select the type of scan to use\n 1. TCP scan\n 2. SYN scan\n 3. XMAS scan\n 4. FIN scan\n 5. NULL scan\n Default: TCP scan.\n")
    parser.add_argument('-t', '--threads', nargs='?', type=int, default=3, help="Number of threads to use in scanning the device(s).\n Default: 3 workers\n")
    parser.add_argument('-p', '--port', nargs='?', type=int, default=4, help=port_type_help)
    args = parser.parse_args()

    if args.interactive is not None:
        banner()
        ip = utils.get_ip_address()
        scan_type = scan_types.get_scan_type()
        ports = get_ports.get_ports()
        workers_num = utils.get_workers_num()
        utils.scan_ports(ip, ports, scan_type, workers_num)
    else:
        if args.ip_address is not None:
            banner()
            utils.scan_ports(args.ip_address, get_ports.parse_port_option(args.port), scan_types.parse_scan_type(args.scan_type), args.threads)
        else:
            print("\nError: Not enabling Interactive mode (-i), -ip/--ip-address option is required!!!\n")
            parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted, exiting program.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

