import sys, os, argparse
import modules.scan_types as scan_types
import modules.get_ports as get_ports
import modules.utils as utils

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
    '''
    banner()
    
    '''
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interactive', nargs='?', type=int, const=True)
    parser.add_argument('-ip', '--ip-address', nargs='?', type=str)
    parser.add_argument('-s', '--scan-type', nargs='?', type=int, default=1)
    parser.add_argument('-t', '--threads', nargs='?', type=int, default=3)
    parser.add_argument('-p', '--port', nargs='?', type=int, default=4)
    args = parser.parse_args()
    print(args)
    if args.interactive:
        ip = utils.get_ip_address()
        scan_type = scan_types.get_scan_type()
        ports = get_ports.get_ports()
        workers_num = utils.get_workers_num()
        utils.scan_ports(ip, ports, scan_type, workers_num)
    else:
        utils.scan_ports(args.ip, get_ports.parse_port_option(args.ports), scan_type, workers_num)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted, exiting program.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

