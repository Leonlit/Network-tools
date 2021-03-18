#!/usr/bin/python
# -*- coding: utf-8 -*-

import scapy.all as scapy
import ipaddress, os, sys, re, requests
from time import sleep as sleep

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
    print("║|_╚╝_______________________________________________________________╚╝___|║")
    print("╚═════════════════════════════════════════════════════════════════════════╝")
    print("")
    print(" Welcome user, this is a simple tools to detect the devices on your network.")
    print(" This tool will show the scanned device's private IP, MAC address, and the vendor")
    print(" who manufactured the interface card for the device")
    print("")


def isIPValid (ip):
    try:
        ipaddress.ip_network(ip)
        return True
    except ValueError:
        return False

def getRequestData(url):
    try:
        response = requests.get(url)
        statsCode = response.status_code
        if (statsCode == 200):
            jsonData = response.json()
            return jsonData
        else:
            print(f"Warning: Request returned request code: {statsCode}")
    except requests.exceptions.HTTPError as e:
        print(f"Error when requesting data from API server for url {url}. {str(e)}")

def extractMacAddressesFromString(string):
    try:
        pattern = re.compile(r'(?:[0-9a-fA-F]:?){12}')
        return re.findall(pattern, string)[0]
    except Exception as ex:
        return False # means not a mac address

def extractIPAddressFromString(string):
    return re.findall( r'[0-9]+(?:\.[0-9]+){3}', string)[0]

def getMacAddresssInfo(mac):
    url = f"https://api.maclookup.app/v2/macs/{mac}"
    jsonData = getRequestData(url)
    company = jsonData["company"]
    country = jsonData["country"]
    return f"{company}({country})"

def addInfoIntoResult(filename, fileContent):
    for index, line in enumerate(fileContent):
        if line[0] == "\n":
            continue
        mac = extractMacAddressesFromString(line)
        if mac:
            ip = extractIPAddressFromString(line)
            macVendor = getMacAddresssInfo(mac)
            finalChange = f"  {mac} {macVendor} {ip}\n"
            fileContent[index] = finalChange
            sleep(1)
    try:
        fileObj = open(filename, "w+")
        for line in fileContent:
            fileObj.write(line)
        fileObj.close()
    except IOError as ex:
        print(f"Could not update MAC address info for {filename}")
    return fileContent

def readFromFile(filename):
    print("") # to separate file content from the previous line
    try:
        with open(filename) as reader:
            content = reader.readlines()
        return content
    except IOError as ex:
        print(f"Could not read file content at {filename}\n\n {str(ex)}")

def printFromFileContent(content):
    for line in content:
        print(line.replace("\n", ""))

def scanNetwork(ipRange):
    filename = ipRange.split("/")
    filename = f"{filename[0]}-{filename[1]}.txt"
    filepath = os.path.join(os.getcwd(), filename)

    try:
        fileObj = open(filepath, "w+")
        sys.stdout = fileObj
        scans = scapy.arping(ipRange)
    except Exception as ex:
        print(ex)
        print(f"\nCould not scan the network: {ipRange}")
        print("Please re-run the program.\n")
        exit()
    finally:
        sys.stdout = sys.__stdout__
        fileObj.close()
        fileContent = readFromFile(filename)
        if fileContent:
            updatedContent = addInfoIntoResult(filepath, fileContent)
            for line in updatedContent:
                print(line)
            print(f"Updated content for {filename} with additional MAC address info")
            print(f"\nSaved scan result for {ipRange} into {filename}")
            print(f"Full path: {filepath}")
        else:
            print(f"Could not get content from {filepath}")
            exit()

def main():
    banner()
    while (True):
        ip = input("Please enter the IP range to scan: ")
        ipValid = isIPValid(ip)
        if ipValid:
            scanNetwork(ip)
            break
        else:
            print("Invalid IP address range, please try again")
            print("Example of valid address are, 192.158.0.125/24\n")
            continue

if __name__ == "__main__":
    main()



