import sys, subprocess, nmap, pymongo, ipaddress
from datetime import date
from collections import defaultdict
import pyinputplus as pyip

# Easy script that scans network blocks, formats results to a MongoDB.

ip_list = []
client = pymongo.MongoClient("INSERT MONGODB HERE")
db = client.scan

def scan(network):
    try:
        nm = nmap.PortScanner()
        args = f'-sV -T4 --script vulners.nse'


        # Scan top ports. User vulners.nse script to include CVE vulners data
        print(f"Scanning {network}")
        s = nm.scan(hosts=network, arguments=args)
        print("Scan was successful!")
        print("Writing to database...")

        mongo_dict = dict()

        for item in s['scan']:
            mongo_dict['ip'] = item
            mongo_dict['hostname'] = s['scan'][item]['hostnames']
            mongo_dict['ip_status'] = s['scan'][item]['status']['state']
            mongo_dict['stat_reason'] = s['scan'][item]['status']['reason']
            mongo_dict['time'] = s['nmap']['scanstats']['timestr']
            mongo_dict['elapsed'] = s['nmap']['scanstats']['elapsed']

            if 'tcp' in s['scan'][item]:
                mongo_dict['tcp'] = dict() 

                for port in s['scan'][item]['tcp']:

                    mongo_dict['tcp'][port] = dict() 
                    mongo_dict['tcp'][port]['product'] = s['scan'][item]['tcp'][port]['product']
                    mongo_dict['tcp'][port]['version'] = s['scan'][item]['tcp'][port]['version']
                    mongo_dict['tcp'][port]['extrainfo'] = s['scan'][item]['tcp'][port]['extrainfo']
                    mongo_dict['tcp'][port]['status'] = s['scan'][item]['tcp'][port]['state']
                    mongo_dict['tcp'][port]['stat_reason'] = s['scan'][item]['tcp'][port]['reason']
                    mongo_dict['tcp'][port]['service_name'] = s['scan'][item]['tcp'][port]['name']

                    if 'script' in s['scan'][item]['tcp'][port]:
                        modified = str(s['scan'][item]['tcp'][port]['script']).replace('\\t', '********')
                        modified = modified.replace('\\n', '\n')
                        mongo_dict['tcp'][port]['vulners'] = modified

            if 'udp' in s['scan'][item]:
                mongo_dict['udp'] = dict() 

                for port in s['scan'][item]['udp']:

                    mongo_dict['udp'][port] = dict() 
                    mongo_dict['udp'][port]['product'] = s['scan'][item]['tcp'][port]['product']
                    mongo_dict['udp'][port]['version'] = s['scan'][item]['tcp'][port]['version']
                    mongo_dict['udp'][port]['extrainfo'] = s['scan'][item]['tcp'][port]['extrainfo']
                    mongo_dict['udp'][port]['status'] = s['scan'][item]['tcp'][port]['state']
                    mongo_dict['udp'][port]['stat_reason'] = s['scan'][item]['tcp'][port]['reason']
                    mongo_dict['udp'][port]['service_name'] = s['scan'][item]['tcp'][port]['name']

                        
            print(mongo_dict)

            data = {
                'ip': mongo_dict['ip'],
                'hostname': mongo_dict['hostname'],
                'ip_status': mongo_dict['ip_status'],
                'stat_reason': mongo_dict['stat_reason'],
                'time': mongo_dict['time'],
                'elapsed': mongo_dict['elapsed'],
                'tcp': {
                    '#': mongo_dict['tcp'][port],
                    'product': mongo_dict['tcp'][port]['product'],
                    'version': mongo_dict['tcp'][port]['version']
                }
            }

#  CONTINUE CREATING DATA ^^^^^   #

            db.posts.update_one({'ip':mongo_dict['ip']}, {"$set":data}, upsert=True)


    except KeyboardInterrupt:
        print(f"Keyboard interrupt detected. Storing scan to continue later.")
        with open("last_session", "w") as w:
            w.writelines(ip_list)

if __name__ == "__main__":

    scan_option = pyip.inputMenu(prompt="Please choose a scan type: \n",
                choices=["INTERNAL_CORE", "INTERNAL_ALT", "EXTERNAL", "VLAN1", "VLAN2", "PRINTERS", "CONTINUE"], numbered=True)

    if scan_option == "CONTINUE":
        with open("last_session", "r") as f: 
            ip_list = f.read().splitlines()

    else: 
        with open(scan_option, "r", newline='\n') as f:
            ip_list = f.read().splitlines()

    for ip in ip_list:
        if ip[-3:].find("/") != -1:
            i = ipaddress.ip_network(ip).hosts()
            for x in i:
                scan(str(x))
