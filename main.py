#!/usr/bin/env python
# coding: utf8

import asyncio
import datetime
import json
import os
import subprocess
import time
from sys import platform
from requests import get
from colorama import Fore, init

with open('settings.json', 'r') as settings:
    settings = json.load(settings)

async def clear():
    os.system("clear")

async def event(message):
    # python gradiant.py banner.txt 73,204,255 white > output.txt
    print("   " + Fore.LIGHTWHITE_EX + datetime.datetime.now().strftime("%H:%M:%S") + " │ [38;2;73;204;255m[[38;2;99;211;255mE[38;2;125;218;255mV[38;2;151;225;255mE[38;2;177;232;255mN[38;2;203;239;255mT[38;2;229;246;255m][0;00m" + Fore.LIGHTWHITE_EX + " | " + message)

async def detection(message):
    # python gradiant.py banner.txt 255,52,52 white > output.txt
    print("   " + Fore.LIGHTWHITE_EX + datetime.datetime.now().strftime("%H:%M:%S") + " │ [38;2;255;52;52m[[38;2;255;70;70mD[38;2;255;88;88mE[38;2;255;106;106mT[38;2;255;124;124mE[38;2;255;142;142mC[38;2;255;160;160mT[38;2;255;178;178mI[38;2;255;196;196mO[38;2;255;214;214mN[38;2;255;232;232m][0;00m" + Fore.LIGHTWHITE_EX + " | " + message)

async def action(message):
    # python gradiant.py banner.txt 255,253,52 white > output.txt
    print("   " + Fore.LIGHTWHITE_EX + datetime.datetime.now().strftime("%H:%M:%S") + " │ [38;2;255;253;52m[[38;2;255;253;77mA[38;2;255;253;102mC[38;2;255;253;127mT[38;2;255;253;152mI[38;2;255;253;177mO[38;2;255;253;202mN[38;2;255;253;227m][0;00m" + Fore.LIGHTWHITE_EX + " | " + message)


async def main():
    # check if dump file exist
    if os.path.isdir(settings['directory']):
        pass
    else:
        directory_choice = input("Specified dump directory could not be found, would you like to create the directory? [Y | N]: ")
        if directory_choice.lower() == "y":
            print(f"{Fore.LIGHTGREEN_EX}Creating the directory")
            await asyncio.sleep(1)
            try:
                os.system("mkdir -p " + settings['directory'])
            except Exception as e:
                print(f"Could not create directory: {e}")
                await asyncio.sleep(1)
                exit(0)
        else:
            print(f"\n {Fore.LIGHTRED_EX}Goodbye. \n")
            await asyncio.sleep(1)
            exit(0)

    await clear()
    print(f"""
        [38;2;73;204;255m│ [38;2;73;204;255mC[38;2;99;211;255ma[38;2;125;218;255mp[38;2;151;225;255mt[38;2;177;232;255mu[38;2;203;239;255mr[38;2;229;246;255me[0;00m
        [38;2;103;212;255m│
        [38;2;133;220;255m│  {Fore.WHITE}Efficiently capture DDoS attacks in real-time.
        [38;2;193;236;255m│  {Fore.WHITE}Developers, Flairings.
""")
    await listen()

checks = 0
async def listen():
    global checks
    try:
        ip = get('https://api.ipify.org').text
        await event(f"Started traffic listener on {settings['interface']} : {ip}")
    except Exception:
        await event(f"Started traffic listener on {settings['interface']}")
    while True:
        pps_old = os.popen(f"grep {settings['interface']}: /proc/net/dev | cut -d :  -f2 | awk " + "'{ print $2 }'").read().replace("\n", "")
        time.sleep(1)
        pps_new = os.popen(f"grep {settings['interface']}: /proc/net/dev | cut -d :  -f2 | awk " + "'{ print $2 }'").read().replace("\n", "")

        pps = (int(pps_new)) - (int(pps_old))

        if pps > settings['threshold']:
            checks += 1
            if checks > settings['checks']:
                attack_detected = True
                await detected(pps)
                checks = 0
        else:
            pass

global file
fixed_time_date = f"{datetime.datetime.now().strftime('%H:%M:%S, %m/%d/%Y')}".replace(",", "-").replace("/", "-").replace(" ", "")
file = f"{settings['directory']}attack-{fixed_time_date}.pcap"

async def detected(pps):
    await asyncio.sleep(2)
    await detection(f"PPS Threshold reached [{pps}].")
    await action(f"Capturing all incoming traffic...")
    await capture()
    await asyncio.sleep(2)
    await event(f"Successfully captured possible attack to {file}")
    await action(f"Sleeping for {settings['sleep_time']} seconds.")
    print("\n")
    await asyncio.sleep(int(settings['sleep_time']))
    await event("Waiting for a new attack.")


async def capture():
    # switch to os.system
    process = subprocess.Popen(f"sudo tcpdump -i {settings['interface']} -t -w {file} -c {settings['dump_size']}", shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    out,err = process.communicate()
   # print(process)

if __name__ == '__main__':
    if platform == "linux" or platform == "linux2":
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        else:
            try:
                init()
                loop = asyncio.get_event_loop()
                loop.run_until_complete(main())
            except KeyboardInterrupt:
                print(f"{Fore.LIGHTRED_EX}\n Goodbye. \n")
    else:
        print("This script is developed for Linux operating systems only \nIf this is linux and you are seeing this message please create an issue at https://github.com/Flairings")
        time.sleep(5)
        exit(0)

# copyright, flairings.agency.
