import nmap
import socket
import time
import threading
import json
import netifaces

class Device:
    def __init__(self, ip, mac, hostname):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.vendor = "Unknown"
        self.os = "Unknown"
        self.last_seen = time.time()
        self.open_ports = []

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os": self.os,
            "last_seen": self.last_seen,
            "open_ports": self.open_ports
        }

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_local_networks():
    networks = []
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                if not ip.startswith('127.'):
                    netmask = addr['netmask']
                    network = f"{ip}/{sum([bin(int(x)).count('1') for x in netmask.split('.')])}"
                    networks.append(network)
    return networks

def scan_network(network, devices, lock):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    
    for host in nm.all_hosts():
        ip = nm[host]['addresses']['ipv4']
        hostname = get_hostname(ip)
        
        with lock:
            if 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses']['mac']
            else:
                mac = "Unknown"
            
            if ip not in devices:
                devices[ip] = Device(ip, mac, hostname)
            devices[ip].last_seen = time.time()
            
            # Get more information about the device
            try:
                nm.scan(ip, arguments='-O -sV --top-ports 100')
                if 'osmatch' in nm[ip]:
                    devices[ip].os = nm[ip]['osmatch'][0]['name']
                if 'vendor' in nm[ip]['addresses']:
                    devices[ip].vendor = nm[ip]['addresses']['vendor']
                devices[ip].open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
            except:
                pass

def continuous_scan(devices, lock):
    while True:
        networks = get_local_networks()
        threads = []
        for network in networks:
            thread = threading.Thread(target=scan_network, args=(network, devices, lock))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        
        # Remove devices not seen in the last 5 minutes
        current_time = time.time()
        with lock:
            devices = {ip: device for ip, device in devices.items() if current_time - device.last_seen <= 300}
        
        time.sleep(60)  # Wait for 1 minute before next scan

def print_devices(devices):
    print("\033[H\033[J")  # Clear screen
    print("Connected Devices:")
    print("-" * 80)
    for ip, device in devices.items():
        print(f"IP: {device.ip}")
        print(f"Hostname: {device.hostname}")
        print(f"MAC: {device.mac}")
        print(f"Vendor: {device.vendor}")
        print(f"OS: {device.os}")
        print(f"Open Ports: {', '.join(map(str, device.open_ports))}")
        print(f"Last Seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(device.last_seen))}")
        print("-" * 80)

def save_results(devices, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as jsonfile:
        json.dump({ip: device.to_dict() for ip, device in devices.items()}, jsonfile, indent=2)

def main():
    print("Scanning for connected devices...")
    devices = {}
    lock = threading.Lock()
    
    scan_thread = threading.Thread(target=continuous_scan, args=(devices, lock))
    scan_thread.daemon = True
    scan_thread.start()

    try:
        while True:
            with lock:
                print_devices(devices)
                save_results(devices, "connected_devices.json")
            time.sleep(10)  # Update display every 10 seconds
    except KeyboardInterrupt:
        print("\nScanning stopped by user.")

if __name__ == "__main__":
    main()

