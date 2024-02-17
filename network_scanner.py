from scapy.all import ARP, Ether, srp
from colorama import Fore, Style, init
init()
logo = (f"{Fore.CYAN} ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ \n"
        f"░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     \n"
        f"░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     \n"
        f"░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     \n"
        f"░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     \n"
        f"░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     \n"
        f"░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░     {Style.RESET_ALL}")

def scan_network(subnet):
    try:
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request = broadcast/ARP(pdst=subnet)
        answered, unanswered = srp(arp_request, timeout=2, retry=10, verbose=False)

        devices = []
        for sent, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("\nAvailable devices in the network:")
        print("IP" + " "*18 + "MAC")
        for device in devices:
            print(f"{device['ip']}  {device['mac']}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    print(logo)
    print(f"{Fore.CYAN}NETWORK SCANNER{Style.RESET_ALL}")
    target_subnet = input("\nEnter the subnet to scan (e.g., 192.168.1.0/24):\n")
    scan_network(target_subnet)
