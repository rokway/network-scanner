import socket
import subprocess
import ipaddress

def ping_sweep(network):
    # ping all devices in the given network range
    print(f"scan network {network}")
    active_devices = [] #to strore Ips of devices that respond to the ping
    for ip in ipaddress.IPv4Network(network, strict=False): #loop through all Ips in the network
        response = subprocess.run(['ping', '-n', '1', '-w', '500', str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0: # a return code of 0 means device responded
            active_devices.append(str(ip))
    return active_devices

def port_scan(ip, ports):
    # scan the given ports on the given ip
    print(f"scan ports {ports} on {ip}")
    open_ports = [] #to store open ports
    for port in ports: #loop through all ports
        try: 
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) #timeout after .5 seconds
                result = s.connect_ex((ip, port))
                print(f"Port {port}: {'Open' if result == 0 else 'Closed'}")  # Verbose output
                if result == 0:  # 0 means the port is open
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
    return open_ports   


if __name__ == "__main__":
    network_range = input("Enter the network range (e.g., 192.168.1.0/24): ")
    
    # Step 1: Ping sweep
    devices = ping_sweep(network_range)
    print("\nActive devices found:")
    for device in devices:
        print(f"- {device}")
    
    # Step 2: Port scan
    if devices:
        target_ip = input("\nEnter an IP to scan for open ports: ")
        ports_to_scan = range(20, 100) #change this to scan more ports or less
        open_ports = port_scan(target_ip, ports_to_scan)
        print("\nOpen ports:")
        for port in open_ports:
            print(f"- {port}")

    print("\nScan complete.")


