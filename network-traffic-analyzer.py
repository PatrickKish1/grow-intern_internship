import scapy.all as scapy
from datetime import datetime
import threading
import keyboard
import asyncio
import aiohttp

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.packets = []
        self.running = False
        self.paused = False
        self.lock = threading.Lock()
        self.sniffer_thread = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.suspicious_ports = self.load_suspicious_ports()

    def load_suspicious_ports(self):
        return [
            20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443,
            445, 587, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443
        ]

    def packet_handler(self, packet):
        with self.lock:
            if not self.paused:
                self.packets.append(packet)
                self.loop.run_until_complete(self.analyze_packet(packet))

    async def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            packet_type = self.get_packet_type(packet)
            print(f"Packet: {ip_src} -> {ip_dst} | Type: {packet_type}")

            is_bad_ip, report_times = await self.check_ip_in_abuseipdb(ip_dst)

            if is_bad_ip:
                print(f"Bad IP {ip_dst}")
                print(f"This IP was reported {report_times} times.")
            else:
                print(f"{ip_dst} was not found in our database")

            if self.is_suspicious(packet, is_bad_ip):
                self.alert(ip_src, ip_dst)
            else:
                print(f"Packet from {ip_src} to {ip_dst} is not suspicious")
            
            print()  # Empty line before the next packet is analyzed

    def get_packet_type(self, packet):
        if packet.haslayer(scapy.TCP):
            return "TCP"
        elif packet.haslayer(scapy.UDP):
            return "UDP"
        elif packet.haslayer(scapy.ICMP):
            return "ICMP"
        else:
            return "Other"

    def is_suspicious(self, packet, is_bad_ip):
        if is_bad_ip:
            return True
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet.getlayer(scapy.TCP)
            if tcp_layer.flags == "S":  # SYN packet
                if tcp_layer.dport in self.suspicious_ports:
                    return True
            elif tcp_layer.flags == "FPU":
                return True
        if packet.haslayer(scapy.DNS):
            dns_layer = packet.getlayer(scapy.DNS)
            if dns_layer.qr == 0 and dns_layer.qdcount > 1:
                return True
        return False

    async def check_ip_in_abuseipdb(self, ip):
        url = f"https://www.abuseipdb.com/check/{ip}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    text = await response.text()
                    if f"{ip} was found in our database" in text:
                        report_times = self.extract_report_times(text)
                        return True, report_times
                    elif f"{ip} was not found in our database" in text:
                        return False, None
        except aiohttp.ClientConnectorError as e:
            print(f"Error connecting to AbuseIPDB: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
        return False, None

    def extract_report_times(self, response_text):
        try:
            start = response_text.find("This IP was reported") + len("This IP was reported ")
            end = response_text.find(" times.", start)
            report_times = response_text[start:end]
            return report_times
        except Exception as e:
            return "unknown"

    def alert(self, src, dst):
        print(f"Alert! Suspicious activity detected from {src} to {dst} at {datetime.now()}")

    def start(self):
        self.running = True
        self.paused = False
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()
        print("Network traffic analyzer started...")

    def sniff_packets(self):
        scapy.sniff(prn=self.packet_handler, stop_filter=self.should_stop)

    def should_stop(self, packet):
        return not self.running

    def pause(self):
        with self.lock:
            self.paused = True
        print("Network traffic analyzer paused...")

    def resume(self):
        with self.lock:
            self.paused = False
        print("Network traffic analyzer resumed...")

    def stop(self):
        self.running = False
        if self.sniffer_thread is not None:
            self.sniffer_thread.join()
        print("Network traffic analyzer stopped...")

def main_menu():
    analyzer = NetworkTrafficAnalyzer()
    
    while True:
        print("\nWelcome to the Network Traffic Analyzer")
        print("Options:")
        print("1. Start Analysis")
        print("2. Quit")
        print("Press 'p' to pause, 'r' to resume, and 'q' to stop the analysis and return to the main menu.")
        
        choice = input("Enter your choice: ")
        if choice == '1':
            analyzer.start()
            # Register hotkeys
            keyboard.add_hotkey('p', analyzer.pause)
            keyboard.add_hotkey('r', analyzer.resume)
            keyboard.add_hotkey('q', lambda: stop_and_return_to_menu(analyzer))
            while analyzer.running:
                pass
        elif choice == '2':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1 to start analysis or 2 to quit.")

def stop_and_return_to_menu(analyzer):
    analyzer.stop()

if __name__ == "__main__":
    main_menu()
