from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime
from collections import Counter

packet_count = 0
protocol_count = Counter()
results = []

def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    source = packet[IP].src
    destination = packet[IP].dst
    protocol = "Other"
    source_port = "-"
    destination_port = "-"
    info = ""

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        if source_port == 80 or destination_port == 80:
            protocol = "HTTP"
        elif source_port == 443 or destination_port == 443:
            protocol = "HTTPS"

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    if DNS in packet:
        protocol = "DNS"

        if DNSQR in packet:
            try:
                info = packet[DNSQR].qname.decode()
            except:
                info = "DNS query"

    protocol_count[protocol] += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    result = {
        "time": timestamp,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "size": len(packet),
        "info": info
    }

    results.append(result)

    print(
        f"[{timestamp}] "
        f"{source}:{source_port} -> "
        f"{destination}:{destination_port} "
        f"[{protocol}] "
        f"Size={len(packet)}"
    )

    if info:
        print(f"    Info: {info}")

def save_results():
    with open("traffic_results.txt", "w") as file:
        file.write("NETWORK TRAFFIC ANALYZER\n")
        file.write("=" * 70 + "\n\n")

        file.write("Protocol Summary\n")
        file.write("-" * 30 + "\n")

        for protocol, count in protocol_count.items():
            file.write(f"{protocol}: {count}\n")

        file.write("\nPacket Details\n")
        file.write("-" * 70 + "\n")

        for result in results:
            file.write(
                f"{result['time']} | "
                f"{result['source']}:{result['source_port']} -> "
                f"{result['destination']}:{result['destination_port']} | "
                f"{result['protocol']} | "
                f"Size: {result['size']} bytes"
            )

            if result["info"]:
                file.write(f" | {result['info']}")

            file.write("\n")

def main():
    print("=" * 70)
    print("                NETWORK TRAFFIC ANALYZER")
    print("=" * 70)

    interface = input("Enter network interface: ")
    count = int(input("Number of packets to capture: "))

    print("\nStarting packet capture...")
    print("Generate some network traffic while capturing.\n")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=count,
            store=False
        )

    except PermissionError:
        print("Permission denied. Run using sudo.")
        return

    except Exception as error:
        print("Error:", error)
        return

    save_results()

    print("\n" + "=" * 70)
    print("CAPTURE SUMMARY")
    print("=" * 70)

    print("Total packets:", packet_count)

    for protocol, count in protocol_count.items():
        print(f"{protocol}: {count}")

    print("\nResults saved to traffic_results.txt")

if __name__ == "__main__":
    main()
