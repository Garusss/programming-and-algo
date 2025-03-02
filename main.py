import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import scapy.all as scapy
import threading
import csv
from scapy.utils import wrpcap
import socket
from geopy.geocoders import Nominatim

# Global flag to control packet capture
capturing = False
packets_data = []
captured_packets = []

def start_capture():
    global capturing
    capturing = True
    status_label.config(text="Status: Capturing...", fg="green")
    threading.Thread(target=capture_packets, daemon=True).start()

def stop_capture():
    global capturing
    capturing = False
    status_label.config(text="Status: Stopped", fg="red")

def capture_packets():
    scapy.sniff(prn=process_packet, store=True)

def process_packet(packet):
    if not capturing:
        return
    
    protocol = "Unknown"
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
        
        if protocol_filter.get() == "All" or protocol_filter.get() == protocol:
            packets_data.append((src_ip, dst_ip, protocol))
            captured_packets.append(packet)
            packet_list.insert("", "end", values=(src_ip, dst_ip, protocol))
            packet_list.yview_moveto(1)
            update_packet_stats()

def update_packet_stats():
    tcp_count = sum(1 for p in packets_data if p[2] == "TCP")
    udp_count = sum(1 for p in packets_data if p[2] == "UDP")
    icmp_count = sum(1 for p in packets_data if p[2] == "ICMP")
    status_label.config(text=f"Status: Capturing... TCP: {tcp_count} | UDP: {udp_count} | ICMP: {icmp_count}")

def save_packets_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source IP", "Destination IP", "Protocol"])
            writer.writerows(packets_data)
        messagebox.showinfo("Success", "Packets saved successfully!")

def save_packets_pcap():
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        wrpcap(file_path, captured_packets)
        messagebox.showinfo("Success", "Packets saved as PCAP successfully!")

def show_packet_details(event):
    selected_item = packet_list.selection()
    if selected_item:
        item = packet_list.item(selected_item)
        details = f"Source IP: {item['values'][0]}\nDestination IP: {item['values'][1]}\nProtocol: {item['values'][2]}"
        messagebox.showinfo("Packet Details", details)

def geoip_lookup():
    selected_item = packet_list.selection()
    if selected_item:
        item = packet_list.item(selected_item)
        ip = item['values'][0]
        geolocator = Nominatim(user_agent="geoip_lookup")
        try:
            location = geolocator.geocode(ip, timeout=10)
            location_str = location.address if location else "Unknown Location"
            messagebox.showinfo("GeoIP Lookup", f"IP: {ip}\nLocation: {location_str}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve location: {e}")

# GUI Setup
root = tk.Tk()
root.title("Packet Capture Tool")
root.geometry("700x500")
root.configure(bg="#2c3e50")

frame = tk.Frame(root, bg="#2c3e50")
frame.pack(pady=10)

start_btn = tk.Button(frame, text="Start Capture", command=start_capture, bg="#27ae60", fg="white", font=("Arial", 12), width=15)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(frame, text="Stop Capture", command=stop_capture, bg="#c0392b", fg="white", font=("Arial", 12), width=15)
stop_btn.pack(side=tk.LEFT, padx=10)

save_csv_btn = tk.Button(frame, text="Save as CSV", command=save_packets_csv, bg="#2980b9", fg="white", font=("Arial", 12), width=15)
save_csv_btn.pack(side=tk.LEFT, padx=10)

save_pcap_btn = tk.Button(frame, text="Save as PCAP", command=save_packets_pcap, bg="#f39c12", fg="white", font=("Arial", 12), width=15)
save_pcap_btn.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(root, text="Status: Stopped", fg="white", bg="#2c3e50", font=("Arial", 12))
status_label.pack()

# Protocol Filter
tk.Label(root, text="Filter by Protocol:", fg="white", bg="#2c3e50", font=("Arial", 12)).pack()
protocol_filter = ttk.Combobox(root, values=["All", "TCP", "UDP", "ICMP"], state="readonly", font=("Arial", 12))
protocol_filter.set("All")
protocol_filter.pack()

# Packet List
columns = ("Source IP", "Destination IP", "Protocol")
packet_list = ttk.Treeview(root, columns=columns, show="headings", height=15, style="mystyle.Treeview")
for col in columns:
    packet_list.heading(col, text=col)
packet_list.pack(fill="both", expand=True, padx=10, pady=10)
packet_list.bind("<Double-1>", show_packet_details)

# GeoIP Lookup Button
tk.Button(root, text="GeoIP Lookup", command=geoip_lookup, bg="#8e44ad", fg="white", font=("Arial", 12), width=15).pack(pady=5)

# Style
style = ttk.Style()
style.configure("mystyle.Treeview", font=("Arial", 10), rowheight=25)
style.configure("mystyle.Treeview.Heading", font=("Arial", 12, "bold"))

root.mainloop()
