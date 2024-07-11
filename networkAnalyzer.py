import tkinter as tk
from tkinter import ttk
from scapy.all import *

print(get_if_list())

class PacketSnifferTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer Tool")
        self.root.configure(background="#f0f0f0")

        # Create input field
        self.interface_label = tk.Label(root, text="Select Interface:", bg="#f0f0f0")
        self.interface_label.pack()
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var)
        self.interface_menu['values'] = [i for i in get_if_list()]
        self.interface_menu.pack()

        # Create buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white")
        self.start_button.pack()
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, bg="#FF0000", fg="white")
        self.stop_button.pack()

        # Create output field
        self.output_text = tk.Text(root, height=20, width=80, bg="#f0f0f0")
        self.output_text.pack()

        # Initialize sniffing variables
        self.sniffing = False
        self.sniffer = None

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniffer = sniff(iface=self.interface_var.get(), prn=self.process_packet)
            self.start_button.config(text="Sniffing...", state="disabled")
            self.stop_button.config(state="normal")

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.sniffer.stop()
            self.start_button.config(text="Start Sniffing", state="normal")
            self.stop_button.config(state="disabled")

    def process_packet(self, packet):
        self.output_text.insert("end", f"Packet captured: {packet.summary()}\n")
        self.output_text.insert("end", f"Source IP: {packet[IP].src}\n")
        self.output_text.insert("end", f"Destination IP: {packet[IP].dst}\n")
        self.output_text.insert("end", f"Protocol: {packet.protocol}\n")
        self.output_text.insert("end", f"Payload: {packet.payload}\n\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferTool(root)
    root.mainloop()
