import tkinter as tk
from tkinter import ttk, scrolledtext
import customtkinter as ctk
from scapy.all import sniff
import threading

# GUI Setup
ctk.set_appearance_mode("dark")  # Dark mode for better look
ctk.set_default_color_theme("blue")

class PacketSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Packet Analyzer")
        self.geometry("800x500")

        # Start/Stop Buttons
        self.start_button = ctk.CTkButton(self, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = ctk.CTkButton(self, text="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        self.stop_button.pack(pady=5)

        # Packet Display Table
        self.tree = ttk.Treeview(self, columns=("No", "Source", "Destination", "Protocol"), show="headings")
        self.tree.heading("No", text="No")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")

        self.tree.column("No", width=50)
        self.tree.column("Source", width=200)
        self.tree.column("Destination", width=200)
        self.tree.column("Protocol", width=100)

        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Packet Details Section
        self.packet_details = scrolledtext.ScrolledText(self, height=10)
        self.packet_details.pack(pady=5, fill=tk.BOTH, expand=True)

        self.sniffing = False  # Flag to control sniffing
        self.packet_count = 1   # Packet counter

    def start_sniffing(self):
        """Starts the packet sniffing in a separate thread."""
        self.sniffing = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        """Stops packet sniffing."""
        self.sniffing = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def sniff_packets(self):
        """Captures packets and updates the GUI."""
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        """Processes captured packets and updates the UI."""
        if not self.sniffing:
            return

        src_ip = packet.src if hasattr(packet, "src") else "Unknown"
        dst_ip = packet.dst if hasattr(packet, "dst") else "Unknown"
        protocol = packet.proto if hasattr(packet, "proto") else "Unknown"

        self.tree.insert("", "end", values=(self.packet_count, src_ip, dst_ip, protocol))
        self.packet_count += 1

        self.packet_details.insert(tk.END, f"{packet.summary()}\n")
        self.packet_details.see(tk.END)

# Run Application
if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
