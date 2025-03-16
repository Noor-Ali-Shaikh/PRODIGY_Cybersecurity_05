# PRODIGY_Cybersecurity_05
# 🔥 Network Packet Analyzer - Advanced GUI-Based Packet Sniffer

## 🚀 Introduction
**Network Packet Analyzer** is an advanced **GUI-based packet sniffer tool** built using Python and Scapy. It captures, analyzes, and displays real-time network traffic, showing details like **source/destination IPs, protocols, ports, and payload data.**

🔹 Built for **ethical hacking, cybersecurity research, and network analysis**.  
🔹 User-friendly **GUI interface** for smooth packet monitoring.  
🔹 **Supports all major network protocols** (TCP, UDP, ICMP, HTTP, etc.).  

> 🚨 **Disclaimer:** This tool is strictly for educational and ethical purposes. Unauthorized use on public networks is illegal.

---

## 🛠️ Features
✅ **Real-Time Packet Capture** - Sniffs network traffic instantly.  
✅ **Protocol Analysis** - Identifies TCP, UDP, ICMP, ARP, and more.  
✅ **Advanced GUI Interface** - No need for complex terminal commands.  
✅ **Search & Filter** - Focus on specific IPs, protocols, or keywords.  
✅ **Export to CSV** - Save captured data for further analysis.  
✅ **Lightweight & Fast** - Uses Python's Scapy for high-performance packet sniffing.

---

## 🎯 How It Works
1️⃣ **Launch the Tool** - Run the Python script.  
2️⃣ **Start Sniffing** - Click **"Start Capture"** to begin packet monitoring.  
3️⃣ **Analyze Traffic** - View packet details like IPs, MAC addresses, and protocols.  
4️⃣ **Filter & Search** - Find specific packets based on protocol or address.  
5️⃣ **Export Data** - Save the captured logs for detailed inspection.

---

## 🔧 Installation & Setup
### **📌 Requirements**
- **Windows/Linux/Mac** (Admin privileges required)
- Python 3.x installed
- **Npcap (Windows) / libpcap (Linux)** installed
- Required Python libraries: `scapy`, `tkinter`, `pandas`

### **📥 Installation Steps**
```bash
# Clone the repository
git clone https://github.com/YourUsername/Network-Packet-Analyzer.git
cd Network-Packet-Analyzer

# Install dependencies
pip install -r requirements.txt

# Run the tool
python packet_sniffer.py
```

---

## 🎨 DEMO
![network](https://github.com/user-attachments/assets/29188e94-483f-43ce-9a7f-8fb75703b79d)


---

## ⚡ Usage Examples
**1️⃣ Capture packets on a specific interface:**
```python
sniff(iface='eth0', count=10)
```

**2️⃣ Filter packets by protocol (Only TCP):**
```python
sniff(filter='tcp', prn=lambda x: x.summary())
```

**3️⃣ Save captured packets to a file:**
```python
wrpcap('captured_traffic.pcap', packets)
```

---

## 🔥 Ethical & Legal Disclaimer
- This tool is meant **only for educational and ethical hacking purposes**.
- **DO NOT** use this on unauthorized networks.
- The developer is **not responsible** for any misuse.

---

## 🤝 Contributing
Contributions are welcome! Feel free to **fork** this repo and submit a **pull request**.

--

🚀 **If you like this project, don't forget to ⭐ the repo!**
