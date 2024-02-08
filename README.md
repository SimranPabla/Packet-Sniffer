# Packet Sniffer

Packet Sniffer is a Python script that implements a packet sniffer tool using the Scapy library. It captures packets from a specified network interface and displays either packet summaries or detailed information based on user preference.

## Features

- Capture packets from a specified network interface.
- Display packet summaries or detailed information.
- Apply BPF filter expressions to capture specific types of packets.
- Command-line interface (CLI) for easy usage.

## Usage

To use the Packet Sniffer, follow these steps:

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/SimranPabla/Packet-Sniffer.git
   ```

2. Navigate to the project directory:
   ```bash
   cd packet-sniffer
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the script with the desired arguments. Here are some examples:
   - Capture packets on interface "eth0" in summary mode:
     ```bash
     python packet_sniffer.py eth0 summary
     ```
   - Capture TCP packets on interface "eth0" in detail mode:
     ```bash
     python packet_sniffer.py eth0 detail -f "tcp"
     ```

## Requirements

- Python 3.x
- Scapy library
- Click library (for command-line interface)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
