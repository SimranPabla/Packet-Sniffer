# Packet Sniffer

Packet Sniffer is a Python script that captures and analyzes network packets using the Scapy library. It provides two modes of operation: summary and detail. Additionally, it supports applying BPF filters to capture specific types of packets and saving the captured packets to an output file.

## Features

- Capture and analyze network packets in summary or detail mode.
- Apply BPF filter expressions to capture specific types of packets.
- Save captured packets to an output file.
- Command-line interface (CLI) for easy usage.

## Usage

To use the Packet Sniffer, follow these steps:

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/SimranPabla/Packet-Sniffer.git
   ```

2. Navigate to the project directory:
   ```bash
   cd Packet-Sniffer
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
   - Capture packets on interface "eth0" in detail mode and save them to an output file:
     ```bash
     python packet_sniffer.py eth0 detail -o output.txt
     ```

## Options

- `interface`: The network interface to capture packets from.
- `mode`: The mode of operation, either "summary" or "detail".
- `-f`, `--filter`: Optional. BPF filter expression to capture specific types of packets.
- `-o`, `--output`: Optional. Output file name to save captured packets.

## Requirements

- Python 3.x
- Scapy library
- Click library (for command-line interface)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
