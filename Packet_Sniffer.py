import scapy.all as scapy
import sys
import click
@click.command()
@click.argument('interface', type=str)
@click.argument('mode', type=click.Choice(['summary', 'detail']))
@click.option('-f', '--filter', type=str, help='BPF filter expression')
@click.option('-o', '--output',type=str, help="Output file name")
def sniff_packets(interface, mode, filter=None, output=None):
    packets = []

    def process_packet_summary(packet):
        packets.append(packet.summary())
        if output != "":
            click.echo(packet.summary())

    def process_packet_detail(packet):
        packets.append(packet.summary())
        packets.append(str(packet.show(dump=True)))
        if output != "":
            click.echo(packet.summary())
            click.echo(packet.show())
    try:
        if mode == "summary":
            scapy.sniff(iface=interface, store=False, filter=filter, prn=process_packet_summary)
        elif mode == "detail":
            scapy.sniff(iface=interface, store=False, filter=filter, prn=process_packet_detail)

        if output:
            with open(output, 'w', encoding="utf-8") as f:
                for packet in packets:
                    f.write(packet + '\n')
        else:
            for packet in packets:
                click.echo(packet)

    except scapy.Scapy_Exception as e:
        click.echo(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        sniff_packets()
    except KeyboardInterrupt:
        click.echo("\nPacket sniffing stopped by the user.")
        sys.exit(1)
