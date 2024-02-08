import scapy.all as scapy
import sys
import click
@click.command()
@click.argument('interface', type=str )
@click.argument('mode', type=click.Choice(['summary', 'detail']))
@click.option('-f', '--filter', type=str, help='BPF filter expression')

def sniff_packets(interface, mode, filter=None):
        try:
                if mode == "summary":
                        scapy.sniff(iface=interface, store=False, filter=filter, prn=process_packet_summary)
                elif mode == "detail":
                        scapy.sniff(iface=interface, store=False, filter=filter, prn=process_packet_detail)
        except scapy.Scapy_Exception as e:
                click.echo(f"An error occurred: {e}")
                sys.exit(1)
def process_packet_summary(packet):
        click.echo(packet.summary())

def process_packet_detail(packet):
        click.echo(packet.summary())
        click.echo(packet.show())

if __name__ == "__main__":
    try:
        sniff_packets()
    except KeyboardInterrupt:
        click.echo("\nPacket sniffing stopped by the user.")
        sys.exit(1)
