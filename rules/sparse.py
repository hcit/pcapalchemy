'''
Sparse

Create a sparse version of a pcap by skipping a defined amount of packets.
'''

def config(parser):
    parser.add_argument('--skip', dest='skip_packets', metavar='COUNT',
        required=False, default=100,
        help='Skip every COUNT packets')


def loop(alchemy):
    c = 0
    for ts, packet in alchemy.all_packets():
        if c % alchemy.config.skip_packets != 0:
            continue
        alchemy.emit(packet, ts)
        alchemy.log_status()

