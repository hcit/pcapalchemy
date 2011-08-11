''''
Randomize

Randomly select packets from the source pcap files and emit them into the new
file in any order.
'''

import random
import datetime
import time

def config(parser):
    return

def loop(alchemy):
    alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=1)

    packets = [alchemy.packet_random(1000) for a in xrange(10)]

    while alchemy.time_range < datetime.timedelta(days=2):
        alchemy.emit(random.choice(packets))
        alchemy.timestamp += datetime.timedelta(seconds=1)
        alchemy.log_status()

