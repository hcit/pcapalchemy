# Sample pcapa rules file

import random
import datetime
import time
import glob

alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=1)
alchemy.source_files = glob.glob('dumps/cctf-defcon11/ulogd.znb0.pcap.2')

packets = [alchemy.packet_random(1000) for a in xrange(10)]

while alchemy.time_range < datetime.timedelta(days=2):
    alchemy.emit(random.choice(packets))
    alchemy.timestamp += datetime.timedelta(seconds=1)
    alchemy.log_status()

