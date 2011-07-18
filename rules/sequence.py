# Sample pcapa rules file

import random
import datetime
import time
import glob

alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=1)
alchemy.source_files = glob.glob('dumps/cctf-defcon11/ulogd.znb0.pcap.*')

while alchemy.time_range < datetime.timedelta(days=2):

    for ts, pkt in alchemy.loop_pcap():
        alchemy.emit(pkt)
        alchemy.timestamp += datetime.timedelta(seconds=-1)
        alchemy.log_status()

