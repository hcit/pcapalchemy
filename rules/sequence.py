# Sample pcapa rules file

import random
import datetime
import time
import glob

start = -2
end = 2

alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=-start)
alchemy.source_files = glob.glob('dumps/cctf-defcon11/ulogd.znb0.pcap.*')

exito = False

while not exito:

    for ts, pkt in alchemy.loop_pcap():
        alchemy.emit(pkt)
        alchemy.timestamp += datetime.timedelta(seconds=1)
        alchemy.log_status()

        if alchemy.time_range > datetime.timedelta(days=end - start):
            exito = True
            break

