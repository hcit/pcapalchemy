# Sample pcapa rules file

import random
import datetime
import time
import glob

alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=100)
alchemy.source_files = glob.glob('dumps/halekulani/halekulani.pcap')

packet = alchemy.packet_random(1)
alchemy.emit(packet)

