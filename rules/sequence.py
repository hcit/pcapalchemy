'''
Sequence

'''
import random
import datetime
import time

def config(parser):
    return


def loop(alchemy):
    start = -365
    end = 0

    alchemy.timestamp = datetime.datetime.now() - datetime.timedelta(days=-start)

    exito = False
    while not exito:
        for ts, pkt in alchemy.all_packets():
            alchemy.emit(pkt)
            alchemy.timestamp += datetime.timedelta(seconds=60 * 60 *
                random.random())
            alchemy.log_status()

            if alchemy.time_range > datetime.timedelta(days=end - start):
                exito = True
                break

