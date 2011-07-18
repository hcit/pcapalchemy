import os
import datetime
import time
import cPickle as pickle
from collections import defaultdict
import random

import dpkt


class Stats(object):
    __slots__ = 'total', 'files'


class PcapAlchemy(object):

    def __init__(self, config):
        self.config = config
        self._source_files = []

        self.timestamp = datetime.datetime.now()
        self.earliest = None
        self.latest = None
        self.writer = dpkt.pcap.Writer(open(self.config.write_fn, 'wb'))

        self.total_bytes = 0
        self.total_packets = 0

    #--------------------------------------------------------------------------

    def prepare_sources(self):
        '''
        Quick scan through pcaps
        '''
        self.stats = Stats()
        self.stats.total = 0

        cache_file = os.path.join(self.config.cache_dir, 'stats.files.cache')

        # TODO option for clearing cache
        try:
            self.stats.files = pickle.load(open(cache_file, 'rb'))
        except IOError, e:
            self.stats.files = defaultdict(int)

        for f in self.source_files:

            if f in dict(self.stats.files):
                self.stats.total += self.stats.files[f]
                continue

            try:
                r = dpkt.pcap.Reader(open(f, 'rb'))
            except ValueError, e:
                print('%s: %s' % (f, e))
                continue

            for ts, buf in r:
                self.stats.total += 1
                self.stats.files[f] += 1

            print('%s: %s' % (f, self.stats.files[f]))

            pickle.dump(self.stats.files, open(cache_file, 'wb'))

    #--------------------------------------------------------------------------

    def set_source_files(self, f):
        assert(isinstance(f, (list, tuple)))
        self._source_files = f
        self.prepare_sources()

    def get_source_files(self):
        return self._source_files

    source_files = property(get_source_files, set_source_files)

    #--------------------------------------------------------------------------

    @property
    def time_range(self):
        if not self.earliest or not self.latest:
            return datetime.timedelta(0)

        return self.latest - self.earliest

    #--------------------------------------------------------------------------

    def packet_random(self, max_iter=0):
        '''
        Randomly picks a single packet from the whole set of pcap files.
        '''

        opts = [self.stats.total]
        if max_iter:
            opts.append(max_iter)

        rand = random.randint(0, min(opts))
        c = 0
        for f, total in self.stats.files.iteritems():
            c += total
            if c > rand:
                o = random.randint(0, min(opts))
                break

        r = dpkt.pcap.Reader(open(f, 'rb'))
        pkt = None
        for ts, pkt in r:
            o -= 1
            if o < 0:
                break

        if not pkt:
            assert(0)

        return pkt

    def emit(self, pkt):
        ts = time.mktime(self.timestamp.timetuple())
        self.writer.writepkt(pkt, ts=ts)

        self.total_packets += 1
        self.total_bytes += len(pkt)

        if not self.latest or self.timestamp > self.latest:
            self.latest = self.timestamp
        if not self.earliest or self.timestamp < self.earliest:
            self.earliest = self.timestamp


    def loop_pcap(self, specific=None):

        def _loop(fn):
            r = dpkt.pcap.Reader(open(fn, 'rb'))
            for ts, pkt in r:
                yield ts, pkt

        if not specific:
            for f in self.stats.files.iterkeys():
                for y in _loop(f):
                    yield y

        else:
            for y in _loop(specific):
                yield y

    def log_status(self):
        if self.total_packets % 100 == 0 and \
                self.time_range.total_seconds() > 0:
            print self.time_range, self.total_bytes, \
                self.total_bytes / self.time_range.total_seconds() \
            / 1000000

