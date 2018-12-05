'''
COMP3331 18s2 ASS
-----
z5125769
'''

import binascii
import time

from abc import ABC, abstractmethod

STP_STA = {
    'NOT_CONN': 0,
    'SYN_SENT': 1,
    'SYNA_RCV': 2,
    'CONN_EST': 3,
    'FIN_SENT': 4,
    'FIN_RCVD': 5,
    'DAT_RCVD': 6,
    'ACK_RCVD': 7,
    'TIME_OUT': 8
}


class STPLogger(ABC):
    '''
    log component
    '''
    def __init__(self, f_name):
        self._f_name = f_name
        self._init_t = time.time()
        self._retrans = []
        self._counter = None

    def set_rf(self, seq_l):
        '''
        set retransmission flag
        '''
        self._retrans += seq_l

    def log(self, event, seq, ack, opts, dat_l):
        '''
        log component, main logic
        '''
        if seq in self._retrans:
            event += '/RXT'
            self._retrans.remove(seq)
        ack_b, dat_b, syn_b, fin_b = opts
        typ = ''
        if ack_b == 1:
            typ += 'A'
        if dat_b == 1:
            typ += 'D'
        if syn_b == 1:
            typ += 'S'
        if fin_b == 1:
            typ += 'F'
        self.counter_hook(event, opts)
        with open(self._f_name, 'a') as openf:
            openf.write(
                f"{event:<18} {time.time() - self._init_t:>12.6f} {typ:>2} {seq:>10} {dat_l:>6} {ack:>10}\n")

    def init_counter(self, counter):
        ''' setter '''
        self._counter = counter

    def log_time(self, string):
        ''' DEBUG '''
        with open(self._f_name, 'a') as openf:
            openf.write(f"{string} {time.time() - self._init_t}\n")

    @abstractmethod
    def counter_hook(self, event, opts):
        ''' hook function for counter in the sub class, to be overrided '''
        pass

    @abstractmethod
    def summarize_hook(self, info):
        ''' hook function for summary at the end of the log file, to be overrided '''
        pass


class STPPacker:
    '''
    STP packer, helper class for STP packets
    '''
    def __init__(self, sport, dport):
        self._sport = sport
        self._dport = dport

    def packing(self, seq, ack, opts, payload):
        '''
        return packed bytearray
        '''
        ack_b, dat_b, syn_b, fin_b = opts
        stp_header = []
        stp_header.append((self._sport << 16) + self._dport)
        stp_header.append(seq)
        stp_header.append(ack)
        stp_header.append((ack_b << 20) + (dat_b << 19) + (syn_b << 17)
                          + (fin_b << 16))
        stp_header = list(map(lambda x: x.to_bytes(4, 'big'), stp_header))
        crc_dat = b''.join(stp_header + [payload])
        crc = binascii.crc32(crc_dat) & (2**32 - 1)
        stp_header.append(crc.to_bytes(4, 'big'))

        return b''.join(stp_header + [payload])

    def unpacking(self, packet):
        '''
        return info in the packet
        '''
        packet_l = [packet[i:i+4] for i in range(0, len(packet), 4)]
        packet_l_int = list(map(lambda x: int.from_bytes(x, 'big'), packet_l[0:5]))
        sport = packet_l_int[0] >> 16
        dport = packet_l_int[0] & (2**16 - 1)
        if self._dport != sport:
            self._dport = sport
        if sport != self._dport or dport != self._sport:
            raise ValueError('port check failed')
        seq = packet_l_int[1]
        ack = packet_l_int[2]
        opts = packet_l_int[3]
        opts_t = ((opts & 0x100000) >> 20, (opts & 0x80000) >> 19,
                  (opts & 0x20000) >> 17, (opts & 0x10000) >> 16)
        crc = packet_l_int[4]
        payload = b''.join(packet_l[5:])
        crc_dat = b''.join(packet_l[0:4]) + payload
        crc_cal = binascii.crc32(crc_dat) & (2**32 - 1)
        if crc != crc_cal:
            raise ValueError('package corrupted')
        return seq, ack, opts_t, payload

    @staticmethod
    def unpack_header(packet):
        '''
        extract some info from the header of the packet
        '''
        packet_l = [packet[i:i+4] for i in range(0, len(packet), 4)]
        packet_l_int = list(map(lambda x: int.from_bytes(x, 'big'), packet_l[0:5]))
        seq = packet_l_int[1]
        ack = packet_l_int[2]
        opts = packet_l_int[3]
        opts_t = ((opts & 0x100000) >> 20, (opts & 0x80000) >> 19,
                  (opts & 0x20000) >> 17, (opts & 0x10000) >> 16)
        payload = b''.join(packet_l[5:])
        return seq, ack, opts_t, len(payload)
