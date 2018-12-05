'''
COMP3331 18s2 ASS
-----
z5125769
'''

import socket
import sys

from public import STP_STA, STPLogger, STPPacker

ONE_BYTE = b'0'


class STPReceiverLogger(STPLogger):
    '''
    log component
    '''
    def __init__(self):
        super().__init__("Receiver_log.txt")
        counter = {
            'all_seg_rcv': 0,
            'dat_seg_rcv': 0,
            'crp_seg_rcv': 0,
            'dup_seg_rcv': 0,
            'dup_ack_snt': 0
        }
        super().init_counter(counter)

    def counter_hook(self, event, opts):
        ''' override function in super class '''
        e_cls = event[0:3]
        e_opt = event[4:]
        dat_b = opts[1]
        if e_cls == "rcv":
            self._counter['all_seg_rcv'] += 1
            if dat_b:
                self._counter['dat_seg_rcv'] += 1
            if e_opt == "corr":
                self._counter['crp_seg_rcv'] += 1
            elif e_opt == "dup" and dat_b:
                self._counter['dup_seg_rcv'] += 1
            else:
                pass
        elif e_cls == "snd" and e_opt == "DA":
            self._counter['dup_ack_snt'] += 1
        else:
            pass

    def summarize_hook(self, info):
        ''' override function in super class '''
        dat_len_rcv = info
        with open(self._f_name, 'a') as openf:
            openf.write(f"============================================\n")
            openf.write(f"Amount of Data Received (bytes)   {dat_len_rcv:>10}\n")
            openf.write(f"Total segments received           {self._counter['all_seg_rcv']:>10}\n")
            openf.write(f"Data segments received            {self._counter['dat_seg_rcv']:>10}\n")
            openf.write(f"Data Segments with bit errors     {self._counter['crp_seg_rcv']:>10}\n")
            openf.write(f"Duplicate data segments received  {self._counter['dup_seg_rcv']:>10}\n")
            openf.write(f"Duplicate ACKs sent               {self._counter['dup_ack_snt']:>10}\n")
            openf.write(f"============================================\n")


class STPReceiver:
    '''
    STP protocol, implementation on receiver side
    '''
    def __init__(self, sport):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(('', sport))
        self._packer = STPPacker(sport, 0)
        self._logger = STPReceiverLogger()
        self._seq = 0
        self._ack = 0

        self._payload = None
        self._payload_isn = 0
        self._rcv_win = set()

    def receiving(self):
        '''
        receiving all the payloads and return as a whole bytearray
        '''
        packer = self._packer
        logger = self._logger
        with self._socket as sock:
            state = STP_STA['NOT_CONN']
            while True:
                recv, addr = sock.recvfrom(4096)
                try:
                    seq, ack, opts, payload = packer.unpacking(recv)
                except ValueError as err:
                    if err.args[0] == "port check failed" or err.args[0] == "package corrupted":
                        logger.log("rcv/corr", 0, 0, (0, 0, 0, 0), 0)
                    continue
                p_len = len(payload)
                if seq <= self._ack or self.check_dup((seq, payload)):
                    logger.log("rcv/dup", seq, ack, opts, p_len)
                else:
                    logger.log("rcv", seq, ack, opts, p_len)
                if opts == (0, 0, 1, 0) and state == STP_STA['NOT_CONN']:
                    self._ack = seq + p_len
                    packet = packer.packing(self._seq, self._ack, (1, 0, 1, 0), ONE_BYTE)
                    sock.sendto(packet, addr)
                    logger.log("snd", self._seq, self._ack, (1, 0, 1, 0), 1)
                    state = STP_STA['SYN_SENT']
                elif opts == (1, 0, 0, 0) and state == STP_STA['SYN_SENT']:
                    self._ack = seq + p_len
                    state = STP_STA['CONN_EST']
                    self.set_payload_isn(seq + p_len)
                elif opts == (0, 1, 0, 0) and state == STP_STA['CONN_EST']:
                    event = self.update_receive_window(ack, (seq, payload))
                    packet = packer.packing(self._seq, self._ack, (1, 0, 0, 0), ONE_BYTE)
                    sock.sendto(packet, addr)
                    logger.log(event, self._seq, self._ack, (1, 0, 0, 0), 1)
                elif opts == (0, 0, 0, 1) and state == STP_STA['CONN_EST']:
                    if ack == self._seq + 1:
                        self._seq += 1
                        self._ack = seq + p_len
                        logger.log("snd", self._seq, self._ack, (1, 0, 0, 0), 1)
                        packet = packer.packing(self._seq, self._ack, (1, 0, 0, 0), ONE_BYTE)
                        sock.sendto(packet, addr)
                        self._seq += 1
                        logger.log("snd", self._seq, self._ack, (0, 0, 0, 1), 1)
                        packet = packer.packing(self._seq, self._ack, (0, 0, 0, 1), ONE_BYTE)
                        sock.sendto(packet, addr)
                        state = STP_STA['FIN_SENT']
                elif opts == (1, 0, 0, 0) and state == STP_STA['FIN_SENT']:
                    if ack == self._seq + 1:
                        state = STP_STA['FIN_RCVD']
                        logger.summarize_hook(len(self._payload))
                        return self._payload
                elif opts == (0, 0, 1, 0):
                    print("Please restart receiver.")
                    sys.exit(1)
                else:
                    pass
                    # print(f"unexpected {opts} with payload {payload}")
        return b''

    def set_payload_isn(self, isn):
        ''' set isn for payload '''
        self._payload = b''
        self._payload_isn = isn

    def update_receive_window(self, ack, p_info):
        ''' use _ack as CACK pointer, _rcv_win as receive buffer '''
        self._rcv_win.add(p_info)
        rcv_win = sorted(self._rcv_win, key=lambda x: x[0])
        t_seq, t_load = rcv_win[0]
        if t_seq == self._ack:
            # received ack checked here
            while t_seq == self._ack and ack <= self._seq + 1:
                self._ack += len(t_load)
                self._payload += t_load
                rcv_win.pop(0)
                if not rcv_win:
                    break
                t_seq, t_load = rcv_win[0]
            self._rcv_win = set(rcv_win)
            self._seq += 1
            return "snd"
        if t_seq < self._ack:
            self._rcv_win.remove(p_info)
            return "snd/DA"
        assert t_seq > self._ack
        return "snd/DA"

    def check_dup(self, p_info):
        ''' check whether same segment appears in _rcv_win '''
        return p_info in self._rcv_win


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: ./{__file__} receiver_port file_name")
        sys.exit(1)
    S_PORT = int(sys.argv[1])
    F_NAME = str(sys.argv[2])
    RECEIVER = STPReceiver(S_PORT)
    F_BYTES = RECEIVER.receiving()
    with open(F_NAME, "wb") as open_pdf:
        open_pdf.write(F_BYTES)
