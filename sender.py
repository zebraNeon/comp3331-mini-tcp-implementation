'''
COMP3331 18s2 ASS
-----
z5125769
'''

import random
import socket
import sys
import threading
import time

from public import STPLogger, STPPacker

ONE_BYTE = b'0'


def dump_file(file_name):
    '''
    helper func
    '''
    with open(file_name, "rb") as openf:
        return openf.read()


class STPTimer:
    '''
    Timer for STP protocol on sender side
    '''
    def __init__(self, gamma):
        self._est_rtt = 0.500
        self._dev_rtt = 0.250
        self._gamma = gamma
        self._timeout = self._est_rtt + self._gamma * self._dev_rtt
        self.__start = 0

    def get_timeout(self):
        ''' getter '''
        return self._timeout

    def start(self):
        ''' counter '''
        self.__start = time.time()

    def end(self):
        ''' counter '''
        self.update_timeout(time.time() - self.__start)

    def update_timeout(self, s_rtt):
        ''' setter '''
        self._est_rtt = (1 - 0.125) * self._est_rtt + 0.125 * s_rtt
        self._dev_rtt = (1 - 0.25) * self._dev_rtt + 0.25 * abs(s_rtt - self._est_rtt)
        self._timeout = self._est_rtt + self._gamma * self._dev_rtt

    def check_timeout(self):
        ''' check timeout or not '''
        return time.time() - self.__start > self._timeout


class STPSenderLogger(STPLogger):
    '''
    log component
    '''
    def __init__(self):
        super().__init__("Sender_log.txt")
        counter = {
            'all_seg': 0,
            'pld_seg': 0,
            'drp_seg': 0,
            'crp_seg': 0,
            'ror_seg': 0,
            'dup_seg': 0,
            'dly_seg': 0,
            'rtx_seg': 0,
            'fst_rtx': 0,
            'dup_ack': 0
        }
        super().init_counter(counter)

    def counter_hook(self, event, opts):
        if event[0:4] == "drop":
            self._counter['drp_seg'] += 1
        if event[0:3] == "snd":
            if "corr" in event[4:]:
                self._counter['crp_seg'] += 1
            elif "rord" in event[4:]:
                self._counter['ror_seg'] += 1
            elif "dup" in event[4:]:
                self._counter['dup_seg'] += 1
            elif "dely" in event[4:]:
                self._counter['dly_seg'] += 1
            elif "RXT" in event[4:]:
                self._counter['rtx_seg'] += 1
        elif "DA" in event[4:]:
            self._counter['dup_ack'] += 1
        else:
            pass

    def summarize_hook(self, info):
        f_size = info
        with open(self._f_name, 'a') as openf:
            openf.write(f"========================================================\n")
            openf.write(f"Size of the file (in bytes)                   {f_size:>10}\n")
            openf.write(f"Segments transmitted (including drop & RXT)   {self._counter['all_seg']:>10}\n")
            openf.write(f"Number of Segments handled by PLD             {self._counter['pld_seg']:>10}\n")
            openf.write(f"Number of Segments Dropped                    {self._counter['drp_seg']:>10}\n")
            openf.write(f"Number of Segments Corrupted                  {self._counter['crp_seg']:>10}\n")
            openf.write(f"Number of Segments Re-ordered                 {self._counter['ror_seg']:>10}\n")
            openf.write(f"Number of Segments Duplicated                 {self._counter['dup_seg']:>10}\n")
            openf.write(f"Number of Segments Delayed                    {self._counter['dly_seg']:>10}\n")
            openf.write(f"Number of Retransmissions due to timeout      {self._counter['rtx_seg']:>10}\n")
            openf.write(f"Number of Fast Retransmissions                {self._counter['fst_rtx']:>10}\n")
            openf.write(f"Number of Duplicate Acknowledgements received {self._counter['dup_ack']:>10}\n")
            openf.write(f"========================================================\n")

    def count_fast_rtx(self):
        ''' count fst_rtx only '''
        self._counter['fst_rtx'] += 1

    def count_all(self):
        ''' count all_seg only '''
        self._counter['all_seg'] += 1

    def count_pld(self):
        ''' count pld_seg only '''
        self._counter['pld_seg'] += 1


class PLDModule:
    '''
    implementation of pld module -- corrupting packages on purpose
    '''
    def __init__(self, p_drp, p_dup, p_crp, p_ord, m_ord, p_dly, m_dly, seed):
        self._socket = None
        self._logger = None
        self._buffer = None
        self._ord_c = 0
        self._ord_f = False
        self._p_drp = p_drp
        self._p_dup = p_dup
        self._p_crp = p_crp
        self._p_ord = p_ord
        self._m_ord = m_ord
        self._p_dly = p_dly
        self._m_dly = m_dly
        random.seed(seed)

    def set_socket(self, sock):
        '''
        setter for socket
        '''
        self._socket = sock

    def set_logger(self, logger):
        '''
        setter for logger
        '''
        self._logger = logger

    def send(self, packet):
        '''
        wrapper for socket.send() as well as doing bad things on purpose
        '''
        if self._socket is None:
            print("socket not set for pld")
            sys.exit(1)
        seq, ack, opts, dat_l = STPPacker.unpack_header(packet)
        self._logger.count_all()
        if opts[1] == 0:
            self._socket.send(packet)
            self._logger.log("snd", seq, ack, opts, dat_l)
            return
        self._logger.count_pld()
        if random.random() < self._p_drp:
            self._logger.log("drop", seq, ack, opts, dat_l)
        elif random.random() < self._p_dup:
            self._socket.send(packet)
            self._socket.send(packet)
            self._logger.log("snd/dup", seq, ack, opts, dat_l)
        elif random.random() < self._p_crp:
            self._socket.send(self._corrupt(packet))
            self._logger.log("snd/corr", seq, ack, opts, dat_l)
        elif random.random() < self._p_ord:
            if self._buffer is not None:
                self._socket.send(packet)
                self._logger.log("snd", seq, ack, opts, dat_l)
            else:
                self._buffer = packet
                self._ord_f = True
        # using threading here instead of asyncio
        elif random.random() < self._p_dly:
            def dely_sending(packet):
                dly = random.random() * self._m_dly * 0.001
                time.sleep(dly)
                try:
                    self._socket.send(packet)
                    self._logger.log("snd/dely", seq, ack, opts, dat_l)
                except OSError:
                    pass
            thr = threading.Thread(target=dely_sending, args=(packet,))
            thr.start()
            # thr.join()
        else:
            self._socket.send(packet)
            self._logger.log("snd", seq, ack, opts, dat_l)
        if self._ord_f is True:
            self._ord_c += 1
        if self._buffer is not None and self._ord_c == self._m_ord:
            self._socket.send(self._buffer)
            seq, ack, opts, dat_l = STPPacker.unpack_header(self._buffer)
            self._logger.log("snd/rord", seq, ack, opts, dat_l)
            self._buffer = None
            self._ord_c = 0
            self._ord_f = False

    @staticmethod
    def _corrupt(packet):
        '''
        internal method to flip _one_ bit of the packet
        '''
        byte_i = int(random.random() * (len(packet) - 1))
        byte = packet[byte_i]
        bit_i = int(random.random() * 7)
        crp_byte = byte ^ (1 << bit_i)
        return packet[0:byte_i] + crp_byte.to_bytes(1, 'big') + packet[byte_i+1:]


class STPSender:
    '''
    STP protocol, implementation on sender side
    '''
    def __init__(self, dhost, dport, mss, mws, gamma, pld):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.connect((dhost, dport))
        sport = self._socket.getsockname()[1]
        self._packer = STPPacker(sport, dport)
        self._timer = STPTimer(gamma)
        self._logger = STPSenderLogger()

        self._mss = mss
        self._mws = mws
        self._gamma = gamma
        self._pld = pld
        self._pld.set_socket(self._socket)
        self._pld.set_logger(self._logger)

        # random.seed(int(time.time()))
        # self._seq = int(random.random() * (2**32 - 1))
        self._seq = 0
        self._ack = 0

        self._payload = None
        self._payload_len = 0
        self._payload_isn = 0
        self._snd_win = []

    def sending(self, payload):
        '''
        main logic
        '''
        self._payload = payload
        self._payload_len = len(payload)
        packer = self._packer
        logger = self._logger
        timer = self._timer
        pld = self._pld

        with self._socket as sock:

            # SYN PART
            while True:
                sock.settimeout(timer.get_timeout())
                pld.send(packer.packing(self._seq, self._ack, (0, 0, 1, 0), ONE_BYTE))
                timer.start()
                try:
                    seq, ack, opts, payload = packer.unpacking(sock.recv(4096))
                    timer.end()
                    if opts != (1, 0, 1, 0) or ack != self._seq + 1:
                        logger.log("rcv/corr", seq, ack, opts, len(payload))
                        raise ValueError("package not acked")
                    logger.log("rcv", seq, ack, opts, len(payload))
                    self._seq += 1
                    self._ack = seq + len(payload)
                    break
                except (socket.timeout, ValueError) as err:
                    self._handle_err(err, [self._seq])

            pld.send(packer.packing(self._seq, self._ack, (1, 0, 0, 0), ONE_BYTE))
            self._seq += 1

            # DAT PART
            curr_rcvd_ack = -1
            curr_rcvd_ack_c = 0
            self.set_payload_isn()
            while self.get_send_window_len():
                r_ack_t = list(map(lambda x: (x[0], x[0] + len(x[1])), self._snd_win))
                for p_seq, p_load in self._snd_win:
                    pld.send(packer.packing(p_seq, self._ack, (0, 1, 0, 0), p_load))
                # here we ignore the time interval between sending packets
                timer.start()
                while not timer.check_timeout():
                    if not self.get_send_window_len():
                        # break
                        continue
                    if curr_rcvd_ack_c >= 3:
                        rtx_index = 0
                        for i in range(len(r_ack_t)):
                            if r_ack_t[i][1] == ack:
                                rtx_index = i
                        logger.set_rf([self._snd_win[rtx_index][0]])
                        logger.count_fast_rtx()
                        pld.send(packer.packing(self._snd_win[rtx_index][0], self._ack,
                                                (0, 1, 0, 0), self._snd_win[rtx_index][1]))
                        curr_rcvd_ack_c = 0
                    sock.settimeout(timer.get_timeout())
                    try:
                        seq, ack, opts, payload = packer.unpacking(sock.recv(4096))
                        # here we ignore the time interval between sending packets
                        if not r_ack_t:
                            continue
                        if ack >= r_ack_t[0][1]:
                            timer.end()
                        self._ack = seq + len(payload)
                        if opts != (1, 0, 0, 0):
                            logger.log("rcv/corr", seq, ack, opts, len(payload))
                            raise ValueError("package corrupted")
                        r_ack_t.sort(key=lambda x: x[0])
                        if ack < curr_rcvd_ack:
                            logger.log("rcv/DA", seq, ack, opts, len(payload))
                        elif ack == curr_rcvd_ack:
                            curr_rcvd_ack_c += 1
                            logger.log("rcv/DA", seq, ack, opts, len(payload))
                        else:
                            logger.log("rcv", seq, ack, opts, len(payload))
                            curr_rcvd_ack = ack
                            curr_rcvd_ack_c = 0
                        self.update_send_window(ack)
                        r_ack_t = list(filter(lambda x: x[1] != ack, r_ack_t))
                        if not r_ack_t:
                            # break
                            continue
                    except (socket.timeout, ValueError) as err:
                        if isinstance(err, ValueError):
                            if err.args[0] == "port check failed" or \
                                    err.args[0] == "package corrupted":
                                logger.log("rcv/corr", 0, 0, (0, 0, 0, 0), 0)
                            else:
                                print(f"unexpected string in ValueError {err.args[0]}")
                        else:
                            pass
                if r_ack_t:
                    logger.set_rf(map(lambda x: x[0], r_ack_t))

            # FIN PART
            while True:
                sock.settimeout(timer.get_timeout())
                pld.send(packer.packing(self._seq, self._ack, (0, 0, 0, 1), ONE_BYTE))
                timer.start()
                try:
                    seq, ack, opts, payload = packer.unpacking(sock.recv(4096))
                    timer.end()
                    if opts != (1, 0, 0, 0) or ack != self._seq + 1:
                        logger.log("rcv/corr", seq, ack, opts, len(payload))
                        raise ValueError("package not acked")
                    logger.log("rcv", seq, ack, opts, len(payload))
                    self._seq += 1
                    self._ack = seq + len(payload)
                    sock.settimeout(timer.get_timeout())
                    seq, ack, opts, payload = packer.unpacking(sock.recv(4096))
                    if opts != (0, 0, 0, 1) or ack != self._seq:
                        logger.log("rcv/corr", seq, ack, opts, len(payload))
                        raise ValueError("package not acked")
                    logger.log("rcv", seq, ack, opts, len(payload))
                    self._ack = seq + 1
                    pld.send(packer.packing(self._seq, self._ack, (1, 0, 0, 0), ONE_BYTE))
                    break
                except (socket.timeout, ValueError) as err:
                    self._handle_err(err, [self._seq])

            logger.summarize_hook(len(self._payload))

    def set_payload_isn(self):
        ''' set isn for payload as well as initial send window '''
        self._payload_isn = self._seq
        self._fill_send_window(self._seq)

    def get_send_window_len(self):
        ''' return length of data to be sent '''
        if self._payload is None:
            return 0
        return sum(map(lambda x: len(x[1]), self._snd_win))

    def update_send_window(self, ack):
        ''' update send window '''
        self._seq = ack
        self._snd_win = list(filter(lambda x: x[0] + len(x[1]) > ack, self._snd_win))
        if not self._snd_win:
            start_seq = self._seq
        else:
            start_seq = self._snd_win[-1][0] + len(self._snd_win[-1][1])
        self._fill_send_window(start_seq)

    def _fill_send_window(self, start_seq):
        ''' helper function to fill _snd_win buffer '''
        start_offset = start_seq - self._payload_isn
        left_len = self._payload_len - (self._seq - self._payload_isn) - self.get_send_window_len()
        left_win_size = self._mws - self.get_send_window_len()
        snd_win_new_len = min(left_win_size, left_len)
        if snd_win_new_len == 0:
            return
        if snd_win_new_len < self._mss:
            self._snd_win.append((start_seq, self._payload[start_offset:]))
        else:
            fp_num = int(snd_win_new_len / self._mss)
            lp_len = snd_win_new_len % self._mss
            end_offset = start_offset + self._mss
            if start_offset > self._payload_len:
                return
            for _ in range(fp_num):
                self._snd_win.append((start_seq, self._payload[start_offset:end_offset:]))
                start_offset = end_offset
                end_offset += self._mss
                start_seq += self._mss
            if lp_len != 0:
                self._snd_win.append((start_seq, self._payload[start_offset:lp_len:]))

    def _handle_err(self, err, seq_l):
        if isinstance(err, ValueError):
            pass
        else:
            self._logger.set_rf(seq_l)


if __name__ == "__main__":
    if len(sys.argv) != 15:
        print(f"Usage: ./{__file__} receiver_host_ip receiver_port file_name " +
              "MWS MSS gamma pDrop pDuplicate pCorrupt pOrder maxOrder pDelay " +
              "maxDelay seed")
        sys.exit(1)
    D_HOST = str(sys.argv[1])
    D_PORT = int(sys.argv[2])
    F_NAME = str(sys.argv[3])
    MWS = int(sys.argv[4])
    MSS = int(sys.argv[5])
    GAMMA = int(sys.argv[6])
    P_DRP = float(sys.argv[7])
    P_DUP = float(sys.argv[8])
    P_CRP = float(sys.argv[9])
    P_ORD = float(sys.argv[10])
    M_ORD = int(sys.argv[11])
    P_DLY = float(sys.argv[12])
    M_DLY = int(sys.argv[13])
    SEED = int(sys.argv[14])
    F_BYTES = dump_file(F_NAME)
    PLD = PLDModule(P_DRP, P_DUP, P_CRP, P_ORD, M_ORD, P_DLY, M_DLY, SEED)
    SENDER = STPSender(D_HOST, D_PORT, MSS, MWS, GAMMA, PLD)
    SENDER.sending(F_BYTES)
