import argparse
import pickle
import sys
import signal
import socket
import struct
import threading
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 7777

ACTIVE_CONNECTIONS = []


# https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=v5.4.222&id=ee9952831cfd0bbe834f4a26489d7dce74582e37
TCP_REPAIR = 19
TCP_REPAIR_QUEUE = 20
TCP_QUEUE_SEQ =	21
TCP_REPAIR_OPTIONS = 22
TCP_TIMESTAMP = 24
TCP_REPAIR_WINDOW = 29

TCP_NO_QUEUE = 0
TCP_RECV_QUEUE = 1
TCP_SEND_QUEUE = 2
TCP_QUEUES_NR = 3

ENABLE_REPAIR = 1
DISABLE_REPAIR = 0

TCPOPT_MSS = 2
TCPOPT_WINDOW = 3
TCPOPT_SACK_PERM = 4
TCPOPT_TIMESTAMP = 8

# struct tcp_repair_window {
# 	__u32	snd_wl1;
# 	__u32	snd_wnd;
# 	__u32	max_window;

# 	__u32	rcv_wnd;
# 	__u32	rcv_wup;
# };

WINDOW_STRUCT_SIZE = struct.calcsize('III II'.replace(' ', ''))

INFO_STRUCT_FORMAT = 'BBBBBBBB IIII IIIII IIII IIIIIIII II I QQQ Q II IIII Q QQ Q II Q QII I I'.replace(' ', '')
INFO_STRUCT_SIZE = struct.calcsize(INFO_STRUCT_FORMAT)

# TODO: I just copied this from /usr/include/linux/tcp.h
# but this is error-prone (it is specific to this kernel version), see if we can load this with ctypes or a c extension instead
# struct tcp_info {
# 	__u8	tcpi_state;
# 	__u8	tcpi_ca_state;
# 	__u8	tcpi_retransmits;
# 	__u8	tcpi_probes;
# 	__u8	tcpi_backoff;
# 	__u8	tcpi_options;
# 	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
# 	__u8	tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

# 	__u32	tcpi_rto;
# 	__u32	tcpi_ato;
# 	__u32	tcpi_snd_mss;
# 	__u32	tcpi_rcv_mss;

# 	__u32	tcpi_unacked;
# 	__u32	tcpi_sacked;
# 	__u32	tcpi_lost;
# 	__u32	tcpi_retrans;
# 	__u32	tcpi_fackets;

# 	/* Times. */
# 	__u32	tcpi_last_data_sent;
# 	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
# 	__u32	tcpi_last_data_recv;
# 	__u32	tcpi_last_ack_recv;

# 	/* Metrics. */
# 	__u32	tcpi_pmtu;
# 	__u32	tcpi_rcv_ssthresh;
# 	__u32	tcpi_rtt;
# 	__u32	tcpi_rttvar;
# 	__u32	tcpi_snd_ssthresh;
# 	__u32	tcpi_snd_cwnd;
# 	__u32	tcpi_advmss;
# 	__u32	tcpi_reordering;

# 	__u32	tcpi_rcv_rtt;
# 	__u32	tcpi_rcv_space;

# 	__u32	tcpi_total_retrans;

# 	__u64	tcpi_pacing_rate;
# 	__u64	tcpi_max_pacing_rate;
# 	__u64	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
# 	__u64	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
# 	__u32	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
# 	__u32	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

# 	__u32	tcpi_notsent_bytes;
# 	__u32	tcpi_min_rtt;
# 	__u32	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
# 	__u32	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

# 	__u64   tcpi_delivery_rate;

# 	__u64	tcpi_busy_time;      /* Time (usec) busy sending data */
# 	__u64	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
# 	__u64	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

# 	__u32	tcpi_delivered;
# 	__u32	tcpi_delivered_ce;

# 	__u64	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
# 	__u64	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
# 	__u32	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
# 	__u32	tcpi_reord_seen;     /* reordering events seen */

# 	__u32	tcpi_rcv_ooopack;    /* Out-of-order packets received */

# 	__u32	tcpi_snd_wnd;	     /* peer's advertised receive window after
# 				      * scaling (bytes)
# 				      */
# };

def get_repair_options_payload(state):
    repair_opt_struct_format = 'II'
    payload = struct.pack(repair_opt_struct_format*2,
                       TCPOPT_MSS, int.from_bytes(state['mss_clamp'], 'big'),
                       TCPOPT_WINDOW, state['wscale_ok'],
    )
    if state['is_sack']:
        payload += struct.pack(repair_opt_struct_format, TCPOPT_SACK_PERM, 0)
    if state['tstamp_ok']:
        payload += struct.pack(repair_opt_struct_format, TCPOPT_TIMESTAMP, 0)
    return payload

def freeze_socket(sock):
    state = {}
    # these settings don't need repair mode enabled to read
    state['local_addr'] = sock.getsockname()
    state['remote_addr'] = sock.getpeername()
    state['mss'] = sock.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, 2)

    # place the socket into repair mode and return the data needed to restore it
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR, ENABLE_REPAIR)

    info = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, INFO_STRUCT_SIZE)
    values = struct.unpack(INFO_STRUCT_FORMAT, info)
    options = values[5] # tcpi_options
    state['tstamp_ok'] = options & 0b00000001 # bit 0
    state['is_sack'] = options & 0b00000010   # bit 1
    state['wscale_ok'] = options & 0b00000100 # bit 2

    state['mss_clamp'] = sock.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, 2)
    state['timestamp'] = sock.getsockopt(socket.SOL_TCP, TCP_TIMESTAMP, 4)
    state['window'] = sock.getsockopt(socket.SOL_TCP, TCP_REPAIR_WINDOW, WINDOW_STRUCT_SIZE)

    # read the send queue contents + sequence numbers
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
    state['send_seqno'] = sock.getsockopt(socket.SOL_TCP, TCP_QUEUE_SEQ, 4)

    _, send_queue_contents, _, _ = sock.recvmsg(0, 4096, socket.MSG_PEEK)
    state['send_queue'] = send_queue_contents

    # read the recv queue contents + sequence numbers
    # TODO: calculate ancbufsize?
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
    state['recv_seqno'] = sock.getsockopt(socket.SOL_TCP, TCP_QUEUE_SEQ, 4)

    # TODO: it seems like this blocks indefinitely if nothing has ever been received
    # _, recv_queue_contents, _, _ = sock.recvmsg(0, 4096, socket.MSG_PEEK)
    state['recv_queue'] = []

    # closing the socket doesn't impact the peer when it's in repair mode
    sock.close()
    return state

def thaw_socket(state):
    # restore a socket from the saved data and return it
    sock = socket.socket()
    sock.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, int.from_bytes(state['mss'], 'big'))

    # set repair mode
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR, ENABLE_REPAIR)
    sock.setsockopt(socket.SOL_TCP, TCP_TIMESTAMP, state['timestamp'])

    # bind to port number
    sock.bind(state['local_addr'])

    # restore send queue contents + sequence number
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
    if state['send_queue']:
        sock.sendmsg([], state['send_queue'])
    sock.setsockopt(socket.SOL_TCP, TCP_QUEUE_SEQ, state['send_seqno'])

    # restore receive queue contents + sequence number
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
    if state['recv_queue']:
        sock.sendmsg([], state['recv_queue'])
    sock.setsockopt(socket.SOL_TCP, TCP_QUEUE_SEQ, state['recv_seqno'])

    # set options for MSS, window size, selective ack feature, timestamp feature
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_WINDOW, state['window'])

    # re-connect to the remote host and disable repair mode
    sock.connect(state['remote_addr'])
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_OPTIONS, get_repair_options_payload(state))
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR, DISABLE_REPAIR)
    return sock


def cleanup(state_file_path):
    print('saving connection state')
    records = [freeze_socket(sock) for sock in ACTIVE_CONNECTIONS]
    with open(state_file_path, 'wb') as fout:
        pickle.dump(records, fout)
    print('saved connection state to {}'.format(state_file_path))


def service_connection(sock):
    try:
        # periodically write some data
        while True:
            time.sleep(2)
            with open('/proc/loadavg', 'rb') as fin:
                data = fin.read()
            sock.sendall(data)
    except Exception:
        pass
    finally:
        ACTIVE_CONNECTIONS.remove(sock)


def init_conn(sock):
    ACTIVE_CONNECTIONS.append(sock)
    threading.Thread(target=service_connection, args=(sock,), daemon=True).start()


if __name__ == '__main__':
    # first start by restoring any stored connections
    parser = argparse.ArgumentParser()
    parser.add_argument('connection_state', help='The path to stored connections to restore')
    args = parser.parse_args()


    # have to bind the listener socket before restoring any of the saved connections
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((SERVER_HOST, SERVER_PORT))
    listener.listen()

    print('restoring connections')
    try:
        with open(args.connection_state, 'rb') as f:
            records = pickle.load(f)
    except IOError:
        print('No state to restore')
    else:
        for record in records:
            sock = thaw_socket(record)
            init_conn(sock)
        print('finished restoring connections')
        # TODO: rm state file now


    # also on shutdown we need to freeze any active connections
    def term_handler(signo, frame):
        # block the signal while we're shutting down
        # to prevent multiple invocations
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        # stop listening for new connections
        listener.close()

        cleanup(args.connection_state)
        sys.exit(0)

    signal.signal(signal.SIGTERM, term_handler)

    print('listening for new connections')
    try:
        while True:
            sock, addr = listener.accept()
            init_conn(sock)
    except KeyboardInterrupt:
        print('stopping')
    finally:
        listener.close()
