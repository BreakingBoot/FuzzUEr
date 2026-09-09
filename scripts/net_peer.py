"""A network peer whose every reply is under the fuzzer's control.

The protocol harnesses call a protocol member with fuzzed arguments. That reaches the
API surface of the network stack and almost none of its parsing: what Dhcp4Dxe,
Mtftp4Dxe and UefiPxeBcDxe actually spend their code on is bytes that arrived from
somewhere else. To reach those paths something has to be on the other end of the wire
answering, and answering wrong.

QEMU's socket netdev is that wire. With

    -netdev socket,id=n0,connect=127.0.0.1:<port> -device virtio-net-pci,netdev=n0

the guest's NIC is a TCP stream to this process, framed as a 4 byte big endian length
followed by one raw Ethernet frame. No tap device, no root, no host networking, and the
peer is an ordinary process the fuzzer can drive.

What is implemented is the minimum that gets a UEFI guest to PXE boot -- ARP, ICMP echo,
DHCP and TFTP over IPv4 -- because that is the path with the parsers worth breaking. Each
reply is built correctly and then corrupted from the input bytes, so a run is
reproducible: the same input file produces the same packets.
"""

import argparse
import os
import socket
import struct
import sys
import time

ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
IP_ICMP = 1
IP_UDP = 17

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
TFTP_PORT = 69

DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK = 1, 2, 3, 5


def checksum(data):
    """The one's complement sum every header here needs."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac_bytes(text):
    return bytes(int(part, 16) for part in text.split(':'))


def mac_text(raw):
    return ':'.join(f'{byte:02x}' for byte in raw)


class Mutator:
    """Turns the fuzzer's bytes into decisions, and says what it did.

    Deliberately dull: a byte stream read left to right, wrapping when it runs out. A
    mutation is (which packet, which offset, what value), so a finding replays from the
    same input file rather than from a lucky race.
    """

    def __init__(self, data, per_packet=0, skip=0, labels=None):
        self.data = data or b''
        self.per_packet = per_packet
        self.skip = skip
        # Which replies may be corrupted, by name. Counting packets instead is a trap:
        # the guest sends two read requests -- one to probe tsize, which it then aborts --
        # so the reply a given index lands on moves, and corrupting an OACK ends the
        # transfer before a single DATA block is sent.
        self.labels = labels or []
        self.position = 0
        self.packets_seen = 0
        self.log = []

    def _next(self, count=1):
        if not self.data:
            return b'\x00' * count
        out = bytearray()
        for _ in range(count):
            out.append(self.data[self.position % len(self.data)])
            self.position += 1
        return bytes(out)

    def apply(self, packet, label, protect=0):
        """Corrupt a built reply.

        `protect` keeps the leading headers intact -- corrupting the Ethernet or IP
        header just makes the guest drop the frame, which burns an iteration without
        reaching a parser. The payload is where the parsers are.
        """
        if self.labels and not any(label.startswith(want) for want in self.labels):
            return packet
        self.packets_seen += 1
        if self.per_packet <= 0 or self.packets_seen <= self.skip:
            return packet
        if len(packet) <= protect:
            return packet
        out = bytearray(packet)
        span = len(out) - protect
        for _ in range(self.per_packet):
            raw = self._next(3)
            offset = protect + ((raw[0] << 8 | raw[1]) % span)
            out[offset] = raw[2]
            self.log.append((label, offset, raw[2]))
        return bytes(out)

    def summary(self):
        if not self.log:
            return 'no mutations applied'
        parts = [f'{label}@{offset}={value:#04x}' for label, offset, value in self.log]
        return f'{len(self.log)} mutation(s): ' + ' '.join(parts[:12]) + \
               (' ...' if len(parts) > 12 else '')


class Peer:
    def __init__(self, args, mutator):
        self.args = args
        self.mutator = mutator
        self.my_mac = mac_bytes(args.server_mac)
        self.my_ip = socket.inet_aton(args.server_ip)
        self.client_ip = socket.inet_aton(args.client_ip)
        self.netmask = socket.inet_aton(args.netmask)
        self.client_mac = None
        # keyed by the port we answer from, not the client's: RFC 1350 gives every
        # transfer a fresh server TID, and the client sends its ACKs there. Answering
        # from port 69 got exactly one DATA out and never an ACK back.
        self.tftp = {}
        self.next_tid = 40000
        self.events = []
        self.transfers = 0
        self.blocks_sent = 0
        self.boot_file = args.boot_file.encode()

    def note(self, text):
        self.events.append(text)
        if not self.args.quiet:
            print(f'  {text}', flush=True)

    # ---- framing ---------------------------------------------------------------

    def eth(self, dst, ethertype, payload):
        return dst + self.my_mac + struct.pack('!H', ethertype) + payload

    def ipv4(self, dst_ip, protocol, payload):
        total = 20 + len(payload)
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64,
                             protocol, 0, self.my_ip, dst_ip)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        return header + payload

    def udp(self, src_port, dst_port, payload):
        # checksum 0 is legal for IPv4 UDP and keeps a mutated payload from being
        # rejected by the checksum instead of reaching the parser under test
        return struct.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0) + payload

    # ---- handlers --------------------------------------------------------------

    def handle_arp(self, frame):
        body = frame[14:]
        if len(body) < 28:
            return None
        opcode, = struct.unpack('!H', body[6:8])
        target_ip = body[24:28]
        if opcode != 1 or target_ip != self.my_ip:
            return None
        sender_mac, sender_ip = body[8:14], body[14:18]
        self.client_mac = sender_mac
        self.note(f'ARP who-has {socket.inet_ntoa(target_ip)} from {mac_text(sender_mac)}')
        reply = struct.pack('!HHBBH', 1, ETH_IPV4, 6, 4, 2) + \
            self.my_mac + self.my_ip + sender_mac + sender_ip
        return self.eth(sender_mac, ETH_ARP, reply)

    def handle_icmp(self, frame, src_mac, src_ip, payload):
        if not payload or payload[0] != 8:
            return None
        self.note(f'ICMP echo request from {socket.inet_ntoa(src_ip)}')
        body = b'\x00\x00' + payload[2:]
        body = body[:2] + struct.pack('!H', checksum(b'\x00\x00' + payload[2:])) + body[4:]
        return self.eth(src_mac, ETH_IPV4, self.ipv4(src_ip, IP_ICMP, body))

    def dhcp_options(self, message_type):
        options = bytearray(b'\x63\x82\x53\x63')          # magic cookie
        options += bytes([53, 1, message_type])            # message type
        options += bytes([54, 4]) + self.my_ip             # server identifier
        options += bytes([51, 4]) + struct.pack('!I', 600)  # lease time
        options += bytes([1, 4]) + self.netmask            # subnet mask
        options += bytes([3, 4]) + self.my_ip              # router
        options += bytes([6, 4]) + self.my_ip              # dns
        # PXE wants a boot file; 67 is what UefiPxeBcDxe reads to build the TFTP request
        options += bytes([67, len(self.boot_file) + 1]) + self.boot_file + b'\x00'
        options += bytes([97, 17]) + b'\x00' * 17          # client machine id
        options += b'\xff'
        return bytes(options)

    def handle_dhcp(self, src_mac, payload):
        if len(payload) < 240:
            return None
        op = payload[0]
        if op != 1:
            return None
        xid = payload[4:8]
        chaddr = payload[28:34]
        self.client_mac = chaddr
        request = None
        index = 240
        while index + 1 < len(payload):
            code = payload[index]
            if code == 0xFF:
                break
            if code == 0:
                index += 1
                continue
            length = payload[index + 1]
            if code == 53 and length >= 1:
                request = payload[index + 2]
            index += 2 + length
        if request == DHCP_DISCOVER:
            kind, label = DHCP_OFFER, 'OFFER'
        elif request == DHCP_REQUEST:
            kind, label = DHCP_ACK, 'ACK'
        else:
            return None
        self.note(f'DHCP {"DISCOVER" if request == DHCP_DISCOVER else "REQUEST"} '
                  f'from {mac_text(chaddr)} -> {label}')
        # 236, not 240: op/htype/hlen/hops 4, xid 4, secs+flags 4, ciaddr/yiaddr/siaddr/
        # giaddr 16, chaddr 16, sname 64, file 128. The magic cookie follows immediately,
        # and four bytes of padding in front of it is enough for the client to reject the
        # offer and go back to DISCOVER, which is what it looked like the first time.
        reply = bytearray(236)
        reply[0] = 2                                   # BOOTREPLY
        reply[1] = 1                                   # ethernet
        reply[2] = 6
        reply[4:8] = xid
        reply[16:20] = self.client_ip                  # yiaddr
        reply[20:24] = self.my_ip                      # siaddr, the TFTP server
        reply[28:34] = chaddr
        name = self.boot_file[:127]
        reply[108:108 + len(name)] = name              # legacy boot file field
        packet = bytes(reply) + self.dhcp_options(kind)
        # Protect the 236 byte BOOTP header. Corrupting xid, yiaddr or siaddr makes the
        # client drop the reply and go back to DISCOVER, so the run ends without the
        # option parser -- the part with the interesting code -- having done anything.
        packet = self.mutator.apply(packet, label, protect=236)
        udp = self.udp(DHCP_SERVER_PORT, DHCP_CLIENT_PORT, packet)
        return self.eth(b'\xff' * 6, ETH_IPV4,
                        self.ipv4(b'\xff\xff\xff\xff', IP_UDP, udp))

    def handle_rrq(self, src_mac, src_ip, src_port, payload):
        fields = payload[2:].split(b'\x00')
        name = fields[0].decode(errors='replace') if fields else ''
        options = {}
        rest = fields[1:]
        for index in range(1, len(rest) - 1, 2):
            options[rest[index].lower()] = rest[index + 1]
        blksize = self.args.block_size
        if b'blksize' in options:
            try:
                blksize = max(8, min(1428, int(options[b'blksize'])))
            except ValueError:
                pass
        tid = self.next_tid
        self.next_tid += 1
        blob = self.args.serve_bytes
        self.tftp[tid] = {'client_port': src_port, 'blob': blob, 'blksize': blksize,
                          'mac': src_mac, 'ip': src_ip, 'highest': 0}
        self.note(f'TFTP RRQ {name!r} from port {src_port}, options '
                  f'{[k.decode() for k in options]}, serving {len(blob)} bytes '
                  f'as tid {tid} blksize {blksize}')
        if options:
            # RFC 2347: acknowledge only what we honour, then wait for ACK 0.
            body = b'\x00\x06'
            if b'blksize' in options:
                body += b'blksize\x00' + str(blksize).encode() + b'\x00'
            if b'tsize' in options:
                body += b'tsize\x00' + str(len(blob)).encode() + b'\x00'
            body = self.mutator.apply(body, 'OACK', protect=2)
            udp = self.udp(tid, src_port, body)
            return self.eth(src_mac, ETH_IPV4, self.ipv4(src_ip, IP_UDP, udp))
        return self.tftp_data(tid, 1)

    def handle_tftp_ack(self, tid, payload):
        state = self.tftp.get(tid)
        if state is None or len(payload) < 4:
            return None
        opcode, block = struct.unpack('!HH', payload[:4])
        if opcode == 5:
            self.note(f'TFTP error from the guest on tid {tid}: {payload[4:]!r}')
            self.tftp.pop(tid, None)
            return None
        if opcode != 4:
            return None
        state['highest'] = max(state['highest'], block)
        if block * state['blksize'] >= len(state['blob']):
            self.note(f'TFTP transfer complete on tid {tid}, {block} block(s), '
                      f'{len(state["blob"])} bytes')
            self.tftp.pop(tid, None)
            self.transfers += 1
            return None
        return self.tftp_data(tid, block + 1)

    def tftp_data(self, tid, block):
        state = self.tftp.get(tid)
        if state is None:
            return None
        size = state['blksize']
        start = (block - 1) * size
        chunk = state['blob'][start:start + size]
        body = struct.pack('!HH', 3, block) + chunk
        self.blocks_sent += 1
        body = self.mutator.apply(body, f'DATA{block}', protect=4)
        udp = self.udp(tid, state['client_port'], body)
        return self.eth(state['mac'], ETH_IPV4, self.ipv4(state['ip'], IP_UDP, udp))

    # ---- dispatch --------------------------------------------------------------

    def on_frame(self, frame):
        if len(frame) < 14:
            return None
        src_mac = frame[6:12]
        ethertype, = struct.unpack('!H', frame[12:14])
        if ethertype == ETH_ARP:
            return self.handle_arp(frame)
        if ethertype != ETH_IPV4 or len(frame) < 34:
            return None
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl:
            return None
        protocol = ip[9]
        src_ip, dst_ip = ip[12:16], ip[16:20]
        body = ip[ihl:]
        if protocol == IP_ICMP:
            return self.handle_icmp(frame, src_mac, src_ip, body)
        if protocol != IP_UDP or len(body) < 8:
            return None
        src_port, dst_port = struct.unpack('!HH', body[:4])
        udp_payload = body[8:]
        if dst_port == DHCP_SERVER_PORT:
            return self.handle_dhcp(src_mac, udp_payload)
        if dst_port == TFTP_PORT and udp_payload[:2] == b'\x00\x01':
            return self.handle_rrq(src_mac, src_ip, src_port, udp_payload)
        if dst_port in self.tftp:
            return self.handle_tftp_ack(dst_port, udp_payload)
        return None


def serve(args):
    seed = b''
    if args.input and os.path.isfile(args.input):
        with open(args.input, 'rb') as handle:
            seed = handle.read()
    labels = [part.strip() for part in args.mutate_labels.split(',') if part.strip()]
    mutator = Mutator(seed, args.mutate, args.skip_packets, labels)
    peer = Peer(args, mutator)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    if args.ready_file:
        with open(args.ready_file, 'w') as handle:
            handle.write(str(args.port))
    if not args.quiet:
        print(f'net_peer listening on {args.host}:{args.port} '
              f'(server {args.server_ip}, client {args.client_ip}, '
              f'{args.mutate} mutation(s) per reply, '
              f'targets {labels or ["all"]})', flush=True)

    listener.settimeout(args.accept_timeout)
    try:
        stream, _ = listener.accept()
    except socket.timeout:
        print('no guest connected before the accept timeout', file=sys.stderr)
        return 2
    stream.settimeout(1.0)

    deadline = time.time() + args.duration
    buffer = b''
    frames = 0
    try:
        while time.time() < deadline:
            try:
                chunk = stream.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            while len(buffer) >= 4:
                length, = struct.unpack('!I', buffer[:4])
                if length > 65535 or len(buffer) < 4 + length:
                    break
                frame, buffer = buffer[4:4 + length], buffer[4 + length:]
                frames += 1
                try:
                    reply = peer.on_frame(frame)
                except Exception as error:            # a malformed frame is data, not a bug
                    peer.note(f'ignored a frame that did not parse: {error}')
                    reply = None
                if reply:
                    stream.sendall(struct.pack('!I', len(reply)) + reply)
    finally:
        stream.close()
        listener.close()

    print(f'frames in: {frames}')
    print(f'exchanges: {len(peer.events)}')
    print(f'tftp blocks sent: {peer.blocks_sent}, transfers completed: {peer.transfers}')
    print(mutator.summary())
    if args.event_file:
        with open(args.event_file, 'w') as handle:
            handle.write('\n'.join(peer.events) + '\n')
    # A guest that never spoke is a broken setup, not a clean run.
    return 0 if frames else 3


def main():
    parser = argparse.ArgumentParser(
        description='A fuzzer controlled network peer for a QEMU guest')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5555)
    parser.add_argument('--server-ip', default='10.0.2.2')
    parser.add_argument('--client-ip', default='10.0.2.15')
    parser.add_argument('--netmask', default='255.255.255.0')
    parser.add_argument('--server-mac', default='52:54:00:aa:bb:cc')
    parser.add_argument('--boot-file', default='bootx64.efi')
    parser.add_argument('--serve-size', type=int, default=4096,
                        help='bytes to hand out over TFTP when no --serve-file is given')
    parser.add_argument('--serve-file', default='',
                        help='a real UEFI application to hand out as the boot file. '
                             'Worth doing: with synthetic bytes the guest rejects the '
                             'image and stops at the loader, whereas a valid one is '
                             'executed, so the PE parser and everything the application '
                             'itself touches come into range of a mutation')
    parser.add_argument('--block-size', type=int, default=512)
    parser.add_argument('--input', default='',
                        help='fuzzer bytes; the same file replays the same packets')
    parser.add_argument('--mutate', type=int, default=0,
                        help='byte mutations applied to each reply')
    parser.add_argument('--mutate-labels', default='',
                        help='comma separated reply names to corrupt, matched as '
                             'prefixes: OFFER, ACK, OACK, DATA. Empty means all of them. '
                             'DATA alone fuzzes the served image and the block handling; '
                             'OFFER,ACK fuzzes the DHCP option parser')
    parser.add_argument('--skip-packets', type=int, default=0,
                        help='leave the first N replies alone, so the guest gets far '
                             'enough in the exchange to reach the parser under test')
    parser.add_argument('--duration', type=float, default=120)
    parser.add_argument('--accept-timeout', type=float, default=60)
    parser.add_argument('--ready-file', default='')
    parser.add_argument('--event-file', default='')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args()
    if args.serve_file:
        with open(args.serve_file, 'rb') as handle:
            args.serve_bytes = handle.read()
    else:
        # a recognisable payload, so a guest that writes it somewhere is easy to spot
        args.serve_bytes = (b'FIRNESSNETPEER' * ((args.serve_size // 14) + 1))[:args.serve_size]
    return serve(args)


if __name__ == '__main__':
    sys.exit(main())
