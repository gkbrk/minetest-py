from collections import namedtuple
import struct

class Packet:
    pass

class ToServer_Init(Packet):
    def __init__(self, player_name):
        self.player_name = player_name

    def encode(self):
        return struct.pack(f'>HBHHHH{len(self.player_name)}s', 0x2, 28, 0, 37, 37, len(self.player_name), self.player_name.encode('utf-8'))

packet_mapping = {
    0x02: ToServer_Init
}
