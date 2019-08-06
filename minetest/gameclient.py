from .connection import Connection
from . import gameprotocol
import logging

class GameClient:
    def __init__(self, address):
        self.address = address
        self.connection = Connection(address)

        logging.info('lel %s', gameprotocol.packet_mapping)

    def run_loop(self):
        while True:
            packet = self.connection.packets.get()
            self.__on_packet(packet)

    def __on_packet(self, packet):
        logging.info('[RAW packet] %s', packet)
