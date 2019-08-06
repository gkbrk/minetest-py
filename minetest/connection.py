#!/usr/bin/env python3
import socket
import struct
import logging
import queue
from collections import namedtuple
from enum import Enum
import io
import json
import threading
import time
import random

from .gameprotocol import ToServer_Init


LowPacket = namedtuple("LowPacket", "version peer_id channel packet")
Reliable = namedtuple("Reliable", "seqnum packet")
Control = namedtuple("Control", "controltype controldata")
Split = namedtuple("Split", "seqnum count current data")
Unique = namedtuple("Unique", "packet")


class ControlType:
    ACK = "ACK"
    SET_PEER_ID = "SET_PEER_ID"
    PING = "PING"
    DISCO = "DISCO"

    def new(control_type):
        if control_type == 0:
            return ControlType.ACK
        if control_type == 1:
            return ControlType.SET_PEER_ID
        if control_type == 2:
            return ControlType.PING
        if control_type == 3:
            return ControlType.DISCO

    def to(control_type):
        if control_type == ControlType.ACK:
            return 0
        if control_type == ControlType.SET_PEER_ID:
            return 1
        if control_type == ControlType.PING:
            return 2
        if control_type == ControlType.DISCO:
            return 3


def __unpack(stream, fmt):
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    data = struct.unpack(fmt, buf)
    if len(data) == 1:
        return data[0]
    return data


def parse_lowpacket(buf):
    buf = io.BytesIO(buf)
    packet = __unpack(buf, ">IHB")
    packet = LowPacket(*packet, parse_packet(buf.read()))

    assert packet.version == 0x4F457403

    return packet


def parse_packet(buf):
    buf = io.BytesIO(buf)
    packet_type = __unpack(buf, ">B")

    if packet_type == 0:
        control_type = ControlType.new(__unpack(buf, ">B"))
        control_data = None
        if control_type in (ControlType.ACK, ControlType.SET_PEER_ID):
            control_data = __unpack(buf, ">H")
        return Control(control_type, control_data)

    if packet_type == 1:
        return Unique(buf.read())

    if packet_type == 2:
        return Split(__unpack('>HHH'), buf.read())

    if packet_type == 3:
        return Reliable(__unpack(buf, ">H"), parse_packet(buf.read()))


def serialize_packet(packet):
    if isinstance(packet, Control):
        if packet.controldata is not None:
            return struct.pack(
                ">BBH", 0, ControlType.to(packet.controltype), packet.controldata
            )
        else:
            return struct.pack(">BB", 0, ControlType.to(packet.controltype))

    if isinstance(packet, Unique):
        ser = serialize_packet(packet.packet)
        return struct.pack(f">B{len(ser)}s", 1, ser)

    if isinstance(packet, LowPacket):
        ser = serialize_packet(packet.packet)
        return struct.pack(
            f">IHB{len(ser)}s", packet.version, packet.peer_id, packet.channel, ser
        )

    if isinstance(packet, Reliable):
        ser = serialize_packet(packet.packet)
        return struct.pack(f">BH{len(ser)}s", 3, packet.seqnum, ser)

    if isinstance(packet, bytes):
        return packet

    if packet == None:
        return b""


class Connection:
    def __init__(self, address):
        self.address = address
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer_id = 0
        self.packets = queue.Queue()

        logging.info("Creating connection for %s", address)

    def begin(self):
        self.send_to_channel(Reliable(65500, Unique(b"\x00\x00")))

    def send_to_channel(self, packet=None, channel=0):
        packet = LowPacket(0x4F457403, self.peer_id, channel, packet)
        logging.info("[SEND] %s", packet)
        self.sock.sendto(serialize_packet(packet), self.address)
        logging.info("[SEND] %s", serialize_packet(packet).hex())

    def recv_loop(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            packet = parse_lowpacket(data)
            logging.info("[RECV] %s", packet)
            logging.info("[RECV] %s", data.hex())

            self.__on_packet(packet.packet)

    def __on_packet(self, packet):
        if isinstance(packet, Unique):
            self.packets.put(packet.packet)

        if isinstance(packet, Unique) or isinstance(packet, Reliable):
            self.__on_packet(packet.packet)

        if isinstance(packet, Control) and packet.controltype == ControlType.SET_PEER_ID:
            self.peer_id = packet.controldata

            self.send_to_channel(Unique(ToServer_Init("test").encode()), channel=0)

        if isinstance(packet, Reliable):
            self.send_to_channel(Control(ControlType.ACK, packet.seqnum))
