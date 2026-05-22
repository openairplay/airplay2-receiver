"""
PTPv2 (IEEE 1588-2008) message codec.

Implements the subset of message types needed for an ordinary clock running in
SLAVE state on the AirPlay 2 timing path: Announce, Sync, Follow_Up, Delay_Req,
Delay_Resp. Other PTP message types (Pdelay_*, Signaling, Management) are
parsed only to the extent of recognising their type so they can be ignored.

All wire fields are network byte order (big endian). Timestamps are encoded as
seconds_msb(2) || seconds_lsb(4) || nanoseconds(4) = 10 bytes, holding seconds
since the PTP epoch (1970-01-01) — but for AirPlay slaves we treat them as
opaque master-clock values, since the sender's grand-master typically
advertises its own monotonic uptime, not real wall time.
"""

import enum
import struct
from dataclasses import dataclass, field


PTP_HEADER_LEN = 34
PTP_TS_LEN = 10
PTP_CLOCK_IDENTITY_LEN = 8
PTP_PORT_IDENTITY_LEN = 10

PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320


class MsgType(enum.IntEnum):
    SYNC = 0x0
    DELAY_REQ = 0x1
    PDELAY_REQ = 0x2
    PDELAY_RESP = 0x3
    FOLLOW_UP = 0x8
    DELAY_RESP = 0x9
    PDELAY_RESP_FOLLOW_UP = 0xA
    ANNOUNCE = 0xB
    SIGNALING = 0xC
    MANAGEMENT = 0xD


class FlagBit(enum.IntFlag):
    """Subset of PTP header flagField bits relevant to a slave."""
    TWO_STEP = 0x0200       # byte 6 bit 1
    UNICAST = 0x0400        # byte 6 bit 2
    PROFILE_SPECIFIC_1 = 0x2000
    PROFILE_SPECIFIC_2 = 0x4000
    ALTERNATE_MASTER = 0x0100


@dataclass
class PortIdentity:
    clock_identity: bytes  # 8 bytes
    port_number: int       # uint16

    def pack(self) -> bytes:
        assert len(self.clock_identity) == PTP_CLOCK_IDENTITY_LEN
        return self.clock_identity + struct.pack("!H", self.port_number)

    @classmethod
    def unpack(cls, buf: bytes) -> "PortIdentity":
        assert len(buf) >= PTP_PORT_IDENTITY_LEN
        return cls(
            clock_identity=bytes(buf[0:8]),
            port_number=struct.unpack("!H", buf[8:10])[0],
        )

    def __hash__(self):
        return hash((self.clock_identity, self.port_number))


def pack_timestamp(ns: int) -> bytes:
    """Encode an integer nanosecond value as a 10-byte PTP timestamp.

    seconds_msb (16b) || seconds_lsb (32b) || nanoseconds (32b)
    """
    secs, nsecs = divmod(ns, 1_000_000_000)
    secs_msb = (secs >> 32) & 0xFFFF
    secs_lsb = secs & 0xFFFFFFFF
    return struct.pack("!HII", secs_msb, secs_lsb, nsecs)


def unpack_timestamp(buf: bytes) -> int:
    """Decode a 10-byte PTP timestamp to integer nanoseconds."""
    assert len(buf) >= PTP_TS_LEN
    secs_msb, secs_lsb, nsecs = struct.unpack("!HII", buf[0:10])
    secs = (secs_msb << 32) | secs_lsb
    return secs * 1_000_000_000 + nsecs


@dataclass
class PtpHeader:
    """Common 34-byte PTPv2 header."""
    message_type: int                  # 4 bits (we keep low nibble)
    transport_specific: int = 0        # 4 bits
    version: int = 2                   # 4 bits
    message_length: int = 0
    domain_number: int = 0
    flags: int = 0                     # uint16
    correction_ns: int = 0             # int64 carrying ns << 16 (sub-ns ignored)
    source_port_identity: PortIdentity = field(
        default_factory=lambda: PortIdentity(b"\x00" * 8, 0)
    )
    sequence_id: int = 0
    control_field: int = 0
    log_message_interval: int = 0      # int8

    @classmethod
    def unpack(cls, buf: bytes) -> "PtpHeader":
        if len(buf) < PTP_HEADER_LEN:
            raise ValueError(f"ptp header too short: {len(buf)}")
        b0 = buf[0]
        b1 = buf[1]
        msg_type = b0 & 0x0F
        transport_specific = (b0 >> 4) & 0x0F
        version = b1 & 0x0F
        message_length = struct.unpack("!H", buf[2:4])[0]
        domain_number = buf[4]
        flags = struct.unpack("!H", buf[6:8])[0]
        # correctionField: 64-bit signed, scaled ns (low 16 bits = sub-ns)
        correction_scaled = struct.unpack("!q", buf[8:16])[0]
        correction_ns = correction_scaled >> 16
        # reserved 4 bytes at 16:20
        source_port_identity = PortIdentity.unpack(buf[20:30])
        sequence_id = struct.unpack("!H", buf[30:32])[0]
        control_field = buf[32]
        log_message_interval = struct.unpack("!b", buf[33:34])[0]
        return cls(
            message_type=msg_type,
            transport_specific=transport_specific,
            version=version,
            message_length=message_length,
            domain_number=domain_number,
            flags=flags,
            correction_ns=correction_ns,
            source_port_identity=source_port_identity,
            sequence_id=sequence_id,
            control_field=control_field,
            log_message_interval=log_message_interval,
        )


def pack_header_bytes(h: PtpHeader) -> bytes:
    """Pack header to its exact 34-byte wire form."""
    b0 = ((h.transport_specific & 0x0F) << 4) | (h.message_type & 0x0F)
    b1 = h.version & 0x0F
    # correctionField wire encoding: signed int64 in units of (2^-16) ns
    correction_scaled = int(h.correction_ns) * 65536
    if correction_scaled > (1 << 63) - 1:
        correction_scaled = (1 << 63) - 1
    elif correction_scaled < -(1 << 63):
        correction_scaled = -(1 << 63)
    out = bytearray(PTP_HEADER_LEN)
    out[0] = b0
    out[1] = b1
    struct.pack_into("!H", out, 2, h.message_length)
    out[4] = h.domain_number
    out[5] = 0
    struct.pack_into("!H", out, 6, h.flags & 0xFFFF)
    struct.pack_into("!q", out, 8, correction_scaled)
    # 16:20 reserved zeros
    out[20:30] = h.source_port_identity.pack()
    struct.pack_into("!H", out, 30, h.sequence_id & 0xFFFF)
    out[32] = h.control_field & 0xFF
    struct.pack_into("!b", out, 33, h.log_message_interval)
    return bytes(out)


@dataclass
class AnnounceBody:
    origin_timestamp_ns: int
    current_utc_offset: int
    grandmaster_priority1: int
    grandmaster_clock_quality: bytes  # 4 bytes raw
    grandmaster_priority2: int
    grandmaster_identity: bytes       # 8 bytes
    steps_removed: int
    time_source: int

    @classmethod
    def unpack(cls, buf: bytes) -> "AnnounceBody":
        if len(buf) < 30:
            raise ValueError("announce body too short")
        ts_ns = unpack_timestamp(buf[0:10])
        utc_offset = struct.unpack("!h", buf[10:12])[0]
        # reserved byte 12
        prio1 = buf[13]
        clock_quality = bytes(buf[14:18])
        prio2 = buf[18]
        gm_identity = bytes(buf[19:27])
        steps_removed = struct.unpack("!H", buf[27:29])[0]
        time_source = buf[29]
        return cls(
            origin_timestamp_ns=ts_ns,
            current_utc_offset=utc_offset,
            grandmaster_priority1=prio1,
            grandmaster_clock_quality=clock_quality,
            grandmaster_priority2=prio2,
            grandmaster_identity=gm_identity,
            steps_removed=steps_removed,
            time_source=time_source,
        )


@dataclass
class SyncBody:
    origin_timestamp_ns: int

    @classmethod
    def unpack(cls, buf: bytes) -> "SyncBody":
        return cls(origin_timestamp_ns=unpack_timestamp(buf[0:10]))


@dataclass
class FollowUpBody:
    precise_origin_timestamp_ns: int

    @classmethod
    def unpack(cls, buf: bytes) -> "FollowUpBody":
        return cls(precise_origin_timestamp_ns=unpack_timestamp(buf[0:10]))


@dataclass
class DelayReqBody:
    origin_timestamp_ns: int = 0

    def pack(self) -> bytes:
        return pack_timestamp(self.origin_timestamp_ns)


@dataclass
class DelayRespBody:
    receive_timestamp_ns: int
    requesting_port_identity: PortIdentity

    @classmethod
    def unpack(cls, buf: bytes) -> "DelayRespBody":
        rx_ts = unpack_timestamp(buf[0:10])
        req_port = PortIdentity.unpack(buf[10:20])
        return cls(receive_timestamp_ns=rx_ts, requesting_port_identity=req_port)


@dataclass
class PtpMessage:
    """A parsed PTP message: header plus its decoded body (or None)."""
    header: PtpHeader
    body: object  # one of AnnounceBody | SyncBody | FollowUpBody | DelayRespBody | None
    raw: bytes

    @property
    def msg_type(self) -> int:
        return self.header.message_type


def parse(buf: bytes) -> PtpMessage:
    """Parse one PTP datagram. Unknown types parsed to header only."""
    header = PtpHeader.unpack(buf)
    payload = buf[PTP_HEADER_LEN:]
    body = None
    mt = header.message_type
    try:
        if mt == MsgType.SYNC:
            body = SyncBody.unpack(payload)
        elif mt == MsgType.FOLLOW_UP:
            body = FollowUpBody.unpack(payload)
        elif mt == MsgType.ANNOUNCE:
            body = AnnounceBody.unpack(payload)
        elif mt == MsgType.DELAY_RESP:
            body = DelayRespBody.unpack(payload)
    except (struct.error, ValueError):
        body = None
    return PtpMessage(header=header, body=body, raw=buf)


def build_delay_req(
    src_port_identity: PortIdentity,
    sequence_id: int,
    domain_number: int = 0,
) -> bytes:
    """Build a Delay_Req message. originTimestamp is zeroed; the receiver-side
    t1 timestamp is captured locally at send time and matched to the
    Delay_Resp by sequenceId."""
    header = PtpHeader(
        message_type=MsgType.DELAY_REQ,
        transport_specific=0,
        version=2,
        message_length=PTP_HEADER_LEN + PTP_TS_LEN,
        domain_number=domain_number,
        flags=0,
        correction_ns=0,
        source_port_identity=src_port_identity,
        sequence_id=sequence_id & 0xFFFF,
        control_field=0x01,    # legacy "Delay_Req"
        log_message_interval=0x7F,  # 0x7F == "unspecified"
    )
    return pack_header_bytes(header) + DelayReqBody().pack()
