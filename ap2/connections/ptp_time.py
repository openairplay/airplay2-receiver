"""
# Simple, naïve PTP implementation in Python

# Basic listening and sync ability. Listens only to UDP unicast on ports 319+20.
# - systemcrash 2021
# Airplay only cares about *relative* sync, as does this implementation.
# No absolute or NTP references. It currently only slaves to other master clocks
# and follows the PTP election mechanism for grand masters, then syncs to those.
# This implementation also assumes subDomain is 0.
# Apple Airplay uses unicast, not multi. It is specified in e.g.:
# Apple Vendor PTP Profile 2017
# License: GPLv2

Most behaviour in here is derived from PTP within AirPlay. Assume that Apple has its own
PTP Profile. So unless otherwise stated here, the values here apply to Apple's profile.

"""

import socket
import select
import threading
import multiprocessing
import enum
from enum import Flag
import random
import time
from collections import deque

"""
# UDP dest port: 319 for Sync, Delay_Req, Pdelay_Req, Pdelay_Resp;
# UDP dest port: 320 for other messages.
# Sources for this implementation:
# http://www.chronos.co.uk/files/pdfs/cal/TechnicalBrief-IEEE1588v2PTP.pdf
# http://ithitman.blogspot.com/2015/03/precision-time-protocol-ptp-demystified.html
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ptp.c
# https://github.com/ptpd/ptpd/tree/master/src
# https://www.nist.gov/system/files/documents/el/isd/ieee/tutorial-basic.pdf
# https://www.ieee802.org/1/files/public/docs2008/as-garner-1588v2-summary-0908.pdf
# in 2 step, we see Announce, Del_req, Del_resp, Followup, Sig, Sync


# port 319/320 UDP
# first 4 bytes of PTP packets
self.v1_compat  # 4 bits
self.msg_type  # 4 bits
# self.reserved00  # 1 byte
self.ptp_version  # 1 byte
self.msgLength  # 2 bytes
self.subdomainNumber  # 1 byte
self.reserved01  # 1 byte
self.flags  # 2 bytes = 16 bits
self.correctionNanoseconds  # 6 bytes = 48 bits
self.correctionSubNanoseconds  # 2 bytes = 16 bits
self.reserved02  # 4 bytes
self.ClockIdentity  # 8 bytes - typically sender mac, often with fffe in the middle
self.SourcePortID  # 2 bytes = 16 bits
self.sequenceID  # 2 bytes = 16 bits
self.control  # 1 byte
self.logMessagePeriod  # 1 byte
# Delay_Req message
self.originTimestampSec  # 6 bytes - seconds
self.originTimestampNanoSec  # 4 bytes - nanoseconds
# Delay_Resp message
self.rcvTimestampSec  # 6 bytes - seconds
self.rcvTimestampNanoSec  # 4 bytes - nanoseconds
self.requestingSrcPortIdentity  # 8 bytes - mac address
self.requestingSrcPortID  # 2 bytes - port number
# Signalling message
self.targetPortIdentity  # 8 bytes - mac address
self.targetPortID # 2 bytes - port number
self.tlvType  # 2 bytes
self.tlvLen  # 2 bytes
self.orgId  # 3 bytes (first half of mac)
self.orgSubType  # 3 bytes = 01
"""

"""
Apple PTP Limits
ppmLimit 10000
ppmNumerator 10000
ppmDenominator 1000000
filter shift 8

"""


class MsgType(enum.Enum):
    def __str__(self):
        # when we enumerate, only print the msg name w/o class:
        return self.name
    # 0x00-0x03 require time stamping
    SYNC                      = 0x00
    # receiver sends del_reqs message to figure out xceive delay
    DELAY_REQ                 = 0x01
    # path_del only for asymmetric routing topo
    PATH_DELAY_REQ            = 0x02
    PATH_DELAY_RESP           = 0x03
    # 0x08-0x0d do not require time stamping
    # time increment since last msg - offset
    FOLLOWUP                  = 0x08
    # sender gets del_resp to calculate RTT delay
    DELAY_RESP                = 0x09
    PATH_DELAY_FOLLOWUP       = 0x0A
    # Ann declares clock and type
    ANNOUNCE                  = 0x0B
    SIGNALLING                = 0x0C
    MANAGEMENT                = 0x0D


class GMCAccuracy(enum.Enum):
    def __str__(self):
        return self.name
    # GM = GrandMaster
    # 00-1F - reserved
    nS25                    = 0x20  # 25 nanosec
    nS100                   = 0x21
    nS250                   = 0x22
    µS1                     = 0x23  # 1 microsec
    µS2_5                   = 0x24
    µS10                    = 0x25
    µS25                    = 0x26
    µS100                   = 0x27
    µS250                   = 0x28
    mS1                     = 0x29  # 1 millisec
    mS2_5                   = 0x2A
    mS10                    = 0x2B
    mS25                    = 0x2C
    mS100                   = 0x2D
    mS250                   = 0x2E
    S1                      = 0x2F  # 1 sec
    S10                     = 0x30
    GTS10                   = 0x31  # >10sec
    # 32-7F reserved
    # 80-FD profiles
    UNKNOWN                 = 0xFE
    RESERVED                = 0XFF


class ClkSource(enum.Enum):
    def __str__(self):
        return self.name
    ATOMIC                  = 0X10
    GPS                     = 0x20
    TERRESTRIAL_RADIO       = 0x30
    PTP_EXTERNAL            = 0x40
    NTP_EXTERNAL            = 0x50
    HAND_SET                = 0x60
    OTHER                   = 0x90
    INTERNAL_OSCILLATOR     = 0xA0
    # F0-FE - PROFILES
    # FF - Reserved


class ClkClass(enum.Enum):
    def __str__(self):
        return self.name
    # RESERVED 000-005
    PRIMARY_REF_LOCKED      = 6
    PRIMARY_REF_UNLOCKED    = 7
    LOCKED_TO_APP_SPECIFIC  = 13
    UNLOCKD_FR_APP_SPECIFIC = 14
    PRC_UNLOCKED_DESYNC     = 52
    APP_UNLOCKED_DESYNC     = 58
    PRC_UNLOCKED_DESYNC_ALT = 187
    APP_UNLOCKED_DESYNC_ALT = 193
    # RESERVED 194-215
    # Profiles 216-232
    # RESERVED 233-247
    DEFAULT                 = 248
    # RESERVED 249-254
    SLAVE_ONLY              = 255


class TLVType(enum.Enum):
    def __str__(self):
        return self.name
    RESERVED                    = 0x0000
    # standard:
    MANAGEMENT                  = 0x0001
    MANAGEMENT_ERROR_STATUS     = 0x0002
    ORGANIZATION_EXTENSION      = 0x0003
    # optional:
    REQUEST_UNICAST_XMISSION    = 0x0004
    GRANT_UNICAST_XMISSION      = 0x0005
    CANCEL_UNICAST_XMISSION     = 0x0006
    ACK_CANCEL_UNICAST_XMISSION = 0x0007
    # optional trace
    PATH_TRACE                  = 0x0008
    # optional timescale
    ALT_TIME_OFFSET_INDICATOR   = 0x0009
    # RESERVED for std TLV  000A-1FFF
    # From 2008 std:
    AUTHENTICATION              = 0x2000
    AUTHENTICATION_CHALLENGE    = 0x2001
    SECURITY_ASSOCIATION_UPDATE = 0x2002
    CUM_FREQ_SCALE_FACTOR_OFFSE = 0x2003
    # v2.1:
    # Experimental 2004-202F
    # RESERVED   2030-3FFF
    # IEEE 1588 reserved 4002-7EFF
    # Experimental 7F00-7FFF
    # Interesting 8000-8009
    PAD                         = 0x8008
    AUTHENTICATIONv2            = 0x8009
    # IEEE 1588  RESERVED   800A-FFEF
    # RESERVED   FFEF-FFFF


class PTPMsg:
    class MsgFlags(Flag):
        def __str__(self):
            return self.name
        Twostep = 2        # 1<<1
        Unicast = 4        # 1<<2

    @staticmethod
    def getTLVs(msgLen, data, start):
        # TLV = Type, Length, Value Identifier
        tlvSeq = []
        while(msgLen - start) > 0:
            tlvType = int.from_bytes(data[start: start + 2], byteorder='big')
            tlvLen = int.from_bytes(data[start + 2:start + 4], byteorder='big')
            # 3 byte OID + 3 byte subOID
            # V in TLV are even in length.
            """
            1588-2019: 14.3.2 TLV member specifications
            All organization-specific TLV extensions shall have
            the format specified in Table 53:
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0
            lengthField         | 2 | 2
            organizationId      | 3 | 4
            organizationSubType | 3 | 7
            dataField           | N | 10
            """

            """802.1AS-2011 specific TLV in Signalling seems to be:
            targetPortIdentity (PortIdentity) (this comes before the TLV)
            The value is 0xFF. (Apple seems to use 0x00)
            (Message interval request TLV)
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0   <-- 3
            lengthField         | 2 | 2   <-- 12
            organizationId      | 3 | 4   <-- 00:80:c2
            organizationSubType | 3 | 7   <-- 00:00:02
            linkDelayInterval   | 1 | 10
            timeSyncInterval    | 1 | 11
            announceInterval    | 1 | 12
            flags               | 1 | 13
            reserved            | 2 | 14

            uint8 : linkDelayInterval
            uint8 : timeSyncInterval
            uint8 : announceInterval
            uint8 : flags (== 3)
            uint16: reserved

            10.5.4.3.6 linkDelayInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV,
            between successive Pdelay_Req messages sent by the port at the other end of the link
            The format and allowed values of linkDelayInterval are the same as the format and
            allowed values of initialLogPdelayReqInterval, see 11.5.2.2.
            values 127, 126, and -128 are interpreted as (same for timeSync and announce):

            127 = stop sending
            126 = set currentX to the value of initialX
            -128= not to change the mean time interval between successive X messages.

            10.5.4.3.7 timeSyncInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV,
            between successive time-synchronization event messages sent by the port at the other
             end of the link. The format and allowed values of timeSyncInterval are the same as
             the format and allowed values of initialLogSyncInterval, see 10.6.2.3, 11.5.2.3,
             12.6, and 13.9.2.

            10.5.4.3.8 announceInterval (Integer8)
            = log base 2 of mean time interval, desired by the port that sends this TLV, between
             successive Announce messages sent by the port at the other end of the link. The
             format and allowed values of announceInterval are the same as the format and
             allowed values of initialLogAnnounceInterval, see 10.6.2.2.

            10.5.4.3.9 flags (Octet)
            Bits 1 and 2 of the octet are defined in Table 10-14 and take on values T/F
            1 = computeNeighborRateRatio
            2 = computeNeighborPropDelay
            """

            """802.1AS-2011 specific TLV in Signalling seems to be (CSN TLV):
            bitfield       | Octets | TLV offset
            tlvType             | 2 | 0   <-- 3
            lengthField         | 2 | 2   <-- 46
            organizationId      | 3 | 4   <-- 00:80:c2
            organizationSubType | 3 | 7   <-- 00:00:03
            upstreamTxTime      | 12| 10
            neighborRateRatio   | 4 | 22
            neighborPropDelay   | 12| 26
            delayAsymmetry      | 12| 38

            upstreamTxTime (UScaledNs)
            neighborRateRatio (Integer32)
            neighborPropDelay (UScaledNs)
            delayAsymmetry (UScaledNs)
            CSN egress node

            This TLV is not allowed to occur before the Follow_Up information TLV (see 11.4.4.3)
            """
            # org specific
            if tlvType == 3:
                # Usually 00:80:c2:00:00:01 within FOLLOWUP
                # https://hwaddress.com/mac-address-range/00-0D-93-00-00-00/00-0D-93-FF-FF-FF/
                # Apple: 00:0d:93 sub: 00:00:0x => meaning: defined by Apple.
                #   contains clockID(mac)+port
                tlvOID = int.from_bytes(data[start + 4:start + 10], byteorder='big')
                # Exclude the OID from data, tlvLen includes OID
                tlvData = data[start + 10:start + 4 + tlvLen]

                tlvSeq.append([tlvType, tlvLen, tlvOID, tlvData])

            elif tlvType == 8:  # PATH_TRACE
                """
                while it may be possible to have Path and other TLV types together, best for now
                to keep their handling and return separate. Have not seen such a combination yet.
                1588-2019: 16.2.5 PATH_TRACE TLV specification
                The PATH_TRACE TLV format shall be as specified in Table 115.
                bitfield       | Octets | TLV offset
                tlvType             | 2 | 0
                lengthField         | 2 | 2
                pathSequence        | 8N| 4

                N is equal to stepsRemoved+1 (see 10.5.3.2.6). The size of the pathSequence array
                increases by 1 for each time-aware system that the Announce information traverses.
                """
                tlvUnitSize = 8  # bytes
                tlvRecordAmt = int(tlvLen / tlvUnitSize)
                # https://blog.meinbergglobal.com/2019/12/06/tlvs-in-ptp-messages/
                tlvPathSequence = [None] * tlvRecordAmt
                for x in range(0, tlvRecordAmt):
                    tlvPathSequence[x] = int.from_bytes(data[
                        start + 4 + (x * tlvUnitSize):
                        start + 4 + tlvUnitSize + (x * tlvUnitSize)
                    ], byteorder='big')
                    # print(tlvPathSequence[x])
                return tlvPathSequence

            # still in the while loop
            start += tlvLen + 4  # 4 byte TLV header
        return tlvSeq if len(tlvSeq) > 0 else None

    def __init__(self, data):
        # self.v1_compat = (data[0] & 0b00010000) >> 4
        self.msg_type = MsgType(data[0] & 0b00001111)
        # self.ptp_version= data[1] & 0b00001111 #) >> 0
        # data[2] is 1 Reserved byte
        self.msgLength = int.from_bytes(data[2:4], byteorder='big')
        if len(data) == self.msgLength:
            # domain: 0 = default | 1 = alt 1 | 3 = alt 3 | 4-127, user defined.
            self.subdomainNumber = data[4]
            msgFlagsA = int.from_bytes(data[6:7], byteorder='big')
            # msgFlagsB = int.from_bytes(data[7:8], byteorder='big')
            # self.msgFlags = self.getMsgFlags(msgFlagsA, msgFlagsB)
            self.msgFlags = PTPMsg.MsgFlags(msgFlagsA)
            """
            Semantics dictate that correction is always ZERO for
            -Announce
            -Signaling
            -PTP mgmt
            """
            self.correctionNanoseconds = int.from_bytes(data[8:14], byteorder='big')
            # unlikely we will ever deal with subNanoSec or ever be accurate in Python
            # self.correctionSubNanoseconds = int.from_bytes(data[14:16], byteorder='big')
            # data[16:20][0] is 4 Reserved bytes
            self.clockIdentity = int.from_bytes(
                data[20:28], byteorder='big')
            # SrcPortID = ID for the sending address, where each IP may have a diff one, or same.
            self.sourcePortID = int.from_bytes(
                data[28:30], byteorder='big')
            self.sequenceID = int.from_bytes(
                data[30:32], byteorder='big')
            # unnecessary - from ptpv1:
            # self.control    =   data[32]
            # logMessagePeriod / Interval: for Sync, Followup, Del_resp
            # multicast = log2(interval between multicast messages)
            # y = log2(x) => if lMP = -2, x = 0.25 sec i.e. send 4 Sync every second.
            # -3 => 8 per second.
            # Sync: -7 -> 1 (i.e. from 128/sec to 1 per 2 sec)
            # Ann : -3 -> 3 (i.e. from 8/sec   to 1 per 8 sec)
            # Delay_Resp: def -4 (16/sec) | -7 -> 6 (i.e. from 128/sec to 1 per 64 sec)
            self.logMessagePeriod = data[33]
            if((self.msg_type == MsgType.SYNC)
               or (self.msg_type == MsgType.ANNOUNCE)
               or (self.msg_type == MsgType.DELAY_REQ)):
                self.originTimestampSec = int.from_bytes(
                    data[34:40], byteorder='big')
                self.originTimestampNanoSec = int.from_bytes(
                    data[40:44], byteorder='big')
                if(self.msg_type == MsgType.ANNOUNCE):
                    # self.originCurrentUTCOffset = int.from_bytes(data[44:46], byteorder='big')
                    # skip 1 reserved byte
                    # GM determined by (lower = better):
                    # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
                    self.prio01 = data[47]
                    # ClockClass = Quality Level (QL)
                    self.gmClockClass = data[48]
                    self.gmClockAccuracy = data[49]
                    # variance: lower = better. Based on Allan Variance / Sync intv
                    # PTP variance is equal to Allan variance multiplied by (τ^2)/3,
                    # where τ is the sampling interval
                    self.gmClockVariance = int.from_bytes(
                        data[50:52], byteorder='big')
                    self.prio02 = data[52]
                    self.gmClockIdentity = int.from_bytes(
                        data[53:61], byteorder='big')
                    self.localStepsRemoved = int.from_bytes(
                        data[61:63], byteorder='big')
                    self.timeSource = data[63]
                    tlvStart = 64
                    self.hasTLVs = (self.msgLength - tlvStart) > 0
                    if self.hasTLVs:
                        self.tlvPathSequence = self.getTLVs(self.msgLength, data, tlvStart)

            elif(MsgType(self.msg_type) == MsgType.DELAY_RESP):
                self.rcvTimestampSec = int.from_bytes(
                    data[34:40], byteorder='big')
                self.rcvTimestampNanoSec = int.from_bytes(
                    data[40:44], byteorder='big')
                self.requestingSrcPortIdentity = int.from_bytes(
                    data[44:52], byteorder='big')  # mac+port
                self.requestingSrcPortID = int.from_bytes(
                    data[52:54], byteorder='big')  # ID

            elif(MsgType(self.msg_type) == MsgType.FOLLOWUP):
                tlvStart = 44
                self.hasTLVs = (self.msgLength - tlvStart) > 0
                self.preciseOriginTimestampSec = int.from_bytes(
                    data[34:40], byteorder='big')
                self.preciseOriginTimestampNanoSec = int.from_bytes(
                    data[40:44], byteorder='big')
                # in Airplay2 apple products, followups have TLVs (but we don't need them)
                if self.hasTLVs:
                    self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)

            elif(MsgType(self.msg_type) == MsgType.SIGNALLING):
                tlvStart = 44
                self.hasTLVs = (self.msgLength - tlvStart) > 0
                self.targetPortIdentity = int.from_bytes(
                    data[34:42], byteorder='big')
                self.targetPortID = int.from_bytes(
                    data[42:44], byteorder='big')
                if self.hasTLVs:
                    self.tlvSeq = self.getTLVs(self.msgLength, data, tlvStart)


class PTPMaster:
    def __init__(self):
        # Defaults are worst case.
        self.prio01 = 255
        self.gmClockClass = 255  # slave only
        self.gmClockAccuracy = 0xFF
        self.gmClockVariance = 0xFFFF
        self.prio02 = 255
        self.gmClockIdentity = 0xFFFFFFFFFFFFFFFF

    def __init__(self, data):
        self.prio01 = data.prio01
        self.gmClockClass = data.gmClockClass
        self.gmClockAccuracy = data.gmClockAccuracy
        self.gmClockVariance = data.gmClockVariance
        self.prio02 = data.prio02
        self.gmClockIdentity = data.gmClockIdentity

    def __lt__(self, other):
        if not isinstance(other, PTPMaster):
            return False
        if self.prio01 < other.prio01:
            return True
        if self.gmClockClass < other.gmClockClass:
            return True
        if self.gmClockAccuracy < other.gmClockAccuracy:
            return True
        if self.gmClockVariance < other.gmClockVariance:
            return True
        if self.prio02 < other.prio02:
            return True
        if self.gmClockIdentity < other.gmClockIdentity:
            return True
        return False

    def __eq__(self, other):
        if not isinstance(other, PTPMaster):
            return False
        return (self.prio01 == other.prio01
                and self.gmClockClass == other.gmClockClass
                and self.gmClockAccuracy == other.gmClockAccuracy
                and self.gmClockVariance == other.gmClockVariance
                and self.prio02 == other.prio02
                and self.gmClockIdentity == other.gmClockIdentity)


class PTPForeignMaster:
    def __init__(self):
        self.sourcePortID = {}
        self.announceAmount = 0

    def __init__(self, data, arrival):
        self.sourcePortID = {data.gmClockIdentity, data.sourcePortID}
        self.announceAmount = 0
        # 9.3.2.4.3 : array of fm announces within FOREIGN_MASTER_TIME_WINDOW
        self.announceMessages = deque([data] * 4, maxlen=4)
        # Statistical code-golf
        self.announceMessageArrival_ts = deque([arrival] * 10, maxlen=10)
        self.announceMessageArrivalDeltas = deque([0] * 10, maxlen=10)

    def inc(self):
        self.announceAmount += 1

    def setMostRecentAMsg(self, data, arrival):
        self.inc()
        self.announceMessages.append(data)
        self.announceMessageArrival_ts.append(arrival)
        self.announceMessageArrivalDeltas.append(arrival - self.announceMessageArrival_ts[len(self.announceMessageArrival_ts) - 2])
        # self.checkMasterQuality()

    def checkMasterQuality(self):
        # TODO: Verify the quality of the Master's announce timing.
        # This is not mandated in the standard, it's just code golf when it's on the receiver :)
        # IEEE-1588-2019: 9.5.8
        """
        ...the value of the arithmetic mean of the intervals, in seconds,
        between message transmissions is within ±30% of the value of 2 ** portDS.logAnnounceInterval

        Also, a PTP Port shall transmit Announce messages such that:
         at least 90% of the inter-message intervals are within ±30% of
         2 ** portDS.logAnnounceInterval.
         The interval between successive Announce messages should not exceed
         twice the value of 2** portDS.logAnnounceInterval,
         to prevent causing an announceReceiptTimeout event.
        """
        QLength = 10 - self.announceMessageArrivalDeltas.count(0)
        ArithMean = sum(self.announceMessageArrivalDeltas) / QLength
        AInterval = (2 ** self.getMostRecentAMsg().logMessagePeriod) * 10**9
        isWithin = ((AInterval * 0.7) < ArithMean and ArithMean < (AInterval * 1.3))
        # i.e. within ±30%

    def getAnnounceAmt(self):
        return self.announceAmount

    def getMostRecentArrivalNanos(self):
        return self.announceMessageArrival_ts[len(self.announceMessageArrival_ts) - 1]

    def getMostRecentAMsg(self):
        return self.announceMessages[len(self.announceMessages) - 1]

    def __lt__(self, other):
        return (PTPMaster(self.getMostRecentAMsg())
                < PTPMaster(other.getMostRecentAMsg()))

    def __gt__(self, other):
        return (PTPMaster(self.getMostRecentAMsg())
                > PTPMaster(other.getMostRecentAMsg()))

    def __eq__(self, other):
        return (PTPMaster(self.getMostRecentAMsg())
                == PTPMaster(other.getMostRecentAMsg()))
        # return self.sourcePortID == other.sourcePortID #also works


class PTPPortState(enum.Enum):
    def __str__(self):
        # so when we enumerate, we only print the msg name w/o class:
        return self.name
    (
        # PRE_MASTER
        # MASTER
        INITIALIZING,
        LISTENING,
        PASSIVE,
        UNCALIBRATED,
        SLAVE
    ) = range(5)
    # no code yet to run as MASTER


class PTP():
    class CFG(Flag):
        def __str__(self):
            return self.name
        # Config(16383) / Config(0x3FFF) toggles everything on.
        ShowNothing             = 0
        ShowTLVs                = 1     # 1<<0
        ShowSYNC                = 2     # 1<<1
        ShowDELAY_REQ           = 4     # 1<<2
        ShowPATH_DELAY_REQ      = 8     # 1<<3
        ShowPATH_DELAY_RESP     = 16    # 1<<4
        ShowFOLLOWUP            = 32    # 1<<5
        ShowDELAY_RESP          = 64    # 1<<6
        ShowPATH_DELAY_FOLLOWUP = 128   # 1<<7
        ShowANNOUNCE            = 256   # 1<<8
        ShowSIGNALLING          = 512   # 1<<9
        ShowMANAGEMENT          = 1024  # 1<<10
        ShowMasterPromotion     = 2048  # 1<<11
        ShowPortStateChanges    = 4096  # 1<<12
        ShowMeanPathDelay       = 8192  # 1<<13
        ShowDebug               = 16384  # 1<<14
        SetApplePTPProfile      = 32768  # 1<<15

    def __init__(self, net_interface, config_flags):
        self.cfg = self.CFG(config_flags)
        # Test individual flags with e.g.:
        # self.cfg |= self.CFG.ShowMeanPathDelay
        self.portEvent319 = 319    # Sync msgs / Event Port
        self.portGeneral320 = 320  # Followup msgs / General port
        self.gm = None
        self.t1_arr_nanos = 0
        self.t1_ts_s = 0
        self.t1_ts_ns = 0
        self.t1_corr = 0
        self.t2_arr_nanos = 0
        self.t2_ts_s = 0
        self.t2_ts_ns = 0
        self.t3_egress_nanos = 0
        self.t4_arr_at_gm_nanos = 0
        self.ms_propagation_delay = 0
        # Limit Queues to 30 entries
        self.QLength = 30
        self.offsetFromMasterNanos = 0
        self.offsetFromMasterNanosMean = 0
        # deque = O(1) perf
        self.offsetFromMasterNanosValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.meanPathDelayNanos = 0  # bi-directional
        self.meanPathDelayNanosMean = 0  # mean of several bi-di results
        self.meanPathDelayNanosValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.processingOverhead = 0
        self.syncSequenceID = 0
        self.useMasterPromoteAlgo = True
        self.DelayReq_PortID = 32768
        self.DelayReq_template = bytearray.fromhex(
            '1102002c00000408000000000000000000000000'
            '01020304050600018000000100fd00000000000000000000')
        if(net_interface is not None):
            # DelayReq_template contains dummy MAC '010203040506'
            # add 2 empty bytes for 'PTP Port' to end of mac:
            self.net_interface = net_interface << 16
            self.net_interface_bytes = (net_interface << 16).to_bytes(8, byteorder='big')
            self.DelayReq_template[20:28] = self.net_interface_bytes
        else:
            self.net_interface = int('010203040506')
        self.DelayReq_template[28:30] = self.DelayReq_PortID.to_bytes(2, byteorder='big')
        self.portStateChange(PTPPortState.INITIALIZING)
        self.PTPcorrection = 0
        self.fML = []  # <foreignMasterList> # 9.3.2.4.6 Size of <foreignMasterList> min 5
        """
        Each entry of the <foreignMasterList> contains two or three members:
        - <foreignMasterList>[].foreignMasterPortIdentity,
        - <foreignMasterList>[].foreignMasterAnnounceMessages, and optionally
        - <foreignMasterList>[].mostRecentAnnounceMessage.
        """
        self.fMTW = 4  # FOREIGN_MASTER_TIME_WINDOW = 4 announceInterval
        self.fMThr = 2  # FOREIGN_MASTER_THRESHOLD 2 Announce msg within FOREIGN_MASTER_TIME_WINDOW
        """
        announceReceiptTimeoutInterval = portDS.announceReceiptTimeout * announceInterval
        """

        # 7.7.3.1 portDS.announceReceiptTimeout:
        # "Although 2 is permissible, normally the value should be at least 3."
        self.announceReceiptTimeout = 3
        # I.3.2 portDS.logAnnounceInterval: d = 1, 0<->4
        # announceInterval = 2 ** portDS.logAnnounceInterval
        self.announceInterval = 0

        """
        L.4.7 L1SyncReceiptTimeout
        This value = # of elapsed L1SyncIntervals that must pass without reception of the
        L1_SYNC TLV before the L1_SYNC TLV reception timeout occurs (see L.6.3).
        The default init val and allowed values spec'd in the applicable PTP Profile.
        """
        self.syncReceiptTimeout = 3
        # 13.3.2.14 logMessageInterval = 0x7F in unicast.
        # I.3.2 PTP attribute values
        # The default initialization value shall be 0.
        # The configurable range shall be −1 to +1.
        self.logSyncInterval = 0

        """ https://github.com/rroussel/OpenAvnu/blob/ArtAndLogic-aPTP-changes/daemons/gptp/gptp_cfg.ini
        # Per the Apple Vendor PTP profile
        initialLogAnnounceInterval = 0
        initialLogSyncInterval = -3
        # Seconds:
        announceReceiptTimeout = 120

        # Per the Apple Vendor PTP profile (8*announceReceiptTimeout)
        syncReceiptTimeout = 960
        """
        if(self.cfg & self.CFG.SetApplePTPProfile):
            # prio1 & prio2 = 248 and accuracy = 254
            self.logAnnounceInterval = 0
            self.announceReceiptTimeout = 120
            self.logSyncInterval = -3
            self.syncReceiptTimeout = 8 * self.announceReceiptTimeout

        # count down nanos from last Announce - expires current GM
        self.lastAnnounceFromMasterNanos = 0

        self.network_time_ns = 0
        self.network_time_monotonic_ts = time.monotonic_ns()
        self.max_error = 1 * (10 ** 6) # 1 millisecond

    def promoteMaster(self, ptpmsg, reason):
        self.gm = PTPMaster(ptpmsg)
        if(self.cfg & self.CFG.ShowMasterPromotion):
            print("New GM Clock promoted: "
                  f"{ptpmsg.gmClockIdentity:10x} (Prio{ptpmsg.prio01}/{ptpmsg.prio02})",
                  f"reason: {reason}"
                  )
        # reset cumulative mean values to 0
        self.offsetFromMasterValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.meanPathDelayNanosValues = deque([0] * self.QLength, maxlen=self.QLength)
        self.portStateChange(PTPPortState.SLAVE)
        self.announceInterval = 2 ** ptpmsg.logMessagePeriod

    def compareMaster(self, ptpmsg):
        # This algo promotes a new master if its properties are better than currently elected GM
        # prio1 < Class < Accuracy < Variance < prio2 < Ident(mac)
        # Lower values == "better"
        if self.gm is None:
            self.promoteMaster(ptpmsg, "reset")
        else:
            incoming = PTPMaster(ptpmsg)

            if (incoming < self.gm):
                self.promoteMaster(ptpmsg, "better GM")
                self.fML = []
            # else:
                # retain current GM

    def sendDelayRequest(self, sequenceID):
        self.DelayReq_template[30:32] = sequenceID.to_bytes(2, byteorder='big')
        return self.DelayReq_template

    def portStateChange(self, PTPPortState):
        self.portState = PTPPortState
        if (self.cfg & self.CFG.ShowPortStateChanges):
            print(f"PTP State: {self.portState}")

    def getPortState(self):
        return self.portState

    def isKnownForeignMaster(self, ptpfm, ptpmsg, arrivalNanos):
        """
        Looks at our list of foreignMaster candidates and when we have enough Announce
        msgs from one, we kick off the BMCA: compareMaster()
        """
        """
        9.3.2.5 Qualification of Announce messages

        c) Unless otherwise specified by the option of 17.7, if the sender of S is a foreign
        master F, and fewer than FOREIGN_MASTER_THRESHOLD distinct Announce messages from F
        have been received within the most recent FOREIGN_MASTER_TIME_WINDOW interval, S
        shall not be qualified. Distinct Announce messages are those that have different
        sequenceIds, subject to the constraints of the rollover of the UInteger16 data type
        used for the sequenceId field.
        ...
        d) If the stepsRemoved field of S is 255 or greater, S shall not be qualified.
        ...
        e) This specification “e” is optional. ...
        ...
        f) Otherwise, S shall be qualified.
        """
        if ptpfm not in self.fML:
            self.fML.append(ptpfm)
            # first entry means count == 0, so we skip sorting/comparing
            return False
        else:
            self.fML[self.fML.index(ptpfm)].setMostRecentAMsg(ptpmsg, arrivalNanos)
            # check previous Announce arrivalNanos
            lMP = 2 ** ptpmsg.logMessagePeriod  # e.g. 2^-2 = 0.25 sec
            # check interarrival diff of current and stored Announce nanos is
            # less than FOREIGN_MASTER_TIME_WINDOW * logMessagePeriod
            considerBMCA = ((arrivalNanos - self.fML[
                self.fML.index(ptpfm)]
                .getMostRecentArrivalNanos()) * 10**-9) < (self.fMTW * lMP)  # e.g. 4 * 0.25 = 1 sec
            self.fML.sort()  # keep fML list sorted, and mash [0] into BMCA when time comes
            if (self.fML[self.fML.index(ptpfm)].getAnnounceAmt() >= self.fMThr
               and considerBMCA):
                # run BMCA
                self.compareMaster(self.fML[0].getMostRecentAMsg())
            return True

    def handlemsg(self, ptpmsg, address, timestampArrival, processingOverhead):
        # print(f"entered handlemsg() with {ptpmsg.sequenceID} and {self.syncSequenceID}")
        thinning = 100  # print msg every x msgs
        # port 319
        if((ptpmsg.msg_type == MsgType.SYNC)
           or (ptpmsg.msg_type == MsgType.DELAY_REQ)):

            if(((self.cfg & self.CFG.ShowSYNC) or (self.cfg & self.CFG.ShowDELAY_REQ))
               and (ptpmsg.sequenceID % thinning == 0)):
                print(f"PTP319 {ptpmsg.msg_type: <12}",
                      f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                      f"clockId: {ptpmsg.clockIdentity:016x}",
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      f"Time: {ptpmsg.originTimestampSec}.{ptpmsg.originTimestampNanoSec:09d}",
                      )
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

            # were we master, here is when we would respond to DELAY_REQ with DELAY_RESP
            # upon receipt of each Sync, we should respond with DELAY_REQ with same seqID
            if (MsgType(ptpmsg.msg_type) == MsgType.SYNC
               and self.gm is not None
               and ptpmsg.clockIdentity == self.gm.gmClockIdentity):
                if ptpmsg.msgFlags.Twostep:
                    # Calculate ms_propagation_delay in FOLLOWUP
                    self.t2_arr_nanos = timestampArrival
                    self.t2_ts_s = ptpmsg.originTimestampSec
                    self.t2_ts_ns = ptpmsg.originTimestampNanoSec
                    self.syncSequenceID = ptpmsg.sequenceID
                    # assign t3 to delay_req egress timestamp
                    self.t3_egress_nanos = time.monotonic_ns()
                    return self.sendDelayRequest(self.syncSequenceID)
                # else: #PTP in airplay does not seem to bother with 1-step
                #     #iPhone PTP sends ptpmsg.originTimestamp(Nano)Sec = 0... so this won't work
                #     #1-step: must calculate t2-t1 diff here.
                #     self.t1_arr_nanos = ptpmsg.originTimestampSec + (ptpmsg.originTimestampNanoSec / 10 ** 9)
                #     self.ms_propagation_delay = t2_arr - t1_arr

        elif(ptpmsg.msg_type == MsgType.DELAY_RESP
             and ptpmsg.requestingSrcPortIdentity == self.net_interface):
            """
            IEEE1588-2019 Spec says:
            <meanPathDelay> = [(t2 – t1) + (t4 – t3)]/2 = [(t2 – t3) + (t4 – t1)]/2

            <meanPathDelay> = [(t2 - t3) + (receiveTimestamp of Delay_Resp message – preciseOriginTimestamp of Follow_Up message) –
            <correctedSyncCorrectionField> - correctionField of Follow_Up message – correctionField of Delay_Resp message]/2
            """
            t4 = (ptpmsg.rcvTimestampSec * (10**9) + ptpmsg.rcvTimestampNanoSec)

            self.meanPathDelayNanos = ((self.t2_arr_nanos - self.t3_egress_nanos)
                                       + (t4 - (self.t1_ts_s * (10**9)) - self.t1_ts_ns)
                                       - self.t1_corr - ptpmsg.correctionNanoseconds) / 2

            self.PTPcorrection = abs(self.meanPathDelayNanos) / (10**9)
            # print(f"Current mean path delay (sec): {self.PTPcorrection:.09f}")


            # store in self.network_time_ns and self.network_time_monotonic_ts the current network time
            # and the time the 'fixed' network time is retrieved, so we can calculate network time at any time

            # try to filter out invalid values
            network_time_ns = t4 + self.meanPathDelayNanos
            network_time_monotonic_ts = time.monotonic_ns()

            # what time would be now if we need to calculate it?
            previous_network_time = self.network_time_ns + (network_time_monotonic_ts - self.network_time_monotonic_ts)
            # the error is the difference between calculated time from previous ptp sync and the current ptp sync
            error = (previous_network_time - network_time_ns) / (10 ** 6)

            if abs(error) < self.max_error or self.network_time_ns == 0:
                if (abs(error) > 10):
                    print(f'updated time error {error} less than {self.max_error} ms')
                self.network_time_ns = network_time_ns
                self.network_time_monotonic_ts = network_time_monotonic_ts
                self.max_error = 2 # millisecond
            else:
                #print(f'skip update time error {error} bigger than {self.max_error} ms')
                # grow error so an update happens
                self.max_error = self.max_error * 1.2

            """
            # This Q builds a sliding avg of all MPDs.
            self.meanPathDelayNanosValues.append(mpdNanos)
            # must append, otherwise ZeroDivisionError
            self.meanPathDelayNanosMean = sum(self.meanPathDelayNanosValues)/ \
             (self.meanPathDelayNanosValues.maxlen-self.meanPathDelayNanosValues.count(0))
            print(f"self.meanPathDelayNanosMean (sec): {abs(self.meanPathDelayNanosMean)/(10**9):.09f}")
            """

            """
            derived from our clock:
            t4 = self.t3_egress_nanos + mpd - self.offsetFromMasterNanos

            from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec)

            diff of the above two:
            diff = (self.t3_egress_nanos + mpd - self.offsetFromMasterNanos) - \
              ((ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec)

            as our clock derived from master:
            t4 = (ptpmsg.rcvTimestampSec*(10**9)) + ptpmsg.rcvTimestampNanoSec \
                + self.offsetFromMasterNanos
            """
            if ((self.cfg & self.CFG.ShowMeanPathDelay) and (ptpmsg.sequenceID % (thinning / 10) == 0)):
                print(f"PTP-correction (sec): {self.PTPcorrection:.09f}")
                """
                origin = ptpmsg.rcvTimestampSec + (ptpmsg.rcvTimestampNanoSec/(10**9))
                         + self.PTPcorrection
                print(f"Timetamp at origin now: {origin:.09f}")
                """

            if ((self.cfg & self.CFG.ShowDELAY_RESP) and (ptpmsg.sequenceID % thinning == 0)):
                print(f"PTP320 {ptpmsg.msg_type: <12}",
                      f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                      f"clockId: {ptpmsg.clockIdentity:016x}",
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
                      f"receiveTimestamp: {ptpmsg.rcvTimestampSec}.{ptpmsg.rcvTimestampNanoSec:09d}",
                      )
        elif(ptpmsg.msg_type == MsgType.ANNOUNCE):
            ptpfm = PTPForeignMaster(ptpmsg, timestampArrival)
            self.isKnownForeignMaster(ptpfm, ptpmsg, timestampArrival)
            if not (self.getPortState() == PTPPortState.INITIALIZING
                    or self.getPortState() == PTPPortState.SLAVE
                    or self.getPortState() == PTPPortState.PASSIVE
                    or self.getPortState() == PTPPortState.UNCALIBRATED):

                if(self.gm is None):
                    """
                    Normally, (in AirPlay) PTP masters negotiate amongst themselves who leads,
                     then only that 1 gm sends announce.
                    In this half PTP implementation, as a CPU measure, we can let them fight it
                    out and then just run promoteMaster directly.
                    """
                    if not self.useMasterPromoteAlgo:
                        self.promoteMaster(ptpmsg, "changeover")
            if(self.gm is not None):
                # path trace TLV path-seq in Announce (also) has GM
                """
                IEEE-1588-2019:
                16.2.3 Receipt of an Announce message
                A PTP Port of a Boundary Clock receiving an Announce message from
                 the current parent PTP Instance shall:
                a) Scan the pathSequence member of any PATH_TRACE TLV present for a value of the
                 clockIdentity field equal to the value of the defaultDS.clockIdentity member of
                 the receiving PTP Instance, that is, there is a “match.”
                b) Discard the message if the TLV is present and a match is found.
                c) Copy the pathSequence member of the TLV to the pathTraceDS.list member
                 (see 16.2.2.2.1) if the TLV is present and no match is found.
                """
                if self.gm.gmClockIdentity in ptpmsg.tlvPathSequence:
                    self.lastAnnounceFromMasterNanos = timestampArrival
                    pass
                else:  # if self.gm.gmClockIdentity != ptpmsg.gmClockIdentity:
                    if not self.useMasterPromoteAlgo:
                        self.compareMaster(ptpmsg)

            if ((self.cfg & self.CFG.ShowANNOUNCE) and (ptpmsg.sequenceID % thinning == 0)):
                # varianceb10 = 2**((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                # varianceb2 = ((ptpmsg.gmClockVariance - 0x8000) / 2**8)
                # i.e. gmVariance = (log2(variance)*2^8)+32768
                # 0x0000 => 2^-128 | 0xFFFE => 2^127.99219
                print(f"PTP320 {ptpmsg.msg_type: <12}",
                      f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                      f"pri1/2: {ptpmsg.prio01}/{ptpmsg.prio02}",
                      f"gmClockClass: {ClkClass(ptpmsg.gmClockClass)}",
                      f"gmClockAccuracy: {GMCAccuracy(ptpmsg.gmClockAccuracy)}",
                      # f"gmClockVariance(s): {varianceb10:.04g}",
                      # f"gmClockVariance(s): 2^{varianceb2:.04g}",
                      f"gmClockId: {ptpmsg.gmClockIdentity:10x}",  # x = heX
                      f"seq-ID: {ptpmsg.sequenceID:08d}",
                      # f"timeSource: {ptpmsg.timeSource}",
                      "Time:", ptpmsg.originTimestampSec)

                if(self.cfg & self.CFG.ShowTLVs):
                    print(f"PTP320  with PathTrace { [f'0x{addr:016x}' for addr in ptpmsg.tlvPathSequence] }")
                # print(f"processingOverhead for {ptpmsg.msg_type}:{processingOverhead:.9f}")

        elif(ptpmsg.msg_type == MsgType.FOLLOWUP):
            # in Airplay(2) PreciseOriginTimestamp = device uptime.
            if(ptpmsg.sequenceID == self.syncSequenceID
               and self.gm is not None
               and ptpmsg.clockIdentity == self.gm.gmClockIdentity):

                self.t1_arr_nanos = timestampArrival
                self.t1_ts_s = ptpmsg.preciseOriginTimestampSec
                self.t1_ts_ns = ptpmsg.preciseOriginTimestampNanoSec
                self.t1_corr = ptpmsg.correctionNanoseconds

                # when iPhones deep sleep - their uptime (origintimestamp) pauses
                self.offsetFromMasterNanos = (
                    self.t2_arr_nanos
                    - ((ptpmsg.preciseOriginTimestampSec * (10**9))
                        + ptpmsg.preciseOriginTimestampNanoSec
                        + ptpmsg.correctionNanoseconds))
                self.offsetFromMasterNanosValues.append(self.offsetFromMasterNanos)
                # must append otherwise ZeroDivisionError
                self.offsetFromMasterNanosMean = sum(
                    self.offsetFromMasterNanosValues) / (
                    self.offsetFromMasterNanosValues.maxlen
                    - self.offsetFromMasterNanosValues.count(0))
                # print(f"self.offsetFromMasterMean (sec): {self.offsetFromMasterNanosMean/(10**9):.09f}")

                # in two step PTP - we send a DELAY_REQ, and await its response
                # to figure out t3 and t4

                if ((self.cfg & self.CFG.ShowFOLLOWUP) and (ptpmsg.sequenceID % thinning == 0)):
                    # print info every nth pkt
                    print(f"PTP320 {ptpmsg.msg_type: <12}",
                          f"srcprt-ID: {ptpmsg.sourcePortID:05d}",
                          f"clockId: {ptpmsg.clockIdentity:10x}",  # x = heX
                          f"seq-ID: {ptpmsg.sequenceID:08d}",
                          f"correctionNanosec: {ptpmsg.correctionNanoseconds:09d}",
                          f"PreciseTime: {ptpmsg.preciseOriginTimestampSec}.{ptpmsg.preciseOriginTimestampNanoSec:09d}")

                    if((self.cfg & self.CFG.ShowTLVs) and hasattr(ptpmsg, 'hasTLVs') and ptpmsg.hasTLVs):
                        print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                        self.parseTLVs(ptpmsg.tlvSeq)

        elif(ptpmsg.msg_type == MsgType.SIGNALLING):
            if ((self.cfg & self.CFG.ShowSIGNALLING) and (ptpmsg.sequenceID % thinning == 0)):
                print("PTP320", ptpmsg.msg_type,
                      "sequenceID: ", ptpmsg.sequenceID)
                if((self.cfg & self.CFG.ShowTLVs) and hasattr(ptpmsg, 'hasTLVs') and ptpmsg.hasTLVs):
                    print(f"PTP320  with TLVs {ptpmsg.tlvSeq}")
                    self.parseTLVs(ptpmsg.tlvSeq)

    def parseTLVs(self, tlvSeq):
        for x in range(0, len(tlvSeq)):
            if(self.cfg & self.CFG.ShowDebug):
                print(f"Typ:{tlvSeq[x][0]:04x}",
                      f"Len:{tlvSeq[x][1]:04x}",
                      f"OID:{tlvSeq[x][2]:012x}",
                      f"Val:{tlvSeq[x][3].hex()}",
                      )

            OID = tlvSeq[x][2]

            if(tlvSeq[x][0] == 3 and tlvSeq[x][1] == 28  # 0x1c
               and OID == 0x0080c2000001):
                self.parseFollowUpTLV(tlvSeq[x][3])
            if(tlvSeq[x][0] == 3 and tlvSeq[x][1] == 22
               and OID == 0x000d93000001):
                # Master Clock parameters like announceInterval(?)
                self.parseApple001TLV(tlvSeq[x][3])
            if(tlvSeq[x][0] == 3 and tlvSeq[x][1] == 16  # 0x10
               and OID == 0x000d93000004):
                # Master Clock ID
                self.parseApple004TLV(tlvSeq[x][3])

    def parseSignallingTLV(self, tlvSeq):
        """
        uint16_t tlvType;  # 2
        uint16_t lengthField;  # 12
        uint8_t organizationId[3];  # 0x0080c2
        uint8_t organizationSubType_ms;  # 0x00
        uint16_t organizationSubType_ls;  # 0x02
        uint8_t linkDelayInterval;
        uint8_t timeSyncInterval;
        uint8_t announceInterval;
        uint8_t flags;
        uint16_t reserved;
        """

    def parseApple001TLV(self, value):
        """ Apple specific TLV in Signalling seems to be:
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 22
        organizationId      | 3 | 4   <-- 00:0d:93
        organizationSubType | 3 | 7   <-- 00:00:01
        dataField           | N | 10  <-- where:

        uint8 : linkDelayInterval
        uint8 : timeSyncInterval
        uint8 : announceInterval
        uint8 : flags (== 3)
        uint16: reserved
        10 bytes extra ?

        """
        # Master Clock parameters like announceInterval(?)
        dataBlock = int.from_bytes(value[0:16], byteorder='big')
        if(self.cfg & self.CFG.ShowDebug):
            print(f'dataBlock: {dataBlock:032x}')

    def parseApple004TLV(self, value):
        """Apple specific TLV in Follow_Up seems to be:
        bitfield       | Octets | TLV offset
        tlvType             | 2 | 0   <-- 3
        lengthField         | 2 | 2   <-- 10
        organizationId      | 3 | 4   <-- 00:0d:93
        organizationSubType | 3 | 7   <-- 00:00:04
        dataField           | N | 10  <-- where:

        8 byte clock ID (including port)
        2 bytes (reserved?)
        """

        # The Master Clock ID - 8 bytes
        # 2 bytes reserved
        masterClock = int.from_bytes(value[0:8], byteorder='big')
        if(self.cfg & self.CFG.ShowDebug):
            print(f'masterClock: {masterClock:012x}')

    def parseFollowUpTLV(self, value):
        """802.1AS-2011 specific TLV in Follow_Ups:
        (Follow_Up information TLV)
        bitfield                 | Octets | TLV offset
        tlvType                   | 2 | 0   <-- 3
        lengthField               | 2 | 2   <-- 28
        organizationId            | 3 | 4   <-- 00:80:c2
        organizationSubType       | 3 | 7   <-- 00:00:01
        cumulativeScaledRateOffset| 4 | 10
        gmTimeBaseIndicator       | 2 | 14
        lastGmPhaseChange         | 12| 16
        scaledLastGmFreqChange    | 4 | 28


        int32   : cumulative scaledRateOffset
        uint16  : gmTimeBaseIndicator
        ScaledNs: scaledLastGmPhaseChange
        int32   : scaledLastGmFreqChange:

        ScaledNs =
        uint16 Nanos Msb
        uint64 Nanos Lsb
        uint16 FracNanos

        scaledRateOffset = (rateRatio – 1.0) × (2^41), truncated to the next smaller signed
        integer, where rateRatio is the ratio of the frequency of the grandMaster to the
        frequency of the LocalClock entity in the time-aware system that sends the message.

        gmTimeBaseIndicator =
        timeBaseIndicator of the ClockSource entity for the current grandmaster

        lastGmPhaseChange =
        (time of the current GM - time of the prev GM), at the
        time that the current GM became GM.
        value is copied from the lastGmPhaseChange member of the MDSyncSend structure whose
        receipt causes the MD entity to send the Follow_Up message

        scaledLastGmFreqChange =

        fractional frequency offset of the current GM relative to the previous GM,
        at the time that the current GM became GM. or relative to itself prior to the last
        change in gmTimeBaseIndicator, multiplied by 2^41 and truncated to the next smaller
        signed integer. The value is obtained by multiplying the lastGmFreqChange member of
        MDSyncSend whose receipt causes the MD entity to send the Follow_Up message
        (see 11.2.11) by 2^41 , and truncating to the next smaller signed Integer8
        """
        """
        In Airplay:
        int32 cumulativeScaledRateOffset
        uint16 gmTimeBaseIndicator
        scaledNs scaledLastGmPhaseChange
        int32 scaledLastGmFreqChange

        ScaledNs =
        uint32 Nanos Msb  # 4
        uint64 Nanos Lsb  # 8
        """
        cumulativeScaledRateOffset = int.from_bytes(value[0:4], byteorder='big')
        gmTimeBaseIndicator = int.from_bytes(value[4:6], byteorder='big')
        scaledLastGmPhaseChange = int.from_bytes(value[6:18], byteorder='big')
        scaledLastGmFreqChange = int.from_bytes(value[18:22], byteorder='big')
        print(f'cumulativeScaledRateOffset: {cumulativeScaledRateOffset}',
              f'gmTimeBaseIndicator: {gmTimeBaseIndicator}',
              f'scaledLastGmPhaseChange: {scaledLastGmPhaseChange}',
              f'scaledLastGmFreqChange: {scaledLastGmFreqChange}',
              )

    def listen(self):
        sockets = []

        for port in range(319, 321):
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.bind(('0.0.0.0', port))
            sockets.append(server_socket)

        empty = []
        self.portStateChange(PTPPortState.LISTENING)
        while True:
            readable, writable, exceptional = select.select(sockets, empty, empty)
            timenow = time.monotonic_ns()
            for s in readable:
                (data, address) = s.recvfrom(180)
                # print(address, data)
                # s.sendto(client_data, client_address)

                timestampArrival = time.monotonic_ns()
                ptpmsg = PTPMsg(data)
                self.processingOverhead = time.monotonic_ns() - timestampArrival
                # just bake overhead into timestampArrival
                timestampArrival += self.processingOverhead

                delay_req = self.handlemsg(ptpmsg, address, timestampArrival, self.processingOverhead)
                if delay_req is not None:
                    s.sendto(delay_req, address)
            """
            9.2.6.12 ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES
            Each protocol engine shall support a timeout mechanism defining the
            <announceReceiptTimeoutInterval>, with a value of portDS.announceReceiptTimeout
            multiplied by the announceInterval (see 7.7.3.1).
            The ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES event occurs at the expiration of this timeout
            plus a random number uniformly distributed in the range (0,1) announceIntervals.
            """
            if (self.gm is not None and ((timenow - self.lastAnnounceFromMasterNanos) * 10**-9)
               > (self.announceReceiptTimeout * (
                  self.announceInterval + (random.randrange(2) * self.announceInterval)))):
                self.gm = None
                self.portStateChange(PTPPortState.LISTENING)
                # alt self.portStateChange(PTPPortState.MASTER)

        for s in sockets:
            s.close()

    def get_ptp_master_correction(self):
        # Gets the current MPD applied to master
        return self.PTPcorrection

    def get_ptp_master_nanos(self):
        # returns locally adjusted (AirPlay) PTP Master Timestamp in nanos
        return self.network_time_ns + (time.monotonic_ns() - self.network_time_monotonic_ts)

    def reader(self, conn):
        try:
            while True:
                if conn.poll():
                    msg = conn.recv()
                    if (msg == 'get_ptp_master_correction'):
                        conn.send(self.get_ptp_master_correction())
                    if (msg == 'get_ptp_master_nanos_timestamped'):
                        conn.send([self.network_time_ns, self.network_time_monotonic_ts])

        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
        finally:
            conn.close()

    def run(self, p_input):
        p = threading.Thread(target=self.listen)
        # p.daemon = True #triggers nice python crash :D
        p.start()

        reader_p = threading.Thread(target=self.reader, args=((p_input),))
        # reader_p.daemon = True #must be True or shutdown hangs here when in pure thread mode
        reader_p.start()

    @staticmethod
    def spawn(net_interface=None, config_flags=0):
        PTPinstance = PTP(net_interface, config_flags)

        p_output, p_input = multiprocessing.Pipe()

        p = multiprocessing.Process(target=PTPinstance.run, args=(p_input,))
        p.start()

        return p, p_output