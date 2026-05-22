"""
PTPv2 ordinary-clock SLAVE for AirPlay 2 receivers.

Spawned as a multiprocessing.Process when the sender announces PTP peers via
SETPEERS/SETPEERSX. Locks to the sender's grand-master clock and updates a
shared PTPDisciplinedClock that the audio path consumes.

Scope and limitations:
  * Unicast only. AirPlay 2 senders address our PTP ports directly.
  * No BMCA: we trust the master IP/ClockID handed to us by SETPEERSX.
  * One-step or two-step Sync both supported.
  * Software timestamping only; on Windows perf_counter is QPC (~100 ns) but
    OS scheduling / NIC buffering still adds tens-of-µs jitter on Wi-Fi.
  * Servo is a simple step-then-PI on offset; frequency is derived from the
    slope of offset estimates over time.
"""

import logging
import multiprocessing
import os
import random
import select
import socket
import struct
import threading
import time
from collections import deque

from . import ptp_messages as ptpm
from .ptp_clock import PTPDisciplinedClock, now_local_ns


PTP_EVENT_PORT = ptpm.PTP_EVENT_PORT
PTP_GENERAL_PORT = ptpm.PTP_GENERAL_PORT

# Tunables
DELAY_REQ_INTERVAL_S = 1.0           # how often we initiate Delay_Req
MAX_SYNC_HISTORY = 32                # samples kept for slope/jitter detection
INITIAL_STEP_THRESHOLD_NS = 1_000_000  # 1 ms: above this on first lock, step
RUNNING_STEP_THRESHOLD_NS = 100_000_000  # 100 ms: re-step instead of slewing
OUTLIER_REJECT_FACTOR = 4.0          # reject samples whose path delay >> median
ANNOUNCE_TIMEOUT_S = 6.0              # if no Announce/Sync for this long, drop sync
PI_KP = 0.7                          # proportional gain on offset (fraction applied)
PI_KI = 0.05                         # integral gain (slow correction of bias)


def _build_clock_identity() -> bytes:
    """Synthesize an 8-byte clock identity for this slave.

    Real PTP uses MAC+two-byte fill (EUI-64). For a software slave the
    identity only matters for echoing into our own Delay_Req source port:
    the master uses it in Delay_Resp's requestingPortIdentity so we can
    pair our request to its response. We randomize and persist for the
    process lifetime.
    """
    # 0x02 in the first byte marks it as locally-administered, harmless here.
    seed = random.getrandbits(48).to_bytes(6, "big")
    return b"\x02" + seed + b"\x01"


def _make_event_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PTP_EVENT_PORT))
    return s


def _make_general_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PTP_GENERAL_PORT))
    return s


class _PendingSync:
    __slots__ = ("seq", "t2_local_ns", "t1_master_ns", "two_step")

    def __init__(self, seq, t2_local_ns, t1_master_ns, two_step):
        self.seq = seq
        self.t2_local_ns = t2_local_ns
        self.t1_master_ns = t1_master_ns
        self.two_step = two_step


class _PendingDelayReq:
    __slots__ = ("seq", "t3_local_ns")

    def __init__(self, seq, t3_local_ns):
        self.seq = seq
        self.t3_local_ns = t3_local_ns


class PTPSlave:
    """One slave instance bound to one master.

    Run as a child process via spawn(); communicates with the parent through
    the shared array inside ``self.clock``.
    """

    STATE_LISTENING = "LISTENING"
    STATE_UNCALIBRATED = "UNCALIBRATED"
    STATE_SLAVE = "SLAVE"

    def __init__(
        self,
        master_ips: list[str],
        master_clock_identity: bytes | None,
        shared_clock_array,
        is_debug: bool = False,
        log_path: str | None = None,
    ):
        self.master_ips = list(master_ips)
        self.master_clock_identity = master_clock_identity
        self.is_debug = is_debug
        self.log_path = log_path
        self.clock = PTPDisciplinedClock(shared_clock_array)
        self.logger = None

        self._stop = False
        self._state = self.STATE_LISTENING
        self._local_clock_identity = _build_clock_identity()
        self._local_port_identity = ptpm.PortIdentity(self._local_clock_identity, 1)

        self._event_sock: socket.socket | None = None
        self._general_sock: socket.socket | None = None

        self._delay_req_seq = random.getrandbits(15)  # avoid 0
        self._pending_syncs: dict[int, _PendingSync] = {}
        self._pending_delay_reqs: dict[int, _PendingDelayReq] = {}

        self._sample_history: deque = deque(maxlen=MAX_SYNC_HISTORY)
        self._offset_history: deque = deque(maxlen=8)
        self._mean_path_delay_ns = 0
        self._integral_ns = 0.0
        self._last_master_seen_local_ns = 0
        self._last_delay_req_local_ns = 0
        self._first_lock = True

    # ------------- logging -------------

    def _setup_logger(self):
        log = logging.getLogger(f"PTPSlave-{os.getpid()}")
        log.setLevel(logging.DEBUG if self.is_debug else logging.INFO)
        if not log.handlers:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("%(asctime)s [PTP %(levelname)s] %(message)s"))
            log.addHandler(ch)
            if self.log_path:
                try:
                    fh = logging.FileHandler(self.log_path)
                    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
                    log.addHandler(fh)
                except OSError:
                    pass
        self.logger = log

    def _log(self, msg, level=logging.INFO):
        if self.logger:
            self.logger.log(level, msg)

    # ------------- main entry -------------

    def run(self):
        self._setup_logger()
        self._log(
            f"starting; masters={self.master_ips} "
            f"clockID={self.master_clock_identity.hex() if self.master_clock_identity else 'any'}"
        )
        try:
            self._event_sock = _make_event_socket()
            self._general_sock = _make_general_socket()
        except OSError as e:
            self._log(f"failed to bind PTP ports 319/320: {e!r} — slave aborting", logging.ERROR)
            self.clock.set_status(PTPDisciplinedClock.STATUS_UNSYNCED)
            return

        self._log(f"bound UDP/319 + UDP/320; localClockID={self._local_clock_identity.hex()}")
        self.clock.set_status(PTPDisciplinedClock.STATUS_ACQUIRING)
        try:
            self._loop()
        except KeyboardInterrupt:
            pass
        except Exception as e:  # noqa: BLE001
            self._log(f"unexpected error: {e!r}", logging.ERROR)
        finally:
            try:
                self._event_sock.close()
            except OSError:
                pass
            try:
                self._general_sock.close()
            except OSError:
                pass
            self.clock.set_status(PTPDisciplinedClock.STATUS_UNSYNCED)
            self._log("stopped")

    def _loop(self):
        socks = [self._event_sock, self._general_sock]
        while not self._stop:
            # Periodically initiate Delay_Req so we get path-delay samples.
            now = now_local_ns()
            if (now - self._last_delay_req_local_ns) >= int(DELAY_REQ_INTERVAL_S * 1e9):
                self._send_delay_req()
                self._last_delay_req_local_ns = now

            # Detect master disappearance.
            if (
                self._last_master_seen_local_ns
                and (now - self._last_master_seen_local_ns) > int(ANNOUNCE_TIMEOUT_S * 1e9)
                and self._state == self.STATE_SLAVE
            ):
                self._log("no PTP traffic from master — falling back to acquiring", logging.WARNING)
                self._state = self.STATE_UNCALIBRATED
                self.clock.set_status(PTPDisciplinedClock.STATUS_ACQUIRING)

            try:
                ready, _, _ = select.select(socks, [], [], 0.2)
            except (OSError, ValueError):
                break
            for s in ready:
                try:
                    data, addr = s.recvfrom(2048)
                except OSError:
                    continue
                rx_ns = now_local_ns()
                if not self._is_from_master(addr):
                    continue
                self._last_master_seen_local_ns = rx_ns
                if len(data) < ptpm.PTP_HEADER_LEN:
                    continue
                try:
                    msg = ptpm.parse(data)
                except (struct.error, ValueError):
                    continue
                self._dispatch(msg, rx_ns, addr, s is self._event_sock)

    # ------------- helpers -------------

    def _is_from_master(self, addr: tuple) -> bool:
        ip = addr[0]
        if not self.master_ips:
            return True
        if ip in self.master_ips:
            return True
        # iOS sometimes uses link-local v6 we filter v4-only; allow when only
        # v6 candidates were given.
        return False

    def _master_addr_for(self, port: int) -> tuple | None:
        if not self.master_ips:
            return None
        return (self.master_ips[0], port)

    # ------------- message dispatch -------------

    def _dispatch(self, msg: ptpm.PtpMessage, rx_local_ns: int, addr: tuple, on_event_socket: bool):
        mt = msg.msg_type
        if mt == ptpm.MsgType.ANNOUNCE:
            self._on_announce(msg)
        elif mt == ptpm.MsgType.SYNC:
            self._on_sync(msg, rx_local_ns)
        elif mt == ptpm.MsgType.FOLLOW_UP:
            self._on_follow_up(msg)
        elif mt == ptpm.MsgType.DELAY_RESP:
            self._on_delay_resp(msg)
        # ignore Pdelay / signaling / management

    def _on_announce(self, msg: ptpm.PtpMessage):
        if self._state == self.STATE_LISTENING:
            self._state = self.STATE_UNCALIBRATED
            self._log(f"master alive (seq={msg.header.sequence_id}) — UNCALIBRATED")

    def _on_sync(self, msg: ptpm.PtpMessage, t2_local_ns: int):
        if not isinstance(msg.body, ptpm.SyncBody):
            return
        seq = msg.header.sequence_id
        two_step = bool(msg.header.flags & ptpm.FlagBit.TWO_STEP)
        if two_step:
            # Master will send Follow_Up with the precise origin timestamp.
            self._pending_syncs[seq] = _PendingSync(
                seq=seq, t2_local_ns=t2_local_ns,
                t1_master_ns=0, two_step=True,
            )
        else:
            # One-step: this Sync already carries the originTimestamp.
            t1 = msg.body.origin_timestamp_ns + msg.header.correction_ns
            self._record_sync_sample(t1_master_ns=t1, t2_local_ns=t2_local_ns)

        # Garbage-collect stale pending syncs (>5s old)
        cutoff = now_local_ns() - 5_000_000_000
        stale = [s for s, p in self._pending_syncs.items() if p.t2_local_ns < cutoff]
        for s in stale:
            self._pending_syncs.pop(s, None)

    def _on_follow_up(self, msg: ptpm.PtpMessage):
        if not isinstance(msg.body, ptpm.FollowUpBody):
            return
        pending = self._pending_syncs.pop(msg.header.sequence_id, None)
        if not pending:
            return
        t1 = msg.body.precise_origin_timestamp_ns + msg.header.correction_ns
        self._record_sync_sample(t1_master_ns=t1, t2_local_ns=pending.t2_local_ns)

    def _on_delay_resp(self, msg: ptpm.PtpMessage):
        if not isinstance(msg.body, ptpm.DelayRespBody):
            return
        # Ensure the response was addressed to *our* port identity.
        if msg.body.requesting_port_identity.clock_identity != self._local_clock_identity:
            return
        pending = self._pending_delay_reqs.pop(msg.header.sequence_id, None)
        if not pending:
            return
        t4_master_ns = msg.body.receive_timestamp_ns - msg.header.correction_ns
        self._record_delay_sample(t3_local_ns=pending.t3_local_ns, t4_master_ns=t4_master_ns)

    # ------------- TX -------------

    def _send_delay_req(self):
        addr = self._master_addr_for(PTP_EVENT_PORT)
        if not addr or not self._event_sock:
            return
        self._delay_req_seq = (self._delay_req_seq + 1) & 0xFFFF
        seq = self._delay_req_seq
        pkt = ptpm.build_delay_req(self._local_port_identity, seq)
        try:
            t3 = now_local_ns()
            self._event_sock.sendto(pkt, addr)
        except OSError as e:
            self._log(f"sendto Delay_Req failed: {e!r}", logging.DEBUG)
            return
        self._pending_delay_reqs[seq] = _PendingDelayReq(seq=seq, t3_local_ns=t3)
        # GC stale
        if len(self._pending_delay_reqs) > 64:
            oldest = min(self._pending_delay_reqs, key=lambda k: self._pending_delay_reqs[k].t3_local_ns)
            self._pending_delay_reqs.pop(oldest, None)

    # ------------- servo -------------

    def _record_sync_sample(self, t1_master_ns: int, t2_local_ns: int):
        # Tentative offset using last known mean_path_delay.
        # offset = t2 - t1 - mean_path_delay
        offset = t2_local_ns - t1_master_ns - self._mean_path_delay_ns
        self._sample_history.append(("sync", t1_master_ns, t2_local_ns, offset))
        self._apply_offset_estimate(offset, t2_local_ns)

    def _record_delay_sample(self, t3_local_ns: int, t4_master_ns: int):
        # Need a recent t1/t2 to compute mean_path_delay; use most recent sync.
        recent_sync = None
        for entry in reversed(self._sample_history):
            if entry[0] == "sync":
                recent_sync = entry
                break
        if not recent_sync:
            return
        _, t1, t2, _ = recent_sync
        # mean_path_delay = ((t2 - t1) + (t4 - t3)) / 2  in master-equivalent ns
        # Note: this assumes the offset is small / stable across the exchange.
        forward = t2 - t1
        reverse = t4_master_ns - t3_local_ns
        mpd = (forward + reverse) // 2
        if mpd < 0:
            # invalid (clock not yet aligned), skip
            return
        # Reject outliers: keep median-based gate over the last 8 mpd samples.
        if self._mean_path_delay_ns > 0:
            limit = max(int(self._mean_path_delay_ns * OUTLIER_REJECT_FACTOR), 1_000_000)
            if mpd > limit:
                self._log(f"reject outlier mpd={mpd/1e6:.2f}ms (limit {limit/1e6:.2f}ms)", logging.DEBUG)
                return
        # EMA over mpd
        if self._mean_path_delay_ns == 0:
            self._mean_path_delay_ns = mpd
        else:
            self._mean_path_delay_ns = int(0.875 * self._mean_path_delay_ns + 0.125 * mpd)
        # Recompute offset of the recent sync with updated mpd
        new_offset = t2 - t1 - self._mean_path_delay_ns
        self._apply_offset_estimate(new_offset, t2)

    def _apply_offset_estimate(self, raw_offset_ns: int, sample_local_ns: int):
        """
        raw_offset_ns is the unprocessed (t2 - t1 - mpd) estimate of how far
        the *local raw* clock lags behind the *master raw* clock. To bring
        the disciplined clock onto the master timeline we need to *apply*
        `-raw_offset_ns` to local time — i.e. master = local + (-raw_offset).

        The "residual" is the gap between what we're currently applying and
        what we should apply: residual = (-raw_offset) - applied. When small,
        run a P servo over the residual. When large, step.
        """
        self._offset_history.append((sample_local_ns, raw_offset_ns))
        freq_ppb = self._estimate_freq_ppb()

        target_offset = -raw_offset_ns
        applied = self.clock.get_offset_ns()
        residual = target_offset - applied

        if self._first_lock:
            self._first_lock = False
            new_offset = target_offset
            self._integral_ns = 0.0
            status = PTPDisciplinedClock.STATUS_SYNCED
            self._state = self.STATE_SLAVE
            self._log(
                f"initial lock: raw_offset={raw_offset_ns/1e6:.3f}ms "
                f"applied={new_offset/1e6:+.3f}ms "
                f"mpd={self._mean_path_delay_ns/1e6:.3f}ms",
            )
        elif abs(residual) > RUNNING_STEP_THRESHOLD_NS:
            new_offset = target_offset
            self._integral_ns = 0.0
            status = PTPDisciplinedClock.STATUS_ACQUIRING
            self._log(
                f"large residual {residual/1e6:+.3f}ms — re-stepping to {target_offset/1e6:+.3f}ms",
                logging.WARNING,
            )
        else:
            self._integral_ns += residual * PI_KI
            self._integral_ns = max(min(self._integral_ns, 10_000_000.0), -10_000_000.0)
            new_offset = applied + int(residual * PI_KP + self._integral_ns)
            status = PTPDisciplinedClock.STATUS_SYNCED

        self.clock.update(
            offset_ns=new_offset,
            freq_ppb=freq_ppb,
            mean_path_delay_ns=self._mean_path_delay_ns,
            sync_local_ns=sample_local_ns,
            status=status,
        )

        if self.clock.get_sync_count() % 8 == 0:
            self._log(
                f"servo: applied={new_offset/1e6:+.3f}ms "
                f"residual={residual/1e6:+.3f}ms "
                f"raw={raw_offset_ns/1e6:+.3f}ms "
                f"mpd={self._mean_path_delay_ns/1e6:.3f}ms "
                f"freq={freq_ppb:+.1f}ppb",
                logging.DEBUG,
            )

    def _estimate_freq_ppb(self) -> float:
        """Slope of (offset_ns vs local_ns) over recent samples, returned as
        parts-per-billion. Positive means master ticks faster than local.
        """
        if len(self._offset_history) < 4:
            return 0.0
        xs = [s for s, _ in self._offset_history]
        ys = [o for _, o in self._offset_history]
        n = len(xs)
        mx = sum(xs) / n
        my = sum(ys) / n
        num = sum((xs[i] - mx) * (ys[i] - my) for i in range(n))
        den = sum((xs[i] - mx) ** 2 for i in range(n))
        if den == 0:
            return 0.0
        # d(offset)/d(t_local) is dimensionless; convert to ppb.
        slope = num / den
        # Clamp to sanity ±500 ppm
        if slope > 5e-4:
            slope = 5e-4
        if slope < -5e-4:
            slope = -5e-4
        return slope * 1e9


def make_shared_array():
    """Create a fresh shared-state Array for a PTPDisciplinedClock.

    Created externally so the same array can be passed to both the PTP slave
    process and the audio playback process(es).
    """
    array = multiprocessing.Array("d", 8, lock=False)
    for i in range(8):
        array[i] = 0.0
    return array


def _slave_entry(arr, ips, cid, debug, log_path):
    """Module-level entry point for the PTP slave child process.

    Must be top-level (not a closure) so Windows multiprocessing with the
    'spawn' start method can pickle it. Earlier versions had this as a
    nested function and silently broke on Windows.
    """
    slave = PTPSlave(
        master_ips=ips,
        master_clock_identity=cid,
        shared_clock_array=arr,
        is_debug=debug,
        log_path=log_path,
    )
    slave.run()


def spawn(
    master_ips: list[str],
    master_clock_identity: bytes | None = None,
    is_debug: bool = False,
    log_path: str | None = None,
    shared_array=None,
) -> tuple[multiprocessing.Process, PTPDisciplinedClock]:
    """Spawn a PTP slave process for the given master IPs.

    Returns (process, disciplined_clock). The clock object can be passed to
    any other process (it wraps a shared multiprocessing.Array). On master
    change, terminate this process and spawn a new one. Pass ``shared_array``
    to reuse an existing array (the audio processes already hold a view).
    """
    if shared_array is None:
        array = make_shared_array()
    else:
        array = shared_array

    proc = multiprocessing.Process(
        target=_slave_entry,
        args=(array, master_ips, master_clock_identity, is_debug, log_path),
        daemon=True,
    )
    proc.start()
    return proc, PTPDisciplinedClock(array)
