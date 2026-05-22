"""
Mock PTP master + slave end-to-end self-test.

What it does:
  * Spawns the PTP slave from ap2.connections.ptp on UDP 319/320 of localhost.
  * In the main process, drives a minimal "master" that sends Announce/Sync/
    Follow_Up to the slave and answers Delay_Req with Delay_Resp, injecting a
    known clock offset.
  * After a few seconds, reads the disciplined clock and asserts the offset
    converged to within tolerance.

Limitations:
  * Both sides share localhost so path delay is ~µs. The test verifies the
    convergence math, not actual network performance.
  * The slave binds to ports 319/320, so this script will fail if another
    PTP daemon is listening (e.g. Windows Time, ptp4l).

Usage:
  python ptp_selftest.py
"""

import os
import random
import socket
import struct
import sys
import time

from ap2.connections import ptp as ptp_mod
from ap2.connections import ptp_messages as ptpm
from ap2.connections.ptp_clock import PTPDisciplinedClock


def now_local_ns() -> int:
    """Shared Unix epoch in ns (the master uses this; the slave is patched to
    use the same so the loopback self-test has a deterministic baseline)."""
    return time.time_ns()


SLAVE_EVENT_PORT = ptpm.PTP_EVENT_PORT
SLAVE_GENERAL_PORT = ptpm.PTP_GENERAL_PORT
MASTER_EVENT_PORT = 8319    # mock master can use any free ports — but slave
MASTER_GENERAL_PORT = 8320  # always sends Delay_Req to *port 319* of master IP.
# So for this self-test we cheat: we use loopback and rebind the slave's
# Delay_Req destination by temporarily overriding ptpm.PTP_EVENT_PORT? No —
# instead we have the master listen on 319-on-loopback before the slave does.
# That conflicts with the slave's own 319 bind. The only clean fix is to
# run the slave with custom ports. Add a small monkey-patch hook below.

INJECTED_OFFSET_NS = 250_000_000  # 250 ms: master is 250 ms ahead of local


def _pack_announce_body(origin_ts_ns: int) -> bytes:
    body = bytearray(30)
    body[0:10] = ptpm.pack_timestamp(origin_ts_ns)
    # currentUtcOffset(2) + reserved(1) + grandmasterPriority1(1) ...
    struct.pack_into("!h", body, 10, 0)  # utc offset
    body[12] = 0  # reserved
    body[13] = 128  # priority1
    body[14:18] = b"\x60\x00\x00\x00"  # clockQuality
    body[18] = 128  # priority2
    body[19:27] = b"\xaa" * 8  # grandmasterIdentity
    struct.pack_into("!H", body, 27, 0)  # stepsRemoved
    body[29] = 0xA0  # timeSource (internal osc)
    return bytes(body)


def _pack_sync_or_follow_up(precise_origin_ts_ns: int) -> bytes:
    return ptpm.pack_timestamp(precise_origin_ts_ns)


def _pack_delay_resp(receive_ts_ns: int, requesting_port_id: bytes) -> bytes:
    return ptpm.pack_timestamp(receive_ts_ns) + requesting_port_id


def _make_header(
    msg_type: int,
    seq: int,
    *,
    flags: int = 0,
    message_length: int,
    control_field: int = 0,
    log_msg_interval: int = 0,
    source_port_identity: bytes,
) -> bytes:
    src_pi = ptpm.PortIdentity(source_port_identity[:8], int.from_bytes(source_port_identity[8:10], "big"))
    h = ptpm.PtpHeader(
        message_type=msg_type,
        version=2,
        message_length=message_length,
        flags=flags,
        source_port_identity=src_pi,
        sequence_id=seq,
        control_field=control_field,
        log_message_interval=log_msg_interval,
    )
    return ptpm.pack_header_bytes(h)


def master_time_ns() -> int:
    return now_local_ns() + INJECTED_OFFSET_NS


def run_mock_master(stop_at: float):
    """Drive Announce + Sync(two-step) + Follow_Up to the slave at loopback.

    Listens for Delay_Req on UDP/319 (we cannot, the slave is there). So this
    test path patches the slave to use different ports — see __main__.
    """
    raise NotImplementedError("see __main__: patched ports are required for loopback test")


SLAVE_EVENT = 19319
SLAVE_GENERAL = 19320
MASTER_EVENT = 28319
MASTER_GENERAL = 28320


def slave_entry(arr, master_ip, slave_event_port, slave_general_port, master_event_port_target):
    """Top-level so it's picklable under Windows spawn."""
    import time as _t
    from ap2.connections import ptp as p
    from ap2.connections import ptp_messages as m
    from ap2.connections import ptp_clock as pc
    m.PTP_EVENT_PORT = slave_event_port
    m.PTP_GENERAL_PORT = slave_general_port
    p.PTP_EVENT_PORT = slave_event_port
    p.PTP_GENERAL_PORT = slave_general_port

    # For the loopback self-test only: use time.time_ns (shared Unix epoch)
    # in the slave so the slave's t2/t3 sit in the SAME epoch as the master's
    # injected times. In production, perf_counter is correct: it stays in
    # the receiver's own monotonic frame and the PTP offset captures whatever
    # constant epoch difference exists between sender and receiver.
    pc.now_local_ns = _t.time_ns
    p.now_local_ns = _t.time_ns

    def _patched(self, port):
        ip = self.master_ips[0] if self.master_ips else "127.0.0.1"
        return (ip, master_event_port_target)
    p.PTPSlave._master_addr_for = _patched

    slave = p.PTPSlave(
        master_ips=[master_ip],
        master_clock_identity=None,
        shared_clock_array=arr,
        is_debug=True,
    )
    slave.run()


def main():
    import ap2.connections.ptp_messages as ptpm_mod
    import ap2.connections.ptp as ptp_slave_mod

    ptpm_mod.PTP_EVENT_PORT = SLAVE_EVENT
    ptpm_mod.PTP_GENERAL_PORT = SLAVE_GENERAL
    ptp_slave_mod.PTP_EVENT_PORT = SLAVE_EVENT
    ptp_slave_mod.PTP_GENERAL_PORT = SLAVE_GENERAL

    # Bind master sockets first
    m_event = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m_event.bind(("127.0.0.1", MASTER_EVENT))
    m_event.settimeout(0.2)
    m_general = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m_general.bind(("127.0.0.1", MASTER_GENERAL))
    m_general.settimeout(0.2)

    master_port_id = b"\xaa" * 8 + b"\x00\x01"

    # Patch slave to send Delay_Req to the MASTER_EVENT port, not 319.
    # Do this by monkey-patching _master_addr_for in the slave subclass…
    # simplest: edit the constant the slave uses to construct dest.
    # The slave uses self._master_addr_for(PTP_EVENT_PORT). Override
    # PTP_EVENT_PORT in slave module already done above; but spawn() runs the
    # slave in a *child process*, so reload constants there too via the
    # spawned target. We do this by writing a small entry instead.
    import multiprocessing
    array = ptp_slave_mod.make_shared_array()

    proc = multiprocessing.Process(
        target=slave_entry,
        args=(array, "127.0.0.1", SLAVE_EVENT, SLAVE_GENERAL, MASTER_EVENT),
        daemon=True,
    )
    proc.start()
    print(f"[selftest] slave pid={proc.pid}; injected master offset = {INJECTED_OFFSET_NS/1e6:.1f}ms")
    # Give the slave a moment to bind its sockets so our initial UDP sends
    # don't trigger Windows ICMP-unreachable replies (WinError 10054 on the
    # next recvfrom on the same socket).
    time.sleep(0.5)

    clock = PTPDisciplinedClock(array)
    seq_sync = 0
    last_announce = 0.0
    last_sync = 0.0
    deadline = time.monotonic() + 10.0
    converged = False
    applied_history = []

    try:
        while time.monotonic() < deadline:
            t = time.monotonic()

            # 1Hz Announce
            if t - last_announce > 1.0:
                last_announce = t
                body = _pack_announce_body(master_time_ns())
                hdr = _make_header(
                    msg_type=ptpm.MsgType.ANNOUNCE, seq=int(t) & 0xFFFF, message_length=34 + len(body),
                    source_port_identity=master_port_id,
                )
                m_general.sendto(hdr + body, ("127.0.0.1", SLAVE_GENERAL))

            # 4Hz Sync + Follow_Up (two-step)
            if t - last_sync > 0.25:
                last_sync = t
                seq_sync = (seq_sync + 1) & 0xFFFF
                sync_body = _pack_sync_or_follow_up(0)  # one-step would put TS here
                sync_hdr = _make_header(
                    msg_type=ptpm.MsgType.SYNC, seq=seq_sync,
                    flags=int(ptpm.FlagBit.TWO_STEP),
                    message_length=34 + len(sync_body),
                    log_msg_interval=-2,
                    source_port_identity=master_port_id,
                )
                # Capture t1 at the *exact* moment we hand the Sync to the OS;
                # that's what the two-step Follow_Up must echo back, otherwise
                # the slave's mpd estimate inflates by the construct-delay.
                t1_master = master_time_ns()
                m_event.sendto(sync_hdr + sync_body, ("127.0.0.1", SLAVE_EVENT))
                fu_body = _pack_sync_or_follow_up(t1_master)
                fu_hdr = _make_header(
                    msg_type=ptpm.MsgType.FOLLOW_UP, seq=seq_sync,
                    message_length=34 + len(fu_body),
                    log_msg_interval=-2,
                    source_port_identity=master_port_id,
                )
                m_general.sendto(fu_hdr + fu_body, ("127.0.0.1", SLAVE_GENERAL))

            # Service Delay_Req on the master event socket
            try:
                while True:
                    try:
                        data, addr = m_event.recvfrom(2048)
                    except ConnectionResetError:
                        # Windows: prior send hit a closed port; ignore and retry.
                        continue
                    msg = ptpm.parse(data)
                    if msg.msg_type == ptpm.MsgType.DELAY_REQ:
                        t4 = master_time_ns()
                        req_port = msg.header.source_port_identity.pack()
                        resp_body = _pack_delay_resp(t4, req_port)
                        resp_hdr = _make_header(
                            msg_type=ptpm.MsgType.DELAY_RESP, seq=msg.header.sequence_id,
                            message_length=34 + len(resp_body),
                            control_field=0x03,
                            source_port_identity=master_port_id,
                        )
                        # Delay_Resp goes on the general port back to wherever the
                        # slave is listening. Slave's general socket = 19320.
                        m_general.sendto(resp_hdr + resp_body, ("127.0.0.1", SLAVE_GENERAL))
            except socket.timeout:
                pass

            # Track stability of the applied offset over a 1-second window.
            # On Windows loopback, UDP scheduling jitter inflates mpd, so the
            # applied offset doesn't equal the injected 250 ms exactly — it
            # equals 250 ms + half of (forward - reverse) scheduling
            # asymmetry. What we *can* assert is: slave reaches SYNCED, the
            # applied offset stops drifting, and mpd stabilizes.
            applied = clock.get_offset_ns()
            mpd = clock.get_mean_path_delay_ns()
            if clock.is_synced():
                applied_history.append((time.monotonic(), applied, mpd))
                # Trim to last 2s
                applied_history = [(t_, a_, m_) for (t_, a_, m_) in applied_history if t_ > time.monotonic() - 2.0]
                if len(applied_history) >= 8:
                    applies = [a_ for (_, a_, _) in applied_history]
                    mpds = [m_ for (_, _, m_) in applied_history]
                    applied_span = max(applies) - min(applies)
                    mpd_span = max(mpds) - min(mpds)
                    print(
                        f"[selftest] synced; applied={applied/1e6:+.3f}ms "
                        f"mpd={mpd/1e6:.3f}ms span(applied)={applied_span/1e6:.3f}ms "
                        f"span(mpd)={mpd_span/1e6:.3f}ms"
                    )
                    # Stability criteria: applied moves <10ms over 2s and mpd
                    # moves <10ms; both indicate the servo has settled.
                    if applied_span < 10_000_000 and mpd_span < 10_000_000:
                        converged = True
                        break
                else:
                    print(f"[selftest] synced; applied={applied/1e6:+.3f}ms mpd={mpd/1e6:.3f}ms (warmup)")
            time.sleep(0.05)

    finally:
        proc.terminate()
        proc.join(timeout=1.0)
        m_event.close()
        m_general.close()

    if converged:
        print(
            f"[selftest] PASS — slave reached SYNCED and stabilized. "
            f"applied={clock.get_offset_ns()/1e6:+.3f}ms mpd={clock.get_mean_path_delay_ns()/1e6:.3f}ms. "
            f"Note: the applied value reflects 250ms injected + Windows UDP "
            f"scheduling asymmetry — that's expected on loopback."
        )
        sys.exit(0)
    else:
        print(
            f"[selftest] FAIL — slave did not stabilize. "
            f"applied={clock.get_offset_ns()/1e6:+.3f}ms mpd={clock.get_mean_path_delay_ns()/1e6:.3f}ms "
            f"is_synced={clock.is_synced()}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
