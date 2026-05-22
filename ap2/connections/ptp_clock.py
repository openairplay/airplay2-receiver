"""
PTP-disciplined clock state, shared across processes.

The PTP slave process writes (offset_ns, freq_ppb, mean_path_delay_ns, status)
into a multiprocessing.Array; the audio process reads it on a hot path and
converts a local perf_counter_ns() reading into a "master time" estimate.

Why perf_counter and not monotonic_ns:
  Windows time.monotonic_ns() resolution is ~15.6 ms — too coarse for PTP.
  time.perf_counter_ns() uses QueryPerformanceCounter on Windows
  (~100 ns resolution) and CLOCK_MONOTONIC_RAW elsewhere. We use it both
  here and inside the slave's tx/rx timestamping path so the same epoch
  is shared.
"""

import multiprocessing
import struct
import time


# Layout of the shared state array (8 doubles, packed for atomic-ish reads):
#   [0] offset_ns       — master_time - local_perf_counter at sync_local_ns
#   [1] freq_ppb        — frequency adjustment (master ticks per local tick - 1) * 1e9
#   [2] sync_local_ns   — local perf_counter at which (offset_ns, freq_ppb) were valid
#   [3] mean_path_delay_ns
#   [4] last_update_local_ns — perf_counter at last update (for staleness check)
#   [5] status           — 0=unsynced, 1=acquiring, 2=synced
#   [6] sync_count       — incremented each successful update
#   [7] reserved
_SLOT_COUNT = 8


def now_local_ns() -> int:
    return time.perf_counter_ns()


class PTPDisciplinedClock:
    """Shared-state wrapper around the PTP slave's current discipline estimate.

    Instances of this class are cheap to construct in any process: they all
    wrap the same multiprocessing.Array. The slave process holds one as the
    writer; consumers (audio playback) hold one as readers.

    Reads do NOT take the lock: they return possibly-torn views. We tolerate
    that because: (a) updates land at most once per ~1s; (b) we re-poll
    frequently; (c) torn reads can only briefly produce a sub-ms outlier
    which the playback path already smooths over.
    """

    STATUS_UNSYNCED = 0
    STATUS_ACQUIRING = 1
    STATUS_SYNCED = 2

    def __init__(self, shared_array=None):
        if shared_array is None:
            shared_array = multiprocessing.Array("d", _SLOT_COUNT, lock=False)
            shared_array[0] = 0.0
            shared_array[1] = 0.0
            shared_array[2] = 0.0
            shared_array[3] = 0.0
            shared_array[4] = 0.0
            shared_array[5] = float(self.STATUS_UNSYNCED)
            shared_array[6] = 0.0
            shared_array[7] = 0.0
        self._arr = shared_array

    @property
    def shared_array(self):
        return self._arr

    # -------- writer side (called by the PTP slave) --------

    def update(
        self,
        offset_ns: int,
        freq_ppb: float,
        mean_path_delay_ns: int,
        sync_local_ns: int,
        status: int,
    ) -> None:
        # Order matters slightly for readers: bump sync_count last so a
        # reader that sees a fresh sync_count sees fresh fields.
        self._arr[0] = float(offset_ns)
        self._arr[1] = float(freq_ppb)
        self._arr[2] = float(sync_local_ns)
        self._arr[3] = float(mean_path_delay_ns)
        self._arr[4] = float(now_local_ns())
        self._arr[5] = float(status)
        self._arr[6] = self._arr[6] + 1.0

    def set_status(self, status: int) -> None:
        self._arr[5] = float(status)
        self._arr[4] = float(now_local_ns())

    # -------- reader side (called by audio path) --------

    def now_master_ns(self, local_ns: int | None = None) -> int:
        """Convert a local perf_counter_ns reading to estimated master time.

        master_time(t) = offset + (t - sync_local) * (1 + freq_ppb*1e-9) + sync_local
                       = t + offset + (t - sync_local) * freq_ppb*1e-9

        When unsynced, returns the local time unchanged. Caller can check
        get_status() to decide whether to wait.
        """
        if local_ns is None:
            local_ns = now_local_ns()
        # Use the explicit status field — a legitimate sync can land at
        # offset==0 and freq_ppb==0 (loopback self-test, or two clocks
        # genuinely in agreement) and we'd still want to apply discipline
        # (here a no-op, but the status check correctly says "we're synced").
        if int(self._arr[5]) < self.STATUS_SYNCED:
            return local_ns
        offset = self._arr[0]
        freq_ppb = self._arr[1]
        sync_local = self._arr[2]
        elapsed = local_ns - sync_local
        drift = elapsed * freq_ppb * 1e-9
        return int(local_ns + offset + drift)

    def get_offset_ns(self) -> int:
        return int(self._arr[0])

    def get_mean_path_delay_ns(self) -> int:
        return int(self._arr[3])

    def get_status(self) -> int:
        return int(self._arr[5])

    def is_synced(self) -> bool:
        return self.get_status() == self.STATUS_SYNCED

    def staleness_ns(self) -> int:
        last = self._arr[4]
        if last == 0.0:
            return -1
        return now_local_ns() - int(last)

    def get_sync_count(self) -> int:
        return int(self._arr[6])
