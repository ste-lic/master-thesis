#!/usr/bin/env python3
"""
boofuzz fuzzer for the ESP32-C3 Modbus RTU slave (mySlave_bugs123.ino).

Two SEPARATE serial connections are required, matching the firmware's own
architecture:

    /dev/ttyUSB0 (USB-to-TTL adapter wired to GPIO20=RX1/GPIO21=TX1, GND)
        -> the real Modbus RTU UART (Serial1, 9600 baud). This is where
           fuzzed frames are sent; only this port is ever read by the
           firmware's receiveBytes()/processFrame().

    /dev/ttyACM0 (the board's own native USB port)
        -> the debug console (Serial, 115200 baud). Write-only from the
           firmware's perspective -- never parsed as Modbus input -- but
           it prints a boot banner, a "Heartbeat OK ..." line every 5s,
           and, critically, prints the literal string
               "=== CANARY CORRUPTED ==="
           exactly once, the instant any of the three implanted bugs
           corrupts the canary (checkCanary(), called after every write).
           The firmware then halts permanently: no more Modbus replies,
           no more heartbeats, until the board is physically reset.

This replaces the earlier timing-based liveness-probe oracle entirely.
That approach assumed a request/response oracle running on the same link
as the fuzzed traffic; it doesn't match this firmware (which never reads
Serial as input) and was the direct cause of the earlier all-crash /
zero-crash contradictions. Watching for the firmware's own explicit
crash string on its debug console is simpler and load-bearing on nothing
but the literal text the firmware already prints.

Usage:
    python3 boofuzz_modbus_esp32.py --fuzz-port /dev/ttyUSB0 \\
                                     --debug-port /dev/ttyACM0

Requires: pip install boofuzz pyserial
Web UI: http://localhost:26000
"""

import argparse
import struct
import sys
import time

import serial

from boofuzz import (
    BaseMonitor,
    Block,
    Byte,
    Bytes,
    Checksum,
    Request,
    Session,
    SerialConnection,
    Static,
    Target,
)

MODBUS_SLAVE_ID = 0x01
NUM_REGISTERS = 10  # from mySlave_bugs123.ino: holdingRegisters[NUM_REGISTERS]

# Settle time between sending a fuzzed frame and checking the debug console
# for the crash string. Must cover: the firmware's own FRAME_TIMEOUT_MS (10ms
# inter-byte silence before it even starts parsing), handler execution, and
# the debug message's actual USB transit time. Mirrors the 300ms delay the
# original Flipper oracle used for the same reason.
POST_SEND_SETTLE_S = 0.3


# ---------------------------------------------------------------------
# CRC-16/MODBUS (poly 0xA001), low byte first on the wire -- identical to
# crc16() in mySlave_bugs123.ino.
# ---------------------------------------------------------------------
def modbus_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def modbus_crc16_checksum_fn(data: bytes) -> bytes:
    return struct.pack("<H", modbus_crc16(data))


# ---------------------------------------------------------------------
# Request definitions -- one per Modbus function code the firmware
# actually parses (handleReadHoldingRegisters / handleWriteSingleRegister /
# handleWriteMultipleRegisters).
# ---------------------------------------------------------------------
def build_requests():
    requests = []

    # FC=0x03 Read Holding Registers -- Bug 2 (quantity > 125 overflows the
    # 253-byte response buffer; see handleReadHoldingRegisters()).
    req = Request(
        "fc03_read_holding_registers",
        children=(
            Block(
                "body",
                children=(
                    Byte(name="slave_id", default_value=MODBUS_SLAVE_ID, fuzzable=False),
                    Static(name="function_code", default_value=b"\x03"),
                    Byte(name="start_addr_hi", default_value=0x00, fuzzable=False),
                    Byte(name="start_addr_lo", default_value=0x00, fuzzable=False),
                    Byte(name="quantity_hi", default_value=0x00, fuzzable=False),
                    Byte(
                        name="quantity_lo",
                        default_value=0x01,
                        fuzz_values=[10, 100, 124, 125, 126, 127, 200, 250, 255],
                    ),
                ),
            ),
            Checksum(name="crc", block_name="body", algorithm=modbus_crc16_checksum_fn, length=2, fuzzable=False),
        ),
    )
    requests.append(req)

    # FC=0x06 Write Single Register -- Bug 3 (off-by-one: addr == 10 passes
    # the `addr > NUM_REGISTERS` check and corrupts the canary directly).
    req = Request(
        "fc06_write_single_register",
        children=(
            Block(
                "body",
                children=(
                    Byte(name="slave_id", default_value=MODBUS_SLAVE_ID, fuzzable=False),
                    Static(name="function_code", default_value=b"\x06"),
                    Byte(name="address_hi", default_value=0x00, fuzzable=False),
                    Byte(
                        name="address_lo",
                        default_value=0x00,
                        fuzz_values=[0, 5, 9, NUM_REGISTERS, NUM_REGISTERS + 1, 50, 255],
                    ),
                    Byte(name="value_hi", default_value=0x11, fuzzable=False),
                    Byte(name="value_lo", default_value=0x11, fuzzable=False),
                ),
            ),
            Checksum(name="crc", block_name="body", algorithm=modbus_crc16_checksum_fn, length=2, fuzzable=False),
        ),
    )
    requests.append(req)

    # FC=0x10 Write Multiple Registers -- Bug 1 (byteCount used directly in
    # memcpy(), no bound against NUM_REGISTERS*2 == 20 bytes of capacity).
    #
    # IMPORTANT (fixed vs. the earlier version of this script): the firmware
    # requires `len >= 7 + byteCount` actual bytes to be present in the
    # frame (handleWriteMultipleRegisters(), the "minimum data present"
    # check) or it returns an exception instead of ever reaching the
    # vulnerable memcpy. So the payload here is a FIXED 255-byte block --
    # comfortably more than any possible byteCount value (0-255) -- with
    # only byte_count itself fuzzed. This guarantees the length check
    # always passes while the vulnerable memcpy still only copies exactly
    # `byte_count` bytes, exactly matching the real code path.
    req = Request(
        "fc10_write_multiple_registers",
        children=(
            Block(
                "body",
                children=(
                    Byte(name="slave_id", default_value=MODBUS_SLAVE_ID, fuzzable=False),
                    Static(name="function_code", default_value=b"\x10"),
                    Byte(name="start_addr_hi", default_value=0x00, fuzzable=False),
                    Byte(name="start_addr_lo", default_value=0x00, fuzzable=False),
                    Byte(name="quantity_hi", default_value=0x00, fuzzable=False),
                    Byte(name="quantity_lo", default_value=0x01, fuzzable=False),
                    Byte(
                        name="byte_count",
                        default_value=0x02,
                        fuzz_values=[2, 10, 20, 21, 50, 100, 200, 255],
                    ),
                    Bytes(name="payload", default_value=bytes([0xFF] * 255), fuzzable=False),
                ),
            ),
            Checksum(name="crc", block_name="body", algorithm=modbus_crc16_checksum_fn, length=2, fuzzable=False),
        ),
    )
    requests.append(req)

    return requests


# ---------------------------------------------------------------------
# Monitor -- watches the SEPARATE debug console (/dev/ttyACM0) for three
# independent anomaly signals, since we confirmed (by comparing the
# printed addresses of `canary` and `holdingRegisters[0]` on the real
# board: 0x3FC8E40C vs 0x3FC90390, ~8KB apart) that the canary is NOT
# adjacent to holdingRegisters[] in the actual compiled binary. Bug 1's
# and Bug 3's overflows land nowhere near it, so watching only for
# "=== CANARY CORRUPTED ===" (the old design) can never catch them.
#
# Instead of assuming a specific corruption target, this monitor watches
# for three independent, assumption-light symptoms:
#
#   1. Heartbeat gap: the firmware prints "Heartbeat OK ..." every 5s
#      unconditionally. If none arrives for HEARTBEAT_TIMEOUT_S, the
#      main loop is hung, regardless of what got corrupted.
#   2. Register/canary value drift: every heartbeat line already reports
#      Reg[0] and Canary -- if either differs from its known-good
#      baseline, something was corrupted, even if the board is still
#      running and never hangs or reboots.
#   3. Boot banner reappearance: if the board hard-crashed and the
#      hardware watchdog/reset fired, "=== Modbus RTU Slave ..." prints
#      again. Since we no longer know whether this board halts forever
#      or recovers on its own, this monitor does NOT latch permanently --
#      each test case is evaluated independently against current state.
# ---------------------------------------------------------------------
BOOT_BANNER_MARKER = b"=== Modbus RTU Slave"
HEARTBEAT_MARKER = b"Heartbeat OK"
# Confirmed present in real captured output: genuine ESP-IDF/toolchain-level
# panics, independent of the sketch's own software `canary` global (which we
# confirmed sits ~8KB away from holdingRegisters[] and is never reached).
# These are the same two crash signatures the original Flipper Zero campaign
# watched for.
CRASH_MARKERS = (b"Stack smashing protect failure", b"Guru Meditation Error")
REG0_BASELINE = 0x1000
CANARY_BASELINE = 0xDEADBEEF
HEARTBEAT_TIMEOUT_S = 12.0  # comfortably more than the firmware's 5s heartbeat interval


def parse_heartbeat_values(line: bytes):
    """Parses 'Heartbeat OK. Reg[0]=0x1000  Canary=0xDEADBEEF' -> (0x1000, 0xDEADBEEF).
    Returns (None, None) if the line doesn't match the expected shape."""
    try:
        text = line.decode(errors="ignore")
        reg_part = text.split("Reg[0]=0x", 1)[1]
        reg_val = int(reg_part.split()[0], 16)
        canary_part = text.split("Canary=0x", 1)[1]
        canary_val = int(canary_part.strip(), 16)
        return reg_val, canary_val
    except (IndexError, ValueError):
        return None, None


class HeartbeatAnomalyMonitor(BaseMonitor):
    """boofuzz Monitor. Opens its own persistent serial connection to the
    board's native USB debug console and, on every post_send(), drains
    whatever text has accumulated, checking three independent signals:

      1. The two real ESP-IDF/toolchain crash strings confirmed present
         in actual captured runs ("Stack smashing protect failure!" and
         "Guru Meditation Error"), printed by the compiler's own stack
         protector and the hardware panic handler -- entirely separate
         from the sketch's own software `canary` global, which we
         confirmed is unreachable (its address is ~8KB away from
         holdingRegisters[] in the actual compiled binary).
      2. Heartbeat gap (main loop hung, regardless of cause).
      3. Canary value drift reported in each heartbeat line.

    Reg[0] is still parsed and tracked (visible in the diagnostic log)
    but NOT used to fail a test case: fc06 and fc10 both legitimately
    write to register 0 whenever their fuzzed address/start_addr happens
    to be 0, and that value then persists across all subsequent test
    cases until the next reboot (nothing else resets it). Comparing it
    against a fixed baseline produced a cascade of false positives on
    real hardware -- confirmed from a captured run where 6 consecutive
    "corrupted" verdicts on fc06/fc10 all traced back to one earlier,
    perfectly legitimate write, not to any bug. Worse, those false
    positives were tripping boofuzz's own crash_threshold_element safety
    valve, causing it to abandon most of fc06's and fc10's mutation
    ranges before ever reaching their real trigger values.

    Confirmed empirically: this board recovers on its own after a crash
    (the boot banner reprints and heartbeats resume with baseline values
    within a few seconds), so this monitor does NOT latch -- every test
    case is judged against current state.
    """

    def __init__(self, debug_port: str, debug_baud: int = 115200):
        super().__init__()
        self._debug_conn = serial.Serial(port=debug_port, baudrate=debug_baud, timeout=0)
        self._buffer = b""
        self._last_heartbeat_time = time.monotonic()
        self._last_reg0 = REG0_BASELINE
        self._last_canary = CANARY_BASELINE
        self._crash_marker_seen = None
        self._last_synopsis = ""

    def _drain_and_update(self, fuzz_data_logger=None):
        new_bytes = self._debug_conn.read(self._debug_conn.in_waiting or 1)
        self._buffer += new_bytes
        # process complete lines only; keep any trailing partial line buffered
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)

            if fuzz_data_logger is not None and line.strip():
                fuzz_data_logger.log_info(f"[debug console] {line!r}")

            for marker in CRASH_MARKERS:
                if marker in line:
                    self._crash_marker_seen = line.strip().decode(errors="ignore")

            if HEARTBEAT_MARKER in line:
                self._last_heartbeat_time = time.monotonic()
                reg0, canary = parse_heartbeat_values(line)
                if reg0 is not None:
                    self._last_reg0 = reg0
                if canary is not None:
                    self._last_canary = canary
                if fuzz_data_logger is not None:
                    fuzz_data_logger.log_info(
                        f"[debug console] parsed heartbeat -> reg0={reg0!r} canary={canary!r}"
                    )

            if BOOT_BANNER_MARKER in line:
                # board just (re)booted -- fresh state, reset our tracking
                self._last_heartbeat_time = time.monotonic()
                self._last_reg0 = REG0_BASELINE
                self._last_canary = CANARY_BASELINE

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        time.sleep(POST_SEND_SETTLE_S)
        self._crash_marker_seen = None
        self._drain_and_update(fuzz_data_logger=fuzz_data_logger)

        if self._crash_marker_seen is not None:
            self._last_synopsis = (
                f"Debug console printed crash signature: {self._crash_marker_seen!r} -- "
                "genuine hardware panic (independent of the sketch's software canary check)."
            )
            return False

        gap = time.monotonic() - self._last_heartbeat_time
        if gap > HEARTBEAT_TIMEOUT_S:
            self._last_synopsis = (
                f"No heartbeat for {gap:.1f}s (limit {HEARTBEAT_TIMEOUT_S}s) -- "
                "main loop appears hung."
            )
            return False

        if self._last_canary != CANARY_BASELINE:
            self._last_synopsis = (
                f"Heartbeat reported Canary=0x{self._last_canary:08X}, expected "
                f"0x{CANARY_BASELINE:08X} -- canary corrupted."
            )
            return False

        return True

    def get_crash_synopsis(self):
        return self._last_synopsis


# ---------------------------------------------------------------------
# Wiring it together
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fuzz-port", required=True, help="USB-to-TTL adapter device, e.g. /dev/ttyUSB0")
    parser.add_argument("--debug-port", required=True, help="Board's native USB console, e.g. /dev/ttyACM0")
    parser.add_argument("--fuzz-baud", type=int, default=9600, help="Modbus UART baud rate (default: 9600)")
    parser.add_argument("--debug-baud", type=int, default=115200, help="Debug console baud rate (default: 115200)")
    args = parser.parse_args()

    fuzz_connection = SerialConnection(port=args.fuzz_port, baudrate=args.fuzz_baud, timeout=2)
    monitor = HeartbeatAnomalyMonitor(debug_port=args.debug_port, debug_baud=args.debug_baud)
    target = Target(connection=fuzz_connection, monitors=[monitor])

    session = Session(target=target)

    for req in build_requests():
        session.connect(req)

    session.fuzz()


if __name__ == "__main__":
    sys.exit(main())
