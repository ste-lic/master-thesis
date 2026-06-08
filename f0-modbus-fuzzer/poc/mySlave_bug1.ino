/*
 * custom_modbus_slave_bug1.ino
 *
 * Modbus RTU Slave — Bug 1 planted (buffer overflow in FC=0x10 handler).
 *
 * CHANGES FROM BASELINE (custom_modbus_slave_week1.ino):
 *   - Added a canary value immediately after holdingRegisters[] in memory.
 *   - handleWriteMultipleRegisters() no longer validates that byteCount <= NUM_REGISTERS*2.
 *     It trusts byteCount directly and uses it to drive a memcpy into the register array.
 *   - checkCanary() is called after every write. If the canary is corrupted, the slave
 *     prints a crash log to Serial and halts (simulating a DoS / unresponsive device).
 *   - Everything else (FC=0x03, FC=0x06, CRC, framing) is identical to the clean baseline.
 *
 * BUG CLASS:
 *   Missing input validation on a length field leads to heap/stack buffer overflow.
 *   Real-world analogue: CVE-2022-30264 (OpenPLC Runtime, Modbus TCP write handler),
 *   and the class of bugs reported in WAGO PLC Modbus implementations (ICS-CERT Advisory
 *   ICSA-19-099-04, 2019).
 *
 * TRIGGER CONDITIONS:
 *   Send FC=0x10, any valid start address, quantity Q, but set byteCount > Q*2.
 *   The handler will memcpy byteCount bytes (from the request payload) into a buffer
 *   sized for Q*2 bytes, overflowing into the canary and adjacent stack variables.
 *   Example trigger frame (slave 0x01, start addr 0x0000, qty 0x0001, byteCount 0x64):
 *     01 10 00 00 00 01 64 [100 bytes of data] [CRC]
 *
 * OBSERVABLE SYMPTOM:
 *   Slave stops responding. Serial Monitor shows "CANARY CORRUPTED" followed by an
 *   infinite halt. The Flipper oracle detects this as: response timeout on the
 *   liveness-check request sent after the fuzz case.
 *
 * DETECTION EXPECTED FROM FUZZER:
 *   Any test case that sends FC=0x10 with byteCount > actual data bytes (or byteCount >
 *   NUM_REGISTERS*2) should trigger this. The Flipper's "oversized byteCount" test case
 *   (test case type 1 in Week 3 expansion) is the primary trigger.
 */

// ─── Configuration ────────────────────────────────────────────────────────────
#define SLAVE_ID        1
#define BAUD_RATE       9600
#define RX_PIN          20      // ESP32-C3 GPIO20 = UART1 RX
#define TX_PIN          21      // ESP32-C3 GPIO21 = UART1 TX
#define NUM_REGISTERS   10      // number of holding registers
#define MAX_FRAME_SIZE  256     // receive buffer size
#define FRAME_TIMEOUT_MS 10     // inter-frame gap in ms (≈3.5 char times at 9600 baud)

// ─── Canary ───────────────────────────────────────────────────────────────────
// Placed immediately after holdingRegisters[] in declaration order so that a
// buffer overflow past the end of the array corrupts it first.
// Value chosen to be recognisable and unlikely to appear as valid register data.
#define CANARY_VALUE    0xDEADBEEF

// ─── Data storage ─────────────────────────────────────────────────────────────
// IMPORTANT: do NOT insert any variable between holdingRegisters and canary.
// The overflow must reach canary before corrupting anything else.
uint16_t holdingRegisters[NUM_REGISTERS];
volatile uint32_t canary = CANARY_VALUE;   // <<< canary sits immediately after array

// ─── Reception state ──────────────────────────────────────────────────────────
static uint8_t  rxBuf[MAX_FRAME_SIZE];
static uint16_t rxLen      = 0;
static uint32_t lastByteMs = 0;
static bool     frameReady = false;

// ─── Slave state ──────────────────────────────────────────────────────────────
static bool halted = false;   // set to true when canary corruption is detected

// ─── CRC-16 ───────────────────────────────────────────────────────────────────
// Algorithm: CRC-16/IBM (Modbus variant). Polynomial 0xA001, init 0xFFFF, LSB-first.
// Source: Modbus over Serial Line Specification V1.02, §3.2.6 (Modbus-IDA, 2006).
uint16_t crc16(const uint8_t *buf, uint16_t len) {
  uint16_t crc = 0xFFFF;
  for (uint16_t i = 0; i < len; i++) {
    crc ^= (uint16_t)buf[i];
    for (uint8_t b = 0; b < 8; b++) {
      if (crc & 0x0001) { crc = (crc >> 1) ^ 0xA001; }
      else              { crc >>= 1; }
    }
  }
  return crc;
}

// ─── Response helpers ─────────────────────────────────────────────────────────
void sendResponse(uint8_t *payload, uint8_t payloadLen) {
  uint16_t crc = crc16(payload, payloadLen);
  Serial1.write(payload, payloadLen);
  Serial1.write((uint8_t)(crc & 0xFF));
  Serial1.write((uint8_t)(crc >> 8));
}

// Modbus exception response. fc = original function code (high bit will be set).
// exCode: 0x01 illegal function, 0x02 illegal data address, 0x03 illegal data value.
// Source: Modbus Application Protocol Specification V1.1b3, §7 (Modbus-IDA, 2012).
void sendException(uint8_t fc, uint8_t exCode) {
  uint8_t pdu[3];
  pdu[0] = SLAVE_ID;
  pdu[1] = fc | 0x80;
  pdu[2] = exCode;
  sendResponse(pdu, 3);
}

// ─── Canary check ─────────────────────────────────────────────────────────────
// Called after every write operation. If the canary has changed, the overflow
// has occurred. We log it and halt — simulating a crashed/unresponsive device.
void checkCanary() {
  if (canary != CANARY_VALUE) {
    Serial.println("=== CANARY CORRUPTED ===");
    Serial.print("Expected: 0x");
    Serial.println(CANARY_VALUE, HEX);
    Serial.print("Got:      0x");
    Serial.println(canary, HEX);
    Serial.println("Slave halting. No further responses will be sent.");
    Serial.println("This simulates a real crash / DoS condition.");
    halted = true;
    // Drain UART so the master gets silence, not garbage.
    while (Serial1.available()) Serial1.read();
  }
}

// ─── FC=0x03: Read Holding Registers ─────────────────────────────────────────
// No bugs in this handler. Same as clean baseline.
void handleReadHoldingRegisters(uint8_t *frame, uint16_t len) {
  if (len < 6) { sendException(0x03, 0x03); return; }

  uint16_t startAddr = ((uint16_t)frame[2] << 8) | frame[3];
  uint16_t quantity  = ((uint16_t)frame[4] << 8) | frame[5];

  if (quantity == 0 || quantity > 125) { sendException(0x03, 0x03); return; }
  if (startAddr + quantity > NUM_REGISTERS) { sendException(0x03, 0x02); return; }

  uint8_t byteCount = (uint8_t)(quantity * 2);
  uint8_t pdu[3 + 250]; // max 125 registers * 2 bytes + header
  pdu[0] = SLAVE_ID;
  pdu[1] = 0x03;
  pdu[2] = byteCount;
  for (uint16_t i = 0; i < quantity; i++) {
    pdu[3 + i*2]     = (uint8_t)(holdingRegisters[startAddr + i] >> 8);
    pdu[3 + i*2 + 1] = (uint8_t)(holdingRegisters[startAddr + i] & 0xFF);
  }
  sendResponse(pdu, 3 + byteCount);
}

// ─── FC=0x06: Write Single Register ──────────────────────────────────────────
// No bugs in this handler. Same as clean baseline.
void handleWriteSingleRegister(uint8_t *frame, uint16_t len) {
  if (len < 6) { sendException(0x06, 0x03); return; }

  uint16_t addr  = ((uint16_t)frame[2] << 8) | frame[3];
  uint16_t value = ((uint16_t)frame[4] << 8) | frame[5];

  if (addr >= NUM_REGISTERS) { sendException(0x06, 0x02); return; }

  holdingRegisters[addr] = value;
  checkCanary();

  // Echo back the request (standard Modbus FC=0x06 response).
  uint8_t pdu[6];
  pdu[0] = SLAVE_ID; pdu[1] = 0x06;
  pdu[2] = frame[2]; pdu[3] = frame[3];
  pdu[4] = frame[4]; pdu[5] = frame[5];
  sendResponse(pdu, 6);
}

// ─── FC=0x10: Write Multiple Registers ───────────────────────────────────────
// *** BUG 1 IS HERE ***
//
// The handler reads byteCount from the request frame and uses it directly in a
// memcpy without checking whether byteCount exceeds the capacity of holdingRegisters.
//
// A correct implementation would validate: byteCount == quantity * 2
// and also: startAddr + quantity <= NUM_REGISTERS.
// Both checks have been intentionally removed.
//
// With the validation removed, an attacker can send any value in byteCount (up to
// the remaining bytes in the receive buffer). The memcpy writes that many bytes
// starting at &holdingRegisters[startAddr], overflowing into canary and beyond.
//
// BUG TYPE: CWE-120 (Buffer Copy without Checking Size of Input).
void handleWriteMultipleRegisters(uint8_t *frame, uint16_t len) {
  if (len < 7) { sendException(0x10, 0x03); return; }

  uint16_t startAddr = ((uint16_t)frame[2] << 8) | frame[3];
  uint16_t quantity  = ((uint16_t)frame[4] << 8) | frame[5];
  uint8_t  byteCount = frame[6];   // <<<< trusted directly, no validation

  // Minimum data present check only (not a safety check — just avoids reading
  // past rxBuf boundary, which would be a separate memory corruption issue).
  if (len < (uint16_t)(7 + byteCount)) { sendException(0x10, 0x03); return; }

  // *** VULNERABLE LINE ***
  // byteCount is not checked against NUM_REGISTERS*2. If byteCount > 20
  // (i.e., > 10 registers * 2 bytes), this overflows past holdingRegisters[]
  // and into canary and adjacent stack memory.
  memcpy((uint8_t *)(&holdingRegisters[startAddr]), &frame[7], byteCount);

  checkCanary();  // will halt the slave if canary was corrupted

  if (halted) return;  // don't send a response after halting

  // Normal response: echo slave ID, function code, start address, quantity.
  uint8_t pdu[6];
  pdu[0] = SLAVE_ID; pdu[1] = 0x10;
  pdu[2] = frame[2]; pdu[3] = frame[3];
  pdu[4] = frame[4]; pdu[5] = frame[5];
  sendResponse(pdu, 6);
}

// ─── Frame processor ─────────────────────────────────────────────────────────
void processFrame() {
  if (rxLen < 4) return;  // minimum valid frame: ID + FC + CRC = 4 bytes

  // CRC check: last two bytes are CRC (little-endian).
  uint16_t receivedCRC = ((uint16_t)rxBuf[rxLen-1] << 8) | rxBuf[rxLen-2];
  uint16_t computedCRC = crc16(rxBuf, rxLen - 2);
  if (receivedCRC != computedCRC) {
    // Silent discard on CRC failure — correct Modbus RTU behaviour.
    // Source: Modbus over Serial Line Specification V1.02, §2.5.1.
    return;
  }

  // Slave ID check.
  if (rxBuf[0] != SLAVE_ID) return;  // not addressed to us

  // If slave has halted due to canary corruption, ignore all further requests.
  if (halted) return;

  uint8_t fc = rxBuf[1];
  switch (fc) {
    case 0x03: handleReadHoldingRegisters(rxBuf, rxLen - 2); break;
    case 0x06: handleWriteSingleRegister(rxBuf, rxLen - 2);  break;
    case 0x10: handleWriteMultipleRegisters(rxBuf, rxLen - 2); break;
    default:
      // Illegal function — standard exception response.
      sendException(fc, 0x01);
      break;
  }
}

// ─── Byte reception ───────────────────────────────────────────────────────────
void receiveBytes() {
  while (Serial1.available()) {
    if (rxLen >= MAX_FRAME_SIZE) rxLen = 0;  // overflow guard
    rxBuf[rxLen++] = (uint8_t)Serial1.read();
    lastByteMs = millis();
    frameReady = false;
  }
}

void checkFrameComplete() {
  if (rxLen > 0 && !frameReady && (millis() - lastByteMs >= FRAME_TIMEOUT_MS)) {
    frameReady = true;
    processFrame();
    rxLen = 0;
    frameReady = false;
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial1.begin(BAUD_RATE, SERIAL_8N1, RX_PIN, TX_PIN);

  // Initialise registers to recognisable values for easy verification.
  for (int i = 0; i < NUM_REGISTERS; i++) {
    holdingRegisters[i] = 0x1000 + i;
  }

  Serial.println("=== Modbus RTU Slave — Bug 1 (buffer overflow in FC=0x10) ===");
  Serial.print("Slave ID: "); Serial.println(SLAVE_ID);
  Serial.print("Baud: ");     Serial.println(BAUD_RATE);
  Serial.print("Registers: "); Serial.println(NUM_REGISTERS);
  Serial.print("Canary address: 0x"); Serial.println((uint32_t)&canary, HEX);
  Serial.print("Canary value:   0x"); Serial.println(canary, HEX);
  Serial.println("Waiting for Modbus requests...");
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  receiveBytes();
  checkFrameComplete();

  // Periodic heartbeat. If this stops printing, the slave has hung.
  static uint32_t lastLog = 0;
  if (millis() - lastLog > 5000) {
    if (!halted) {
      Serial.print("Heartbeat OK. Reg[0]=0x");
      Serial.print(holdingRegisters[0], HEX);
      Serial.print("  Canary=0x");
      Serial.println(canary, HEX);
    }
    lastLog = millis();
  }
}
