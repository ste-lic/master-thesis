/*
 * custom_modbus_slave_bugs123.ino
 *
 * Modbus RTU Slave — All three bugs planted (evaluation version).
 *
 * BUGS PRESENT:
 *   Bug 1: CWE-120 (Buffer Copy without Checking Size of Input)
 *          FC=0x10 handler, byteCount field trusted directly in memcpy.
 *          Trigger: FC=0x10, quantity=1, byteCount=100, 100 bytes payload.
 *
 *   Bug 2: CWE-190 (Integer Overflow or Wraparound)
 *          FC=0x03 handler, startAddr + quantity computed in uint16_t without overflow check.
 *          Trigger: FC=0x03, startAddr=0xFFFE, quantity=3 (sum wraps to 0x0001, bypasses check).
 *
 *   Bug 3: CWE-193 (Off-by-one Error)
 *          FC=0x06 handler, address validation uses > instead of >=.
 *          Trigger: FC=0x06, address=0x000A (10), any value.
 *
 * All three bugs are live simultaneously. The oracle will detect whichever is triggered first.
 * Expected detections:
 *   - Bug 1: Crash (MCAUSE=0x5), canary corruption, timeout on liveness check.
 *   - Bug 2: Out-of-bounds read, likely crash (invalid address), or garbage response data.
 *   - Bug 3: Direct canary corruption, detected by checkCanary() on the write.
 */

// ─── Configuration ────────────────────────────────────────────────────────────
#define SLAVE_ID        1
#define BAUD_RATE       9600
#define RX_PIN          20      // ESP32-C3 GPIO20 = UART1 RX -  Same as datasheet
#define TX_PIN          21      // ESP32-C3 GPIO21 = UART1 TX -  Same as datasheet
#define NUM_REGISTERS   10      // number of holding registers
#define MAX_FRAME_SIZE  256     // receive buffer size - Max by def of MODBUS ADU
#define FRAME_TIMEOUT_MS 10     // inter-frame gap in ms (≈3.5 char times at 9600 baud)

/* 
 * ####################################################################################################
 * Canary
 * ----------------------------------------------------------------------------------------------------
 * Placed immediately after holdingRegisters[] in declaration order so that a
 * buffer overflow past the end of the array corrupts it first.
 * Value chosen to be recognisable and unlikely to appear as valid register data.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

#define CANARY_VALUE    0xDEADBEEF

/* 
 * ####################################################################################################
 * Data storage
 * ----------------------------------------------------------------------------------------------------
 * IMPORTANT: do NOT insert any variable between holdingRegisters and canary: the overflow must reach 
 * canary before corrupting anything else.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

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
// *** BUG 2 IS HERE ***
//
// Integer overflow vulnerability in the response buffer index calculation.
// The response buffer pdu is sized as uint8_t pdu[3 + 250] (253 bytes total).
// The response builder writes register data using index: pdu[3 + i*2]
//
// The quantity validation checks if quantity > 250 (instead of > 125).
// This allows quantity values up to 250 to pass. If quantity=250 and startAddr=0,
// the loop writes to indices 3+i*2 where i goes from 0 to 249.
// Maximum index: 3 + 249*2 = 3 + 498 = 501.
//
// This is far past the 253-byte buffer end. The write corrupts the stack,
// overflowing into the canary and adjacent memory.
//
// BUG TYPE: CWE-190 (Integer Overflow) leading to CWE-120 (Buffer Overflow).
// TRIGGER: Send FC=0x03 with startAddr=0x0000, quantity=0x00FA (250).
//          The handler accepts quantity=250 (passes check 250 > 250? No).
//          Response loop writes to pdu[3 + 0..498], overflowing the 253-byte buffer.
void handleReadHoldingRegisters(uint8_t *frame, uint16_t len) {
  if (len < 6) { sendException(0x03, 0x03); return; }

  uint16_t startAddr = ((uint16_t)frame[2] << 8) | frame[3];
  uint16_t quantity  = ((uint16_t)frame[4] << 8) | frame[5];

  if (quantity == 0 || quantity > 250) { sendException(0x03, 0x03); return; }
  // *** VULNERABLE: bounds check removed to allow buffer overflow in response builder ***
  // Original code had: if (startAddr + quantity > NUM_REGISTERS) check here.
  // Without it, quantity=250 reaches the response buffer overflow below.

  uint8_t byteCount = (uint8_t)(quantity * 2);
  uint8_t pdu[3 + 250]; // max 125 registers * 2 bytes + header — BUT validator allows 250!
  pdu[0] = SLAVE_ID;
  pdu[1] = 0x03;
  pdu[2] = byteCount;
  for (uint16_t i = 0; i < quantity; i++) {
    // *** INDEX OVERFLOW ***
    // If quantity > 125, index 3 + i*2 exceeds buffer size 253.
    pdu[3 + i*2]     = (uint8_t)(holdingRegisters[startAddr + i] >> 8);
    pdu[3 + i*2 + 1] = (uint8_t)(holdingRegisters[startAddr + i] & 0xFF);
  }
  sendResponse(pdu, 3 + byteCount);
}

// ─── FC=0x06: Write Single Register ──────────────────────────────────────────
// *** BUG 3 IS HERE ***
//
// Off-by-one error in address range validation. The correct check is addr >= NUM_REGISTERS
// (reject addresses 10 and above). This handler uses addr > NUM_REGISTERS (reject only > 10),
// allowing addr=NUM_REGISTERS=10 to pass.
//
// With 10 registers at indices 0-9, address 10 is out of bounds. Writing to holdingRegisters[10]
// corrupts whatever sits at that memory location — in this firmware, the canary.
//
// BUG TYPE: CWE-193 (Off-by-one Error).
// TRIGGER: Send FC=0x06 with address=0x000A (10), any value.
//          The check 10 > 10 fails, so it proceeds to holdingRegisters[10] = value.
//          This corrupts canary immediately, which checkCanary() detects.
void handleWriteSingleRegister(uint8_t *frame, uint16_t len) {
  if (len < 6) { sendException(0x06, 0x03); return; }

  uint16_t addr  = ((uint16_t)frame[2] << 8) | frame[3];
  uint16_t value = ((uint16_t)frame[4] << 8) | frame[5];

  // *** VULNERABLE LINE ***
  // Should be: if (addr >= NUM_REGISTERS)
  // But uses: if (addr > NUM_REGISTERS), allowing addr=10 to pass.
  if (addr > NUM_REGISTERS) { sendException(0x06, 0x02); return; }

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

  Serial.println("=== Modbus RTU Slave — Three Bugs Planted (Evaluation Version) ===");
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
