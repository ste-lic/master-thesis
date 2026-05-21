#include <ModbusRTUSlave.h>
#include <HardwareSerial.h>

HardwareSerial ModbusSerial(1);  // UART1
ModbusRTUSlave modbus(ModbusSerial);

uint16_t holdingRegisters[10];
bool coils[8];

void setup() {
  Serial.begin(115200);           // UART0 for debug (USB-CDC)
  ModbusSerial.begin(9600, SERIAL_8N1, 20, 21);  // UART1 for Modbus
  
  for (int i = 0; i < 10; i++) {
    holdingRegisters[i] = 0x1000 + i;
  }
  
  modbus.configureHoldingRegisters(holdingRegisters, 10);
  modbus.configureCoils(coils, 8);
  modbus.begin(1, 9600);  // Slave ID = 1
  
  Serial.println("Modbus slave ready. Slave ID = 1, baud = 9600");
}

void loop() {
  modbus.poll();
  
  static unsigned long lastLog = 0;
  if (millis() - lastLog > 5000) {
    Serial.print("Heartbeat. Reg[0] = 0x");
    Serial.println(holdingRegisters[0], HEX);
    lastLog = millis();
  }
}
