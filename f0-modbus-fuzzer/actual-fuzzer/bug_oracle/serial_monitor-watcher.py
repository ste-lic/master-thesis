####################################################################################################
# Source: https://forum.arduino.cc/t/using-python-to-read-and-process-serial-data-from-arduino/1059079
####################################################################################################

import serial
import time

def readserial(comport, baudrate):

    ser = serial.Serial(comport, baudrate, timeout=0.1)         # 1/timeout is the frequency at which the port is read

    read_lines = 0
    lines_to_read = 50
    lines : list[str] = []
    is_error = False
    while True:

        data = ser.readline().decode().strip()
        
        if error_lookout(data) == True:
            is_error = True
        else: 
            print(data)

        if is_error:
            if read_lines < lines_to_read:
                lines.append(data)
                read_lines += 1
            else:                
                with open('myLog.txt', 'w') as f:
                    for line in lines:
                        f.write(f'{line}\n')
                break

def error_lookout(data : str):
    return "error" in data.lower()
      
if __name__ == '__main__':
    readserial('/dev/ttyACM0', 115200)                          # COM port, Baudrate
