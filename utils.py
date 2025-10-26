import serial
import struct

RESET_DTR = False  # Reset can be set to DTR, or RTS pin
DEFAULT_TIMEOUT = 0.4
DEFAULT_BAUDRATE = 9600

class comport:
    m_sent = 0

    def __init__(self, port, debug=0, initbaud=DEFAULT_BAUDRATE, halfduplex=False):
        self.halfduplex = halfduplex
        self.debug = debug
        self.ser = serial.Serial(
            port,
            baudrate=initbaud,
            dsrdtr=False,
            timeout=DEFAULT_TIMEOUT,
        )

    def read(self, len, breset=True):
        b = b""
        try:
            # Note, for some USB serial adapters, this may only flush the buffer of the OS and not all the data that may be present in the USB part.
            if breset:
                self.ser.reset_input_buffer()
            b = self.ser.read(self.m_sent + len)
            # because we run 1-wire communications
            # we have here bytes we sent
            # and bytes we have for reply
            # we have to remove written to serial bytes
            # emulating half-duplex communication
            if self.debug > 2:
                print("all>> ", b.hex())
            b = b[self.m_sent :]
            # reset
            self.m_sent = 0
            if self.debug > 1:
                print(">>", b.hex())
        except serial.serialutil.SerialException as e:
            print(f"exception {e}")
        return b

    def write(self, b):
        if self.halfduplex:
            self.ser.flush()
        self.ser.write(b)
        if self.halfduplex:
            self.m_sent = len(b)
        # wait sending bytes
        if self.debug > 1:
            print("<<", b.hex())

    def close(self):
        self.ser.close()

    def setdtr(self, val):
        self.ser.dtr = val

    def setrts(self, val):
        self.ser.rts = val

    def resetCPU(self, On=True):
        if (RESET_DTR):
            self.setdtr(On)
        else:
            self.setrts(On)

    def setBaudrate(self, baudrate=DEFAULT_BAUDRATE):
        self.ser.baudrate = baudrate

    def setTimeout(self, timeout=DEFAULT_TIMEOUT):
        self.ser.timeout = timeout
        self.ser.write_timeout = timeout

    def reset_input_buffer(self):
        self.ser.flush()
