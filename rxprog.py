import sys
import struct
import time
import argparse
import utils
import tqdm
import os
import glob
import re
from enum import IntEnum
from intelhex import IntelHex


RESET_PAUSE = 0.7
INITIAL_RESP_TIMEOUT = 0.1
RESPONSE_TIMEOUT = 0.09

'''

(FREQ*SYS_RATIO/PERI_RATIO)/K = baudrate
(FREQ*SYS_RATIO)<max_freq

'''
SECOND_PHASE_BPS = 500000 # смотри также SYS_RATIO, PERI_RATIO
SYS_RATIO = 8 # default, can be changed later
PERI_RATIO = 4 # default, can be changed later

# Определения команд
class BootCommand(IntEnum):
    INITIAL_TRANSMIT = 0x00
    SUPPORTED_DEVICE_INQUIRY = 0x20
    DEVICE_SELECTION = 0x10
    CLOCK_MODE_INQUIRY = 0x21
    CLOCK_MODE_SELECTION = 0x11
    MULTIPLICATION_RATIO_INQUIRY = 0x22
    OPERATING_FREQUENCY_INQUIRY = 0x23
    NEW_BIT_RATE_SELECTION = 0x3F
    NEW_BIT_RATE_CONFIRMATION = 0x06
    ERASURE_BLOCK_INFORMATION_INQ = 0x26
    PROGRAMMING_SIZE_INQ = 0x27
    PROGRAMMING_ERASURE_STATE_TRANSITION = 0x40
    USER_BOOT_AREA_PROGRAMMING_SELECTION = 0x42
    USER_DATA_AREA_PROGRAMMING_SELECTION = 0x43
    ERASE = 0x48
    BLOCK_ERASE = 0x58
    EMBEDDED_PR_STATUS = 0x4F
    BYTE_256_PROGRAMMING = 0x50
    READ_CMD = 0x52
    USERBOOT_AREA_INQUIRY = 0x24
    CODE_AREA_INQUIRY = 0x25
    BLOCK_INQUIRY = 0x26
    PROG_SIZE_INQUIRY = 0x27
    DATA_AREA_INQUIRY = 0x2A
    DATA_AREA_INF_INQUIRY = 0x2B
    BIT_RATE_INIT = 0x55
    DEBUG_PROGRAM = 0x28  # unconfirmed
    ID_CODE_ENTER = 0x60
    USER_BOOT_AREA_CHECKSUM = 0x4A
    USER_DATA_AREA_CHECKSUM = 0x4B
    USER_BOOT_AREA_BLANKCHECK = 0x4C
    USER_DATA_AREA_BLANKCHECK = 0x4D
    READ_LOCKBIT_STATUS = 0x71
    LOCKBIT_PROGRAM = 0x77
    LOCKBIT_ENABLE = 0x7A
    LOCKBIT_DISABLE = 0x75


# Определения ответов
class BootResponse(IntEnum):
    INITIAL_TRANSMIT_OK = 0x00
    CHECKSUM_ERROR = 0x11
    DEVICE_CODE_ERR = 0x21
    CLOCK_MODE_ERR = 0x22
    BITRATE_SEL_ERR = 0x24
    MULTIPLICATION_RATIO_ERR = 0x26
    FREQ_ERR = 0x27
    BLOCK_NUMBER_ERR = 0x29
    ADDR_ERR = 0x2A
    DATASIZE_ERR = 0x2B
    ERASURE_ERR = 0x51
    INC_ERASURE_ERR = 0x52
    PROGRAMMING_ERR = 0x53
    SELECT_ERR = 0x54
    GENERIC_OK = 0x06
    BITRATE_ADJ_ERR = 0xFF
    SUPPORTED_DEVICE_INQUIRY_OK = 0x30
    CLOCK_MODE_INQUIRY_OK = 0x31
    MULTIPLICATION_RATIO_INQUIRY_OK = 0x32
    OPERATING_FREQUENCY_INQUIRY_OK = 0x33
    ERASURE_BLOCK_INFORMATION_INQ_OK = 0x36
    BIT_RATE_INIT_OK = 0xE6
    BIT_RATE_INIT_ERROR = 0xFF
    ID_CODE_PROTECTION_DISABLED = 0x26
    ID_CODE_PROTECTION_ENABLED = 0x16
    BLOCK_INQUIRY = 0x36
    CODE_AREA_INQUIRY = 0x35
    USERBOOT_AREA_INQUIRY = 0x34
    DATA_AREA_INQUIRY = 0x3A
    DATA_AREA_INF_INQUIRY = 0x3B
    ID_CODE_ACK = 0x26
    ID_CODE_ERROR = 0xE0
    COMMAND_ERROR = 0x80
    ERASEBLK_ERR = 0xD8
    PROGRAM_ERR = 0xD0 
    # 11h: Checksum error
    # 53h: Programming cannot be done due to a programming error
    # 2Ah: Address error (the specified address is not in the target area)
    


class RX63NProgrammer:
    BLOCK_SIZE = 0x100
    MAX_PACKAGE = 1000
    erasure_blocks = []

    def __init__(self, port, debug=False,baud=9600):
        self.ser = utils.comport(port=port, debug=debug, initbaud=baud, halfduplex=False)

        # Состояние программы
        self.device_list = []
        self.clock_modes = []
        self.clock_types = []

        # Параметры устройства
        self.flash_size = 0
        self.block_size = 0

    def write_data(self, data, timeout=RESPONSE_TIMEOUT):
        """Отправка данных через последовательный порт"""
        self.ser.setTimeout(timeout)
        self.ser.reset_input_buffer()
        return self.ser.write(data)

    def read_data(self, size, timeout=RESPONSE_TIMEOUT):
        """Чтение данных из последовательного порта с таймаутом"""
        self.ser.setTimeout(timeout)
        return self.ser.read(size)

    def compute_checksum(self, data):
        """Вычисление контрольной суммы"""
        checksum = 0
        for byte in data:
            checksum = (checksum + byte) & 0xFF
        return (~checksum + 1) & 0xFF

    # если expected_response не установлен, то запрос производит вызывающий код
    # ecли payload_size не установлен, то возвращается bool
    # size_of_size - размер size, обычно 1 байт, но бывает и два
    def execute_command(
        self, command, payload=b"", expected_response=None, payload_size=0, size_of_size = 1, resp_timeout = RESPONSE_TIMEOUT
    ):
        """Выполнение команды с обработкой ответа"""
        # Формирование пакета команды
        packet = bytes([command]) + payload

        #was_checksum = False
        if len(packet) > 1:
            if command != BootCommand.BIT_RATE_INIT:
                packet += bytes([self.compute_checksum(packet)])
                #was_checksum = True

        # Отправка команды
        self.write_data(packet)

        # Обработка ответа
        if expected_response is None:
            return True

        # Чтение основного ответа
        response = self.read_data(self.MAX_PACKAGE, timeout=resp_timeout)
        if not response:
            return False

        # Обработка ответов без полезной нагрузки
        if response[0] == expected_response and payload_size == 0:
            return True

        # Обработка ответов с полезной нагрузкой
        if response[0] == expected_response and payload_size > 0:
            if len(response) < 3:
                return False

            # data size of response
            if (1==size_of_size):
                data_size = response[1]
                i_next = 2
            elif (2==size_of_size):
                data_size = struct.unpack(">H",response[1:3])[0]
                i_next = 3
            #
            # print("datasize = %x" % (data_size))
            # check if data size is enough
            if (len(response) - 3) < data_size:
                return False
            # get payload
            payload_data = response[i_next : data_size + i_next+1]
            #if was_checksum:
            if True:
                checksum = self.compute_checksum(response[0:i_next] + payload_data[:-1])                
                # Проверка контрольной суммы
                if checksum != payload_data[-1]:
                    print("chsum wrong = 0x%x" % checksum)
                    return False

            return payload_data[:-1]

        # Обработка ошибок
        if response[0] == BootResponse.BIT_RATE_INIT_ERROR:
            error_data = self.read_data(1)
            return False

        print("Got response: [%s]"%response.hex())

        return False

    def match_bit_rates(self):
        """Согласование скорости соединения"""
        self.ser.resetCPU(True)
        time.sleep(RESET_PAUSE)
        self.ser.resetCPU(False)  # Release reset line
        time.sleep(0.7)  # little pause for some CPUs        

        # Команда INITIAL_TRANSMIT
        for _ in range(30):  # 30 попыток
            if self.execute_command(
                BootCommand.INITIAL_TRANSMIT,
                expected_response=BootResponse.INITIAL_TRANSMIT_OK,
                resp_timeout=INITIAL_RESP_TIMEOUT
            ):
                break
            time.sleep(0.1)
        else:
            return False

        # Команда BIT_RATE_INIT
        return self.execute_command(
            BootCommand.BIT_RATE_INIT, expected_response=BootResponse.BIT_RATE_INIT_OK
        )

    def get_erase_block_info(self):    
        response = self.execute_command(
            BootCommand.ERASURE_BLOCK_INFORMATION_INQ,
            expected_response=BootResponse.ERASURE_BLOCK_INFORMATION_INQ_OK,
            payload_size=1,size_of_size=2
        )
        if not response:
            return False        
        self.erasure_block_count = response[0]
        print("Block info: %d blocks"%self.erasure_block_count)
        for i in range(self.erasure_block_count):
            start_addr,end_addr = struct.unpack(">II", response[1+i*8:1+i*8+8])
            self.erasure_blocks.append([start_addr,end_addr]) 
            # print("%02d) 0x%08X-0x%08X"%(i,start_addr,end_addr))    

    def get_supported_devices(self):
        """Получение списка поддерживаемых устройств"""
        response = self.execute_command(
            BootCommand.SUPPORTED_DEVICE_INQUIRY,
            expected_response=BootResponse.SUPPORTED_DEVICE_INQUIRY_OK,
            payload_size=1,
            resp_timeout=INITIAL_RESP_TIMEOUT
        )
        if not response:
            return False

        device_count = response[0]
        pos = 1
        self.device_list = []

        for _ in range(device_count):
            name_len = response[pos]
            code = response[pos + 1 : pos + 5]
            name = response[pos + 5 : pos + 5 + (name_len - 4)].decode("ascii")

            self.device_list.append({"code": code, "name": name})

            pos += name_len + 1

        return True

    def set_device(self, device_index):
        """Выбор устройства для работы"""
        if device_index >= len(self.device_list):
            return False

        payload = bytes([4]) + self.device_list[device_index]["code"]
        return self.execute_command(
            BootCommand.DEVICE_SELECTION,
            payload=payload,
            expected_response=BootResponse.GENERIC_OK,
            resp_timeout=INITIAL_RESP_TIMEOUT
        )

    def get_clock_modes(self):
        """Получение списка режимов тактирования"""
        response = self.execute_command(
            BootCommand.CLOCK_MODE_INQUIRY,
            expected_response=BootResponse.CLOCK_MODE_INQUIRY_OK,
            payload_size=1,
            resp_timeout=INITIAL_RESP_TIMEOUT
        )
        if not response:
            return False

        self.clock_modes = list(response)
        return True

    def set_clock_mode(self, clock_mode_index):
        """Установка режима тактирования"""
        if clock_mode_index >= len(self.clock_modes):
            return False

        payload = bytes([1, self.clock_modes[clock_mode_index]])
        return self.execute_command(
            BootCommand.CLOCK_MODE_SELECTION,
            payload=payload,
            resp_timeout=INITIAL_RESP_TIMEOUT,
            expected_response=BootResponse.GENERIC_OK,
        )

    def get_multiplication_ratios(self):
        """Получение коэффициентов умножения частоты"""
        response = self.execute_command(
            BootCommand.MULTIPLICATION_RATIO_INQUIRY,
            expected_response=BootResponse.MULTIPLICATION_RATIO_INQUIRY_OK,
            payload_size=1,
            resp_timeout=INITIAL_RESP_TIMEOUT
        )
        if not response:
            return False

        # Парсинг ответа
        clock_type_count = response[0]
        pos = 1
        self.clock_types = []

        for _ in range(clock_type_count):
            ratio_count = response[pos]
            ratios = response[pos + 1 : pos + 1 + ratio_count]
            self.clock_types.append({"ratio_count": ratio_count, "ratios": ratios})
            print(ratios) #todo : make var to move to get_baud
            pos += ratio_count + 1

        return True

    def get_operating_frequencies(self):
        """Получение рабочих частот"""
        response = self.execute_command(
            BootCommand.OPERATING_FREQUENCY_INQUIRY,
            expected_response=BootResponse.OPERATING_FREQUENCY_INQUIRY_OK,
            payload_size=1,
            resp_timeout=INITIAL_RESP_TIMEOUT
        )
        if not response:
            return False

        # Обновление информации о clock_types
        clock_type_count = response[0]
        pos = 1

        for i in range(clock_type_count):
            min_freq = (response[pos] << 8 | response[pos + 1]) * 10000
            max_freq = (response[pos + 2] << 8 | response[pos + 3]) * 10000
            print("%d,%d"%(min_freq,max_freq))

            if i < len(self.clock_types):
                self.clock_types[i]["min_freq"] = min_freq
                self.clock_types[i]["max_freq"] = max_freq

            pos += 4

        return True

    def set_bit_rate(self, bit_rate, frequency, sys_ratio, peri_ratio):
        """Установка скорости обмена и параметров тактирования"""
        # Преобразование параметров
        bit_rate_val = bit_rate // 100
        freq_val = frequency // 10000
        # 3f 07 00 60 06 40 02 04 02 0c // 16Mhz
        # 3f 07 02 40 06 40 02 04 // 57600        
        # 0x3F 0x07 0x04 0x80 0x06 0x40 0x02 0x04 0x02 0xE8
        # 0x3F 0x07 0x1D 0x4C 0x04 0xB0 0x02 0x08 0x04 0x8F // 7500, 12MHZ

        payload = struct.pack(
            ">BHHBBB",
            7,  # 2-bytes inputBitRate, 2-bytes input frequency, 1-byte clocktype count, 2-bytes for the multiplication ratios
            bit_rate_val,
            freq_val,
            2,  # this is always fixed at 2: one for the system clock, and another for the peripheral clock.
            sys_ratio,
            peri_ratio,
        )

        # Отправка команды
        self.execute_command(BootCommand.NEW_BIT_RATE_SELECTION, payload=payload, resp_timeout=INITIAL_RESP_TIMEOUT)

        # Чтение ответа об ошибке (если есть)
        response = self.read_data(2)
        if response and response[0] != BootResponse.GENERIC_OK:
            error_codes = {
                0x11: "Checksum Error",
                0x24: "Bit rate selection Error",
                0x25: "Input frequency Error",
                0x26: "Multiplication ratio Error",
                0x27: "Operating Frequency Error",
            }
            error_msg = error_codes.get(response[1], "Unknown Error")
            print(f"Error: {error_msg}")
            return False

        # Обновление скорости порта
        self.ser.setBaudrate(bit_rate)           

        return True

    def confirm_bit_rate(self):
        """Подтверждение новой скорости обмена"""
        return self.execute_command(
            BootCommand.NEW_BIT_RATE_CONFIRMATION,
            expected_response=BootResponse.GENERIC_OK,
        )

    def activate_flash_programming(self):
        """Активация режима программирования Flash"""
        response = self.execute_command(
            BootCommand.PROGRAMMING_ERASURE_STATE_TRANSITION
        )
        if not response:
            return 0

        # Проверка ответа
        resp = self.read_data(self.MAX_PACKAGE, timeout=0.4)
        while len(resp) < 1:
            resp += self.read_data(self.MAX_PACKAGE)
        if resp:
            if resp[0] == BootResponse.ID_CODE_PROTECTION_DISABLED:
                print("ID Code Disabled. Flash erased.")
                return 1
            elif resp[0] == BootResponse.ID_CODE_PROTECTION_ENABLED:
                print("ID Code Enabled")
                return 2
            else:
                print("Unknown responce 0x%x" % resp[0])            

        return 0

# ACK code
# 26h: Returns the response for a programming/erasure state transition command
# Error (1 byte):Error code
# 11h: Checksum error
# 61h: ID code mismatch
# 63h: ID code mismatch (erasure error)
    def enterIdCode(self, idcode_payload):
        response = self.execute_command(
            BootCommand.ID_CODE_ENTER,
            payload=struct.pack(">B", len(idcode_payload)) + idcode_payload,
            expected_response=BootResponse.ID_CODE_ACK,
        )
        # bigger size needs more timeout
        
        if not response:
            print("Id Code Failed")
            return False
        
        print("ID Code Accepted")
        return True

    def read_area(self, start_addr, size, user):
        payload = struct.pack(">BBIHH", 9, not user, start_addr, 0, size)
        if not self.execute_command(BootCommand.READ_CMD, payload):
            print("Error: Failed to read user data area")
            return None
        # bigger size needs more timeout
        response = self.read_data(size + 6, timeout=0.4)
        if len(response) < 6:
            return None
        (cmd, zero, size_ret) = struct.unpack(">BHH", response[0:5])
        if (cmd != BootCommand.READ_CMD) or (zero != 0) or (size_ret == 0):
            return None

        return response[5:-1]

    def read(self, file_format="hex", idcode=None):
        flashes = [[self.userboot_flash, 1], [self.data_flash, 0], [self.code_flash, 0]]
        
        # Активация программирования Flash для чтения
        print("Activating flash programming mode for reading...")
        activation_result = self.activate_flash_programming()
        if activation_result == 0:
            print("Error: Flash programming activation failed")
            return False
        
        # Ввод ID кода если нужно
        if activation_result == 2:
            if idcode is None:
                print("Error: ID Code required but not provided")
                return False
            if not self.enterIdCode(bytearray.fromhex(idcode)):
                print("Error: ID Code entry failed")
                return False
        
        for flash_ in flashes:
            b = b""
            flash_addr = flash_[0]
            user = flash_[1]
            filename_unique = "RX630_%04X-%04X_%s.%s" % (
                flash_addr[0],
                flash_addr[1],
                time.strftime("%Y%m%d-%H%M%S"),
                file_format,
            )
            print(" Writing file %s..." % filename_unique)
            for addr in tqdm.tqdm(range(flash_addr[0], flash_addr[1] + 1, 0x400)):
                b1 = self.read_area(addr, 0x400, user)
                if b1 is None:
                    return False
                b += b1
            if file_format == "hex":
                ihex = IntelHex()
                ihex[flash_addr[0] : flash_addr[0] + len(b)] = list(b)
                ihex.tofile(filename_unique, format="hex")
            else:  # bin
                with open(filename_unique, "wb") as f:
                    f.write(b)
        return True
    
    def program_user_area(self, file_path, file_format="hex", start_addr=None, skip_erase=False):
        # process file format
        if file_format == "hex":
            ih = IntelHex()
            ih.loadhex(file_path)
            bin_data = ih.tobinarray()
            start_addr = ih.minaddr()
            end_addr = ih.maxaddr()            
        elif file_format == "bin":
            if start_addr is None:
                print("Error: start_addr must be specified for BIN file")
                return False
            with open(file_path, "rb") as f:
                bin_data = f.read()
            end_addr = start_addr + len(bin_data) - 1
            print(f"Programming BIN from 0x{start_addr:08X} to 0x{end_addr:08X}")
        else:
            print("Error: Unknown file format")
            return False
        
        # Стирание только если не пропущено
        if not skip_erase:
            if not self.erase(start_addr, end_addr):
                return False

        """Программирование пользовательской области памяти из HEX или BIN файла"""
        print(f"Programming {file_format.upper()} from 0x{start_addr:08X} to 0x{end_addr:08X}")
        if start_addr == self.userboot_flash[0]:
            cmd = BootCommand.USER_BOOT_AREA_PROGRAMMING_SELECTION
        else:
            cmd = BootCommand.USER_DATA_AREA_PROGRAMMING_SELECTION
        
        # Выбор области программирования
        if not self.execute_command(
            cmd,
            expected_response=BootResponse.GENERIC_OK,
        ):
            print("Error: Failed to select user data area")
            return False

        for addr in tqdm.tqdm(range(start_addr, end_addr + 1, self.BLOCK_SIZE)):
            block_start = addr
            block_end = min(addr + self.BLOCK_SIZE, end_addr + 1)
            block_size = block_end - block_start
            block = bytearray([0xFF] * self.BLOCK_SIZE)
            for i in range(block_size):
                file_offset = block_start - start_addr + i
                if 0 <= file_offset < len(bin_data):
                    block[i] = bin_data[file_offset]
            payload = bytes([BootCommand.BYTE_256_PROGRAMMING])
            payload += struct.pack(">I", block_start) + block
            payload += bytes([self.compute_checksum(payload)])
            self.write_data(payload)
            response = self.read_data(self.MAX_PACKAGE)
            if not response or response[0] != BootResponse.GENERIC_OK:
                error_codes = {
                    0x11: "Checksum error",
                    0x2A: "Address error",
                    0x53: "Programming error",
                }
                error_msg = error_codes.get(
                    response[1] if response else 0, "Unknown error"
                )
                print(f"Error at 0x{block_start:08X}: {error_msg}")
                return False
        
        # Завершение программирования
        term_payload = struct.pack(">I", 0xFFFFFFFF) + bytes(
            [self.compute_checksum(struct.pack(">I", 0xFFFFFFFF))]
        )
        self.write_data(bytes([BootCommand.BYTE_256_PROGRAMMING]) + term_payload)
        
        return True
    
    def close(self):
        """Закрытие соединения с устройством"""
        self.ser.close()

    def flash_inquiry(self):
        r = self.execute_command(
            BootCommand.USERBOOT_AREA_INQUIRY,
            expected_response=BootResponse.USERBOOT_AREA_INQUIRY,
            payload_size=9,
        )
        if not r:
            print("Error: Failed to select user data area")
            return False
        self.userboot_flash = struct.unpack(">II", r[1:])
        r = self.execute_command(
            BootCommand.CODE_AREA_INQUIRY,
            expected_response=BootResponse.CODE_AREA_INQUIRY,
            payload_size=9,
        )
        # add specific USERBOOT erasure block:

        if not r:
            print("Error: Failed to select user data area")
            return False
        self.code_flash = struct.unpack(">II", r[1:])
        r = self.execute_command(
            BootCommand.DATA_AREA_INF_INQUIRY,
            expected_response=BootResponse.DATA_AREA_INF_INQUIRY,
            payload_size=9,
        )
        if not r:
            print("Error: Failed to select user data area")
            return False
        self.data_flash = struct.unpack(">II", r[1:])
        print(
            "\nFlash areas:\n\tUserBoot 0x%0x-0x%0x\n\tCodeFlash 0x%0x-0x%0x\n\tDataFlash 0x%0x-0x%0x"
            % (
                self.userboot_flash[0],
                self.userboot_flash[1],
                self.code_flash[0],
                self.code_flash[1],
                self.data_flash[0],
                self.data_flash[1],
            )
        )
        return True
    
    def erase(self, start, finish):
        if (not self.execute_command(BootCommand.ERASE, expected_response=BootResponse.GENERIC_OK)):
            return False        
        print("Erasing... 0x%04X-0x%04X"%(start,finish))
        for i in tqdm.tqdm(range(len(self.erasure_blocks))):            
            # check if the specified range within the block
            if (start<=self.erasure_blocks[i][0]) and (finish>=self.erasure_blocks[i][1]):                
                block_info = struct.pack(">BB",1,i)
                if (not self.execute_command(BootCommand.BLOCK_ERASE,payload=block_info,expected_response=BootResponse.GENERIC_OK)):
                    return False
        # USER BOOT ERASE:
        #  [0x58 0x01 0x80 0x27] 
        if (start<=self.userboot_flash[0]) and (finish>=self.userboot_flash[1]):
            block_info = struct.pack(">BB",1,0x80)
            if (not self.execute_command(BootCommand.BLOCK_ERASE,payload=block_info,expected_response=BootResponse.GENERIC_OK)):
                return False
        # finish sendin FF
        block_info = struct.pack(">BB",1,0xFF)
        if (not self.execute_command(BootCommand.BLOCK_ERASE,payload=block_info,expected_response=BootResponse.GENERIC_OK)):
            return False
        return True

    def command28(self, arg):
        r = self.execute_command(BootCommand.DEBUG_PROGRAM, payload=arg)
        response = self.read_data(self.MAX_PACKAGE)
        if not response:
            return False
        
    def _finalize_programming(self):
        """Завершение текущего сеанса программирования"""
        print("Finalizing programming...")
        term_payload = struct.pack(">I", 0xFFFFFFFF)
        #self.write_data(bytes([BootCommand.BYTE_256_PROGRAMMING]) + term_payload)
        if not self.execute_command(BootCommand.BYTE_256_PROGRAMMING, payload=term_payload, expected_response=BootResponse.GENERIC_OK):
            return False
        return True

    def _program_single_file(self, file_data, area_cmd, area_name):
        """Программирование одного файла в указанной области"""
        filename = os.path.basename(file_data['path'])
        start_addr = file_data['start_addr']
        end_addr = file_data['end_addr']
        bin_data = file_data['bin_data']
        
        print(f"Programming {filename} from 0x{start_addr:08X} to 0x{end_addr:08X}")
        
        # Программирование блоками
        for addr in tqdm.tqdm(range(start_addr, end_addr + 1, self.BLOCK_SIZE)):
            block_start = addr
            block_end = min(addr + self.BLOCK_SIZE, end_addr + 1)
            block_size = block_end - block_start
            block = bytearray([0xFF] * self.BLOCK_SIZE)
            
            for i in range(block_size):
                file_offset = block_start - start_addr + i
                if 0 <= file_offset < len(bin_data):
                    block[i] = bin_data[file_offset]
            
            payload = bytes([BootCommand.BYTE_256_PROGRAMMING])
            payload += struct.pack(">I", block_start) + block
            payload += bytes([self.compute_checksum(payload)])
            
            self.write_data(payload)
            response = self.read_data(self.MAX_PACKAGE)
            
            if not response or response[0] != BootResponse.GENERIC_OK:
                error_codes = {
                    0x11: "Checksum error",
                    0x2A: "Address error",
                    0x53: "Programming error",
                }
                error_msg = error_codes.get(
                    response[1] if response else 0, "Unknown error"
                )
                print(f"Error at 0x{block_start:08X}: {error_msg}")
                return False
        
        return True

    def _select_programming_area(self, area_cmd, area_name, current_area):
        """Выбор области программирования с завершением предыдущего сеанса только при необходимости"""
        # Завершаем предыдущий сеанс программирования только при переходе к User Boot Area
        if current_area is not None and area_cmd == BootCommand.USER_BOOT_AREA_PROGRAMMING_SELECTION:
            if not self._finalize_programming():
                return False
            print(f"Finalized previous programming session before switching to {area_name} area")
        
        # Выбираем новую область
        print(f"Selecting {area_name} area...")
        if not self.execute_command(area_cmd, expected_response=BootResponse.GENERIC_OK):
            print(f"Error: Failed to select {area_name} area")
            return False
        return True

    def _analyze_files(self, folder_path):
        """Анализ файлов в папке и определение их принадлежности к областям"""
        hex_files = glob.glob(os.path.join(folder_path, "*.hex"))
        bin_files = glob.glob(os.path.join(folder_path, "*.bin"))
        all_files = hex_files + bin_files
        
        if not all_files:
            print(f"Error: No HEX or BIN files found in {folder_path}")
            return None
        
        print(f"Found {len(all_files)} files to program:")
        
        file_info = []
        min_addr = 0xFFFFFFFF
        max_addr = 0x00000000
        
        for file_path in all_files:
            filename = os.path.basename(file_path)
            file_ext = os.path.splitext(filename)[1].lower()
            
            if file_ext == '.hex':
                ih = IntelHex()
                try:
                    ih.loadhex(file_path)
                    start_addr = ih.minaddr()
                    end_addr = ih.maxaddr()
                    bin_data = ih.tobinarray()
                    
                    # Определяем область программирования
                    area_info = self._determine_area(start_addr, end_addr)
                    if not area_info:
                        print(f"Error: Cannot determine area for file {filename}")
                        return None
                    
                    file_info.append({
                        'path': file_path,
                        'type': 'hex',
                        'start_addr': start_addr,
                        'end_addr': end_addr,
                        'bin_data': bin_data,
                        **area_info
                    })
                    
                    min_addr = min(min_addr, start_addr)
                    max_addr = max(max_addr, end_addr)
                    print(f"  {filename}: 0x{start_addr:08X} - 0x{end_addr:08X} ({area_info['area_name']})")
                    
                except Exception as e:
                    print(f"  ✗ Error loading HEX file {filename}: {e}")
                    return None
                            
            elif file_ext == '.bin':
                base_name = os.path.splitext(filename)[0]
                start_addr, end_addr = self._parse_bin_filename(base_name, file_path)
                if start_addr is None:
                    return None
                
                with open(file_path, "rb") as f:
                    bin_data = f.read()
                
                # Определяем область программирования
                area_info = self._determine_area(start_addr, end_addr)
                if not area_info:
                    print(f"Error: Cannot determine area for file {filename}")
                    return None
                
                file_info.append({
                    'path': file_path,
                    'type': 'bin',
                    'start_addr': start_addr,
                    'end_addr': end_addr,
                    'bin_data': bin_data,
                    **area_info
                })
                
                min_addr = min(min_addr, start_addr)
                max_addr = max(max_addr, end_addr)
                print(f"  {filename}: 0x{start_addr:08X} - 0x{end_addr:08X} ({len(bin_data)} bytes, {area_info['area_name']})")
        
        return {
            'file_info': file_info,
            'min_addr': min_addr,
            'max_addr': max_addr
        }

    def _determine_area(self, start_addr, end_addr):
        """Определение области программирования по диапазону адресов"""
        if (start_addr >= self.userboot_flash[0] and end_addr <= self.userboot_flash[1]):
            return {
                'area_cmd': BootCommand.USER_BOOT_AREA_PROGRAMMING_SELECTION,
                'area_name': "user boot",
                'priority': 3
            }
        elif (start_addr >= self.code_flash[0] and end_addr <= self.code_flash[1]):
            return {
                'area_cmd': BootCommand.USER_DATA_AREA_PROGRAMMING_SELECTION,
                'area_name': "code flash", 
                'priority': 2
            }
        elif (start_addr >= self.data_flash[0] and end_addr <= self.data_flash[1]):
            return {
                'area_cmd': BootCommand.USER_DATA_AREA_PROGRAMMING_SELECTION,
                'area_name': "user data",
                'priority': 1
            }
        else:
            return {
                'area_cmd': BootCommand.USER_DATA_AREA_PROGRAMMING_SELECTION,
                'area_name': "unknown (using user data)",
                'priority': 1
            }

    def _parse_bin_filename(self, base_name, file_path):
        """Парсинг имени BIN файла для определения диапазона адресов"""
        addr_match = False
        start_addr = None
        
        # Пытаемся найти диапазон в имени файла
        hex_pattern = r'0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)'
        dec_pattern = r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+)'
        
        match = re.search(hex_pattern, base_name)
        if match:
            start_addr = int(match.group(1), 16)
            end_addr = int(match.group(2), 16)
            addr_match = True
        else:
            match = re.search(dec_pattern, base_name)
            if match:
                try:
                    start_addr = int(match.group(1), 16)
                    end_addr = int(match.group(2), 16)
                    addr_match = True
                except ValueError:
                    addr_match = False
        
        if not addr_match:
            print(f"Warning: Cannot determine address range from filename: {os.path.basename(file_path)}")
            print("  Using default user boot area")
            start_addr = self.userboot_flash[0] if hasattr(self, 'userboot_flash') else 0xFFF00000
        
        file_size = os.path.getsize(file_path)
        if addr_match:
            calculated_end = start_addr + file_size - 1
            if calculated_end > end_addr:
                print(f"  Warning: File size ({file_size} bytes) exceeds specified range")
            end_addr = min(end_addr, calculated_end)
        else:
            end_addr = start_addr + file_size - 1
        
        return start_addr, end_addr

    def get_baud(self,freq,at_least,sys,peri):
        if (freq*sys > self.clock_types[0]["max_freq"]):
                sys=sys//2
                peri=peri//2
        freq_cpu = freq * sys        
        k = freq_cpu//peri
        for i in range(4,12): # todo: get from ratios
            if 0==(k%(i*8)):
                br = k//(i*8)            
                if br >= at_least:
                    return (br,sys,peri)
        return None

    def program_all_areas(self, folder_path, idcode):
        """Программирование всех областей из файлов в папке"""
        # Анализ файлов
        analysis_result = self._analyze_files(folder_path)
        if not analysis_result:
            return False
        
        file_info = analysis_result['file_info']
        min_addr = analysis_result['min_addr']
        max_addr = analysis_result['max_addr']
        
        print(f"\nTotal address range: 0x{min_addr:08X} - 0x{max_addr:08X}")
        
        # Сортируем файлы по приоритету программирования
        file_info.sort(key=lambda x: x['priority'])
        print("\nProgramming order:")
        for i, file_data in enumerate(file_info):
            print(f"  {i+1}. {file_data['area_name']}: 0x{file_data['start_addr']:08X}-0x{file_data['end_addr']:08X}")
        
        # Инициализация программирования
        print("\nActivating flash programming mode...")
        activation_result = self.activate_flash_programming()
        if activation_result == 0:
            print("Error: Flash programming activation failed")
            return False
        
        if activation_result == 2:
            if not self.enterIdCode(bytearray.fromhex(idcode)):
                print("Error: ID Code entry failed")
                return False
        
        print("Erasing entire range...")
        if not self.erase(min_addr, max_addr):
            print("Error: Erase failed")
            return False
        
        # Программирование файлов по областям
        success_count = 0
        current_area = None
        
        for file_data in file_info:
            area_cmd = file_data['area_cmd']
            area_name = file_data['area_name']
            
            # Если сменилась область, выбираем новую (с завершением только при переходе к User Boot)
            if area_cmd != current_area:
                if not self._select_programming_area(area_cmd, area_name, current_area):
                    return False
                current_area = area_cmd
            
            # Программируем файл
            if self._program_single_file(file_data, area_cmd, area_name):
                success_count += 1
                print(f"  ✓ Successfully programmed")
            else:
                print(f"  ✗ Failed to program {file_data['path']}")
                return False
        
        # Финальное завершение программирования
        self._finalize_programming()
        
        print(f"\nProgramming summary: {success_count}/{len(file_info)} files successful")
        return success_count == len(file_info)

# Добавляем аргумент командной строки
def main():
    parser = argparse.ArgumentParser(description="RX63N/RX631 Programmer")
    parser.add_argument(
        "--port", help="Serial port name (e.g. COM1 or /dev/ttyUSB0)", required=True
    )
    parser.add_argument(
        "--hexfile", help="Firmware file in Intel HEX format", default=None
    )
    parser.add_argument("--binfile", help="Firmware file in BIN format", default=None)
    parser.add_argument(
        "--binaddr",
        help="Start address for BIN file (hex, e.g. 0xFFF00000)",
        default=None,
    )
    parser.add_argument(
        "--program", "-p", help="perform programming", action="store_true"
    )
    parser.add_argument("--read", "-r", help="perform reading", action="store_true")
    parser.add_argument(
        "--read-format",
        choices=["hex", "bin"],
        default="hex",
        help="Output format for reading: hex or bin",
    )
    parser.add_argument("--test", "-t", help="Test command 0x28", action="store_true")
    parser.add_argument("--debug", help="Debug Level", default = 0, type=int)
    parser.add_argument("--freq", help="Quartz Frequency,MHz default 12", default = 12, type=float)

    parser.add_argument(
        "--program-all", "-d", 
        help="Program all HEX and BIN files from specified folder",
        default=None
    )
    parser.add_argument(
        "--idcode",
        help="ID Code for flash programming (32 hex digits)",
        default="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    )
    args = parser.parse_args()

    # Проверка ID кода
    if len(args.idcode) != 32 or not all(c in "0123456789ABCDEFabcdef" for c in args.idcode):
        print("Error: ID Code must be exactly 32 hexadecimal digits")
        return 1


    # Проверка конфликтующих параметров
    program_modes = [args.program, args.program_all is not None]
    if sum(program_modes) > 1:
        print("Error: Specify only one of --program/-p or --program-all/-d")
        return 1
        
    if args.binfile and not args.binaddr and not args.program_all:
        print("Error: --binaddr must be specified when using --binfile")
        return 1
    if args.hexfile and args.binfile and not args.program_all:
        print("Error: Specify only one of --hexfile or --binfile")
        return 1

     # Создание программатора
    prog = RX63NProgrammer(args.port, debug=args.debug)

    # Инициализация соединения
    print("Matching bit rates...")
    if not prog.match_bit_rates():
        print("Error: Bit rate matching failed")
        return 1

    print("Getting supported devices...")
    if not prog.get_supported_devices():
        print("Error: Failed to get supported devices")
        return 1

    # Вывод списка устройств
    print("\nSupported devices:")
    for i, dev in enumerate(prog.device_list):
        print(f"{i}: {dev['name']} [{dev['code'].hex()}]")

    # Выбор первого устройства
    print("\nSelecting first device...")
    if not prog.set_device(0):
        print("Error: Device selection failed")
        return 1

    # здесь и далее уже чексуммы можно не использовать:
    prog.USE_CHECK_SUM = False

    print("Getting clock modes...")
    if not prog.get_clock_modes():
        print("Error: Failed to get clock modes")
        return 1

    # Вывод режимов тактирования
    print("\nClock modes:")
    for i, mode in enumerate(prog.clock_modes):
        print(f"{i}: 0x{mode:02X}")

    # Выбор первого режима
    print("\nSelecting first clock mode...")
    if not prog.set_clock_mode(0):
        print("Error: Clock mode selection failed")
        return 1

    print("Getting multiplication ratios...")
    if not prog.get_multiplication_ratios():
        print("Error: Failed to get multiplication ratios")
        return 1

    print("Getting operating frequencies...")
    if not prog.get_operating_frequencies():
        print("Error: Failed to get operating frequencies")
        return 1

    if not prog.flash_inquiry():
        print("Error; flash inquiry")
        return 1

    # Установка скорости обмена

    br_ratios = prog.get_baud(int(args.freq*1E6),SECOND_PHASE_BPS,SYS_RATIO,PERI_RATIO)
    if (None==br_ratios):
        print("Problems counting optimal bitrate")
        return 1
    print("\nSetting bit rate to %d bps..." % SECOND_PHASE_BPS)
    if not prog.set_bit_rate(br_ratios[0],int(args.freq*1E6),br_ratios[1],br_ratios[2]):
        print("Error: Bit rate setting failed")
        return 1

    print("Confirming bit rate...")
    if not prog.confirm_bit_rate():
        print("Error: Bit rate confirmation failed")
        return 1
    
    prog.get_erase_block_info()

    if args.program_all:
        print(f"Programming all files from folder: {args.program_all}")
        if not prog.program_all_areas(args.program_all, args.idcode):
            print("Error: Programming some files failed")
            return 1
        print("All files programmed successfully!")
        return 0
    elif args.program:
        # Для отдельных файлов также нужно добавить ID код
        if args.binfile:
            start_addr = int(args.binaddr, 16) if args.binaddr else None
            print(f"Programming BIN {args.binfile} at address 0x{start_addr:X} ...")
            
            # Активация программирования
            activation_result = prog.activate_flash_programming()
            if activation_result == 0:
                print("Error: Flash programming activation failed")
                return 1
            if activation_result == 2:
                if not prog.enterIdCode(bytearray.fromhex(args.idcode)):
                    print("Error: ID Code entry failed")
                    return 1
            
            if not prog.program_user_area(args.binfile, file_format="bin", start_addr=start_addr):
                print("Error: Programming failed")
                return 1
            print("Programming completed successfully!")
            return 0
        elif args.hexfile:
            print(f"Programming {args.hexfile}...")
            
            # Активация программирования
            activation_result = prog.activate_flash_programming()
            if activation_result == 0:
                print("Error: Flash programming activation failed")
                return 1
            if activation_result == 2:
                if not prog.enterIdCode(bytearray.fromhex(args.idcode)):
                    print("Error: ID Code entry failed")
                    return 1
            
            if not prog.program_user_area(args.hexfile, file_format="hex"):
                print("Error: Programming failed")
                return 1
            print("Programming completed successfully!")
            return 0
    elif args.read:
        print("Reading CPU...")
        if not prog.read(file_format=args.read_format, idcode=args.idcode):
            print("Error: Reading failed")
            return 1
        print("Reading completed successfully!")
        return 0


if __name__ == "__main__":
    sys.exit(main())