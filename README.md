# Описание

Простой программатор для процессоров `Renesas RX6*` в режиме загрузчика.
Функционал: чтение, стирание, запись различных областей флеш памяти.
Возможность установки `id-code` для чтения защищённых процессоров.

# Аппаратная часть

Для работы рекомендуется использовать **Linux**. На **Windows** работа не гарантируется из-за странных проблем в `pyserial`.
Я использовал для работы простой адаптер `USB to TTL CH340E Type C UART (TTL)`.

<img width="800" height="800" alt="USB to TTL adapter" src="https://github.com/user-attachments/assets/6b3b4b6d-3ab1-450a-9801-b6761f7fb64e" />

Пин, помеченный как `DTR` на самом деле является `RTS` и может быть использован как Reset.

# Поддержка

Поддержки проекта нет и не будет. Выкладывается "как есть", используйте на свой страх и риск.

# Установка

## Требования
- **Python 3.6+**
- **Linux** (рекомендуется) или **Windows** (работа не гарантируется)
- Адаптер USB-to-TTL (например CH340E)

## Установка зависимостей

```bash
pip install -r requirements.txt
```

Или установите зависимости вручную:
```bash
pip install pyserial intelhex tqdm
```

## Зависимости
- `pyserial` - работа с последовательным портом
- `intelhex` - работа с HEX файлами
- `tqdm` - индикатор прогресса

# Использование

## Основные команды

### Программирование HEX файла
```bash
python rxprog.py --port /dev/ttyUSB0 --hexfile firmware.hex --program
```

### Программирование BIN файла
```bash
python rxprog.py --port /dev/ttyUSB0 --binfile firmware.bin --binaddr 0xFFF00000 --program
```

### Чтение памяти процессора
```bash
python rxprog.py --port /dev/ttyUSB0 --read --read-format hex
```

### Программирование всех файлов из папки
```bash
python rxprog.py --port /dev/ttyUSB0 --program-all ./firmware_folder
```

## Параметры командной строки

- `--port` - последовательный порт (обязательный)
- `--hexfile` - путь к HEX файлу для программирования
- `--binfile` - путь к BIN файлу для программирования  
- `--binaddr` - стартовый адрес для BIN файла (в шестнадцатеричном формате)
- `--program` / `-p` - выполнить программирование
- `--read` / `-r` - выполнить чтение памяти
- `--read-format` - формат вывода при чтении (`hex` или `bin`)
- `--program-all` / `-d` - программировать все HEX/BIN файлы из указанной папки
- `--idcode` - ID код для программирования защищённых процессоров (32 hex цифры)
- `--debug` - уровень отладки (0-3)
- `--freq` - частота кварца в МГц (по умолчанию 12)

## Примеры использования

### Программирование с ID кодом
```bash
python rxprog.py --port /dev/ttyUSB0 --hexfile firmware.hex --program --idcode 1234567890ABCDEF1234567890ABCDEF
```

### Чтение в BIN формате
```bash
python rxprog.py --port /dev/ttyUSB0 --read --read-format bin
```

### Отладка с высоким уровнем
```bash
python rxprog.py --port /dev/ttyUSB0 --hexfile firmware.hex --program --debug 3
```

## Поддерживаемые процессоры
- Renesas RX63N
- Renesas RX631
- Другие процессоры семейства RX6x
