# Wire Format Halo Protocol v0

Статус: экспериментальный лабораторный формат Stage 1. Все многобайтовые целые числа без знака кодируются в сетевом порядке байтов (big-endian).

## Общий envelope

Каждый UDP datagram содержит ровно один envelope. Фиксированный заголовок имеет размер 24 байта:

| Смещение | Размер | Поле | Правило |
|---:|---:|---|---|
| 0 | 2 | `magic` | `0x48 0x56` (`HV`) |
| 2 | 1 | `version` | только `0x00` |
| 3 | 1 | `message_type` | таблица ниже |
| 4 | 2 | `flags` | ноль в v0 |
| 6 | 8 | `connection_id` | ненулевой непрозрачный идентификатор |
| 14 | 8 | `packet_number` | ноль для handshake; счётчик направления для transport |
| 22 | 2 | `payload_length` | точное число байтов после заголовка |

Полный размер datagram обязан равняться `24 + payload_length`; trailing bytes запрещены. Parser до выделения памяти на основании сетевых данных отвергает вход короче 24 и длиннее 1400 байт, неверный magic, неизвестную версию или тип, ненулевые flags, несогласованную длину и превышение лимита конкретного типа.

| Значение | Тип | Максимальное body | Body Stage 1 |
|---:|---|---:|---:|
| `0x01` | `HandshakeInit` | 488 | 96 для пустого IK payload |
| `0x02` | `HandshakeResponse` | 488 | 48 для пустого IK payload |
| `0x10` | `Data` | 1244 | `44 + application_length` |
| `0x11` | `KeepAlive` | 40 | 40 |
| `0x12` | `Close` | 48 | 48 |

Лимит неаутентифицированного handshake datagram — 512 байт. Лимит буфера UDP carrier — 1400 байт. Отправитель Stage 1 создаёт не более 1268 байт, поскольку application plaintext ограничен 1200 байтами.

## Handshake

Body `HandshakeInit` и `HandshakeResponse` — первое и второе сообщения Noise IK с пустыми Noise payload. Клиент создаёт случайный ненулевой connection ID, а ответ повторяет его. Идентификатор не является секретом и не предоставляет полномочий. Сервер связывает endpoint только после того, как первое IK-сообщение аутентифицирует статический ключ клиента из allowlist. Клиент принимает ответ только от настроенного endpoint и аутентифицированного статического ключа сервера.

Фиксированный Noise prologue — ASCII-строка:

```text
HaloVPN Stage 1|wire=0|Noise_IK_25519_ChaChaPoly_SHA256
```

## Transport protection

`snow::StatelessTransportState` получает внешний `packet_number` как Noise transport nonce. В wire format packet number остаётся big-endian; внутреннее форматирование nonce для ChaChaPoly определяется Noise и реализацией snow.

Stateless API snow не принимает associated data, поэтому Stage 1 аутентифицирует внешний заголовок, помещая его точную 24-байтовую копию в начало зашифрованного plaintext:

```text
NoiseEncrypt(packet_number, outer_header || protected_message)
```

Rust расшифровывает и constant-time сравнением проверяет этот prefix с полученным внешним заголовком до изменения replay window. Поэтому изменение connection ID, type, flags, length или packet number не делает пакет действительным и не занимает позицию replay. 16-байтовый tag ChaCha20-Poly1305 включается в `payload_length`.

### Защищённое сообщение Data

После зашифрованной копии заголовка:

| Смещение | Размер | Поле | Правило |
|---:|---:|---|---|
| 0 | 1 | `payload_type` | ноль (`OpaqueTestData`) |
| 1 | 1 | `payload_flags` | ноль |
| 2 | 2 | `payload_length` | от 0 до 1200, big-endian |
| 4 | N | payload | ровно N байт |

Compression, padding, batching и fragmentation отсутствуют.

### KeepAlive и Close

У KeepAlive нет защищённых байтов после зашифрованной копии заголовка. Close содержит 8 байт: big-endian `reason:u16`, нулевой `reserved:u16` и `detail:u32`. Оба типа расходуют packet number и позицию replay window.

## Replay и лимиты

Каждое направление начинает с packet number 0. Rust требует строго последовательные исходящие номера, отвергает дубликаты, принимает ранее не встречавшуюся перестановку внутри фиксированного окна на 2048 пакетов и отвергает более старые пакеты. Размер 2048 допускает ограниченную UDP-перестановку при фиксированном объёме состояния сессии: текущая лабораторная реализация использует 2048 boolean-значений. Ошибка аутентификации не изменяет окно.

Packet number `2^32` и выше возвращает `KeyLimitReached`; автоматический rekey не реализован. Сессия должна закрыться и выполнить новый handshake. Этот инженерный лимит ниже исчерпания примитива и предотвращает wrap или повторное использование.
