# План тестирования HaloVPN

Автоматические тесты проверяют лабораторный канал Stage 1 и логику Private MVP, но не заменяют аудит безопасности и проверку реального Windows → VPS → Internet.

## Автоматические .NET-тесты Stage 1

- сериализация и разбор всех пяти типов envelope и точных big-endian полей;
- round trip, неверный magic/version, короткий заголовок, несогласованная или избыточная длина и trailing data;
- 10 000 детерминированных случайных входов parser без необработанных исключений;
- управляемый из C# нативный IK handshake и зашифрованный двусторонний ping/pong;
- отклонение изменённого ciphertext и внешнего заголовка без расходования replay window;
- отклонение дубликата, перестановка внутри окна, слишком старый пакет и граница `2^32`;
- неверный статический ключ клиента и использование сессии после dispose;
- UDP loopback, отмена, handshake timeout и лимиты pending attempts;
- проверка отсутствия последовательности plaintext ping в зашифрованном datagram.

## Автоматические .NET-тесты Private MVP

- создание, нормализация, отключение пользователя и проверка Argon2id-пароля;
- login, logout, refresh rotation, token-family reuse и отзыв;
- регистрация и отзыв устройства, device limit, IP lease и исчерпание пула;
- два одновременных Noise-клиента и bounded active/pending sessions;
- source-IP anti-spoofing, client-to-client block, malformed IPv4 и destination policy;
- bounded authorization cache и поведение при временной недоступности PostgreSQL;
- потеря и повторная отправка handshake, response cache и его TTL/limits;
- аутентифицированный KeepAlive, replay/tamper, liveness timeout и отмена;
- построение Windows route/DNS/IPv6 plan без изменения реальной сети;
- persistent guard, protected reconnect, typed recovery journal и partial rollback;
- named-pipe validation, DPAPI-абстракции и ограничение размеров IPC;
- логика one-click installer и rollback-safe обновления.

Основной запуск:

```powershell
.\scripts\build-native.ps1 -Configuration Release
dotnet build HaloVPN.sln -c Release
dotnet test HaloVPN.sln -c Release --no-build
dotnet format HaloVPN.sln --verify-no-changes
```

PostgreSQL concurrency test использует настоящую тестовую базу только при заданной переменной `HALOVPN_POSTGRES_TEST`. База должна быть отдельной и одноразовой: тест применяет миграции и очищает таблицы HaloVPN.

## Rust-тесты

- успешный IK handshake и совместимые направления stateless transport;
- encrypt/decrypt, tamper, replay, неверный static key и порядок handshake;
- перестановка replay window и отклонение старых пакетов;
- null arguments, малый output buffer, destroy/double-destroy и invalid handles;
- намеренный panic, преобразованный в `HALO_INTERNAL_ERROR` внутри FFI boundary.

Запуск:

```powershell
cargo test --manifest-path native/halo-protocol/Cargo.toml
cargo clippy --manifest-path native/halo-protocol/Cargo.toml --all-targets
cargo build --release --locked --manifest-path native/halo-protocol/Cargo.toml
```

## Process-level acceptance Stage 1

Создать временные ключи вне репозитория, запустить ServerLab, затем ClientLab с `--count 10000`. Зафиксировать оба exit code, фазы established/closed, длительность и отсутствие секретов, plaintext и raw datagrams в выводе. Отдельно запустить ServerLab без клиента и убедиться, что handshake timeout завершает процесс без зависания.

## Проверки реальной Windows-сети

Unit tests не должны менять маршруты, DNS, firewall или Wintun. Реальные системные проверки выполняются отдельно с административными правами и возможностью немедленного explicit Disconnect:

- установка и повторное обновление Windows Service;
- создание Wintun и ожидание появления interface index;
- tunnel IPv4, MTU, точные `/32` и full-tunnel `/1` маршруты;
- DNS только на HaloVPN adapter;
- обратимые HaloVPN-owned IPv6 rules;
- сохранение guard при transport failure и reconnect;
- полное удаление только HaloVPN-owned изменений при Disconnect;
- восстановление обычного Internet после Disconnect.

Успешный локальный тест не доказывает работу конкретного VPS, nftables, NAT или внешнего DNS.

## Fuzzing

В `native/halo-protocol/fuzz` подготовлены targets `handshake_input`, `decrypt_input` и `abi_length_handling`. `cargo-fuzz` не устанавливается автоматически. Кампания должна фиксировать toolchain, продолжительность, corpus и crash artifacts.

Пример после отдельной доверенной установки cargo-fuzz:

```powershell
cargo fuzz run handshake_input --fuzz-dir native/halo-protocol/fuzz
cargo fuzz run decrypt_input --fuzz-dir native/halo-protocol/fuzz
cargo fuzz run abi_length_handling --fuzz-dir native/halo-protocol/fuzz
```

## Оставшееся покрытие

- длительные fuzz- и sanitizer-кампании;
- продолжительная нагрузка и rate testing журналов;
- автоматический rekey и overlap после проектирования протокола;
- тесты ротации ключей узла;
- независимый аудит;
- воспроизводимая проверка полного пути Windows → конкретный VPS → Internet для каждого production deployment.
