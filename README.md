# HaloVPN

HaloVPN — частный IPv4 VPN для небольшого числа пользователей с одним Linux-узлом и Windows-клиентами. Репозиторий содержит лабораторный защищённый UDP-канал Stage 1 и развиваемый Private MVP: ControlPlane, Admin CLI, Linux Node, Windows Service с Wintun и минимальный WPF-клиент.

Это не независимо аудированный и не готовый для массового распространения VPN-продукт. Перед эксплуатацией конкретное развёртывание необходимо проверить по полному пути Windows → VPS → Internet, включая маршрутизацию, DNS, IPv6 guard, NAT и восстановление после разрыва связи.

## Архитектура

```text
HaloVPN Desktop
    └─ versioned named pipe
       └─ Windows Service (LocalSystem)
          ├─ Wintun
          ├─ persistent network guard
          └─ Halo Protocol over UDP
             └─ Linux Node
                ├─ Linux TUN
                └─ nftables NAT → Internet

Desktop → HTTPS → ControlPlane → PostgreSQL
```

Логин и пароль используются только для авторизации через HTTPS ControlPlane. Сам VPN-туннель аутентифицируется статическим ключом устройства:

```text
login/password
    → HTTPS ControlPlane
    → access/refresh token
    → регистрация публичного ключа устройства
    → профиль узла и внутренний IPv4
    → Noise IK tunnel authentication
```

Приватный ключ устройства создаётся Windows Service, хранится локально под защитой Windows и не передаётся Desktop или ControlPlane.

## Протокол и криптография

Используется единственный зафиксированный протокол:

```text
Noise_IK_25519_ChaChaPoly_SHA256
```

Согласования cipher suites нет. Полная Noise state machine, статические и эфемерные X25519-секреты, ChaCha20-Poly1305 transport states, счётчики пакетов и replay window находятся в Rust-ядре. C# управляет UDP carrier, 24-байтовым внешним envelope, жизненным циклом сессии и платформенной интеграцией, но не получает сессионные ключи.

После handshake применяются аутентифицированные packet numbers и скользящее replay window на 2048 пакетов. Повреждённые, повторные и слишком старые пакеты отвергаются.

## Основные каталоги

- `native/halo-protocol` — Rust/Noise-ядро и C ABI;
- `src/HaloVPN.ControlPlane` — HTTPS API авторизации, устройств и VPN-профилей;
- `src/HaloVPN.Infrastructure` — EF Core, PostgreSQL и миграции;
- `src/HaloVPN.AdminCli` — административное управление пользователями и устройствами;
- `src/HaloVPN.Node` — многоклиентский Linux UDP/TUN-узел;
- `src/HaloVPN.WindowsService` — привилегированная Windows-служба;
- `src/HaloVPN.Desktop` — пользовательский WPF-клиент;
- `src/HaloVPN.Setup` — нативный bootstrapper установщика и обновления;
- `deploy/linux` — systemd, nftables, sysctl и preflight для VPS;
- `docs` — формат протокола, threat model, ключи и эксплуатационная документация.

## Требования для сборки

- .NET SDK 10;
- Rust stable и Cargo;
- Windows 10/11 x64 для Windows-релиза;
- официальный `wintun.dll` x64 версии 0.14.1 для создания установщика;
- PostgreSQL для ControlPlane и интеграционных тестов, которым требуется настоящая база.

Скрипты не скачивают Wintun или другие сторонние бинарники автоматически.

## Сборка и тесты

```powershell
.\scripts\build-native.ps1 -Configuration Release

cargo test --manifest-path native/halo-protocol/Cargo.toml
cargo clippy --manifest-path native/halo-protocol/Cargo.toml --all-targets
cargo build --manifest-path native/halo-protocol/Cargo.toml --release

dotnet build HaloVPN.sln -c Release
dotnet test HaloVPN.sln -c Release --no-build
dotnet format HaloVPN.sln --verify-no-changes
```

Нативная сборка использует закреплённый `Cargo.lock` и копирует только ожидаемую библиотеку в `artifacts/native/<Configuration>/win-x64`. Debug и Release не смешиваются. Каталоги `target`, `bin`, `obj`, `artifacts`, `publish`, приватные ключи и production-конфигурация исключены из Git.

## Установщик для Windows-тестера

Создание единого самодостаточного EXE:

```powershell
.\scripts\build-windows-oneclick.ps1 `
  -Configuration Release `
  -WintunDllPath 'C:\проверенный-путь\wintun.dll'
```

Результат:

```text
publish/windows-oneclick/HaloVPN.exe
publish/windows-oneclick/HaloVPN.exe.sha256.txt
```

Установщик содержит Desktop, Windows Service, нативное Noise-ядро и проверенный Wintun. Перед упаковкой скрипт проверяет Authenticode-подпись WireGuard LLC и точный SHA-256 разрешённой DLL. В payload не включаются production `appsettings.json`, ключи, токены, recovery journal и PDB.

Тестеру достаточно запустить `HaloVPN.exe` и подтвердить UAC. Установщик:

1. определяет SID запустившего пользователя до повышения прав;
2. устанавливает LocalSystem-службу и Desktop;
3. создаёт защищённый каталог данных;
4. запускает службу;
5. открывает HaloVPN Desktop.

Для входа нужны:

- HTTPS URL ControlPlane;
- имя пользователя;
- пароль;
- опциональный заранее проверенный SPKI PIN.

SPKI PIN — Base64-кодированный SHA-256 отпечаток публичного ключа TLS-сертификата ControlPlane. При обычном сертификате от доверенного CA поле можно оставить пустым. Для частного self-signed сертификата PIN необходимо передать пользователю отдельным доверенным каналом.

Текущий Private MVP не подписывает сам `HaloVPN.exe` сертификатом Authenticode, поэтому SmartScreen может показать предупреждение о неизвестном издателе.

## Обновление Windows-клиента

Онлайн-поиска и автоматического скачивания обновлений пока нет. Для обновления владелец передаёт тестеру новый полный `HaloVPN.exe`.

При запуске новый EXE сравнивает хэш встроенного релиза с:

```text
C:\Program Files\HaloVPN\release.sha256
```

Если версия отличается, установщик предлагает обновление и:

- полностью проверяет новый payload до изменения установки;
- сохраняет точный production `appsettings.json`;
- не удаляет device key и `network-plan.json`;
- заменяет Desktop, Service, Wintun и принадлежащие HaloVPN ярлыки;
- проверяет запуск обновлённой службы;
- восстанавливает предыдущую версию при ошибке.

Остановка службы во время обновления не выполняет Disconnect. Если persistent guard был активен, сеть остаётся fail-closed до запуска обновлённой или восстановленной службы.

Файл `HaloVPN.exe.sha256.txt` не требуется установщику, но его рекомендуется передавать тестеру для внешней проверки целостности. Сам хэш желательно сообщать отдельным доверенным каналом.

## Лабораторная генерация ключей

После Release-сборки создайте каждый приватный ключ по новому явно указанному пути:

```powershell
dotnet run --project src/HaloVPN.KeyGen -c Release --no-build -- `
  --private-key C:\secure-lab\server.key

dotnet run --project src/HaloVPN.KeyGen -c Release --no-build -- `
  --private-key C:\secure-lab\client.key
```

Инструмент не перезаписывает существующий файл, сохраняет ровно 32 байта приватного ключа и выводит только публичный ключ в Base64. На Windows файл наследует ACL родительского каталога, поэтому каталог должен быть заранее ограничен нужной учётной записью.

## Локальная проверка Stage 1

Сервер:

```powershell
dotnet run --project src/HaloVPN.ServerLab -c Release --no-build -- `
  --listen 127.0.0.1 `
  --port 45000 `
  --private-key C:\secure-lab\server.key `
  --client-public <публичный-ключ-клиента-base64> `
  --verbose
```

Клиент:

```powershell
dotnet run --project src/HaloVPN.ClientLab -c Release --no-build -- `
  --server 127.0.0.1:45000 `
  --private-key C:\secure-lab\client.key `
  --server-public <публичный-ключ-сервера-base64> `
  --count 10000 `
  --timeout 5
```

Диагностика может содержать endpoint, connection ID, фазу, безопасный код отказа и количество сообщений. Приватные и сессионные ключи, plaintext, расшифрованные пакеты, authentication tags и полные datagrams не логируются.

## Развёртывание Private MVP

Архитектура ControlPlane, PostgreSQL, Linux Node и Windows guard описана в [docs/private-mvp.md](docs/private-mvp.md). Инструкции VPS находятся в [deploy/linux/README.md](deploy/linux/README.md).

Preflight-проверки ничего не изменяют:

```text
deploy/linux/preflight.sh
scripts/preflight-windows.ps1
```

Они проверяют платформу, TUN/Wintun, интерфейсы, маршруты, порты, TLS, PostgreSQL и конфигурацию, но не устанавливают службу, не меняют firewall и не включают маршрутизацию.

## Ограничения

- только IPv4 full tunnel;
- один Linux-узел и небольшое число пользователей;
- нет split tunneling и IPv6-туннеля;
- нет маскировки трафика и обхода DPI;
- нет публичной регистрации, платежей и web-admin;
- нет встроенного онлайн-канала обновлений;
- Wintun DLL предоставляется оператором;
- Internet/NAT и поведение kill switch должны проверяться на каждом реальном развёртывании;
- проект не проходил независимый аудит безопасности.

Не помещайте в Git приватные ключи, токены, пароли, connection strings, TLS-ключи, production-конфигурацию, DLL/EXE/PDB, publish output или данные PostgreSQL.
