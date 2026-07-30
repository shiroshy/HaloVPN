# Архитектура и эксплуатация Private MVP

Private MVP сохраняет wire format Stage 1 и точный протокол `Noise_IK_25519_ChaChaPoly_SHA256`. Логин и пароль аутентифицируют только HTTPS-запросы ControlPlane. UDP-туннель принимает устройство, только если его статический публичный Noise-ключ находится в ограниченном allowlist активных устройств; пароль и токены никогда не входят в Noise handshake.

## Компоненты

- `HaloVPN.ControlPlane`: ASP.NET Core API, обязательный HTTPS вне Development, login/refresh rate limit по источнику, JWT access token со сроком 15 минут по умолчанию, транзакционная ротация хэшированных refresh token, регистрация устройств и выдача профиля. PostgreSQL блокирует строку предъявленного токена; отзыв parent, вставка replacement и обновление `replaced_by_token_id` фиксируются одной транзакцией. Параллельное повторное использование детерминированно отзывает всю family, включая созданный child: не более одного запроса получает replacement, и после гонки он не остаётся пригодным к использованию.
- `HaloVPN.Infrastructure`: модель EF Core/Npgsql PostgreSQL, Argon2id для паролей, транзакционное выделение адресов, auth/device/admin services и read-only authorization repository узла.
- `HaloVPN.AdminCli`: доступное только владельцу управление пользователями, устройствами и токенами, а также `database migrate`. Пароль читается без отображения либо из двух перенаправленных строк stdin, но никогда из аргументов.
- `HaloVPN.Node` и `HaloVPN.Platform.Linux`: ограниченные многоклиентские Noise-сессии, `/dev/net/tun`, source-address anti-spoofing, запрет client-to-client, outbound destination policy и fail-closed авторизация новых сессий. Недавний bounded snapshot allowlist позволяет существующим сессиям пережить краткую недоступность PostgreSQL или ControlPlane. Специальные и private destinations по умолчанию, tunnel subnet и локальные адреса VPS отвергаются до TUN; принадлежащая HaloVPN nftables table повторяет критические ограничения.
- `HaloVPN.WindowsService` и `HaloVPN.Platform.Windows`: LocalMachine DPAPI для device key, wrapper официального Wintun ABI, Noise/UDP packet pumps, обратимые route/DNS/IPv6 plans и named-pipe IPC с ACL пользователя и администраторов. Persistent guard — Wintun, `/1`, точные node/bootstrap `/32`, DNS и IPv6 block — сохраняется при transport reconnect и перезапуске службы. Ограниченный journal хранит только versioned typed descriptor, но не executable paths или arguments; rollback выполняется только при явном Disconnect или Logout.
- `HaloVPN.Desktop`: непривилегированный WPF-клиент для login/connect. Access token хранится в памяти, refresh token защищён CurrentUser DPAPI. Desktop никогда не получает приватный ключ устройства.
- `HaloVPN.Setup`: единый нативный Windows bootstrapper, проверка встроенного payload, первая установка и rollback-safe обновление без PowerShell у тестера.

PostgreSQL использует UTC, имена snake_case и уникальные индексы для нормализованных username, device keys, leases и token hashes. Raw refresh token в базе не хранится. Подсеть, gateway, MTU, лимит сессий и профиль единственного узла являются конфигурацией, а не разбросанными по коду значениями. Seed узла пропускается, пока оператор не задаст public host и 32-байтовый публичный ключ.

## ControlPlane и Admin CLI

Секреты задаются через environment процесса или внешнее хранилище:

```text
HALOVPN_DATABASE=Host=...;Database=halovpn;Username=...;Password=...
Tokens__SigningKeyBase64=<не-менее-32-случайных-байт>
VpnNode__PublicHost=<адрес-заданный-оператором>
VpnNode__PublicKeyBase64=<публичный-ключ-узла>
```

Применение миграции и управление пользователем:

```powershell
dotnet run --project src/HaloVPN.AdminCli -c Release -- database migrate
dotnet run --project src/HaloVPN.AdminCli -c Release -- user create alice 1
dotnet run --project src/HaloVPN.AdminCli -c Release -- user disable alice
```

Production ControlPlane отвергает plain HTTP. Предпочтителен обычный сертификат доверенного CA. Для частного развёртывания заранее переданный Base64 SHA-256 SPKI PIN вводится в опциональное поле Desktop; `HALOVPN_CONTROLPLANE_SPKI_PIN` остаётся compatibility fallback. PIN никогда не изучается через соединение, которое должен аутентифицировать. HTTP loopback разрешается только при явной development environment variable со значением `1`.

Raw refresh token не логируется и хранится в PostgreSQL только как хэш. Rotation выполняется в PostgreSQL-транзакции с блокировкой строки. При двух параллельных refresh один запрос может создать replacement, а обнаруживший reuse запрос отзывает всю family; созданный в этой гонке replacement после отзыва family также непригоден.

## Windows

### Предварительные требования

Получите официальный Wintun x64, проверьте лицензию распространения и поместите только ожидаемый `wintun.dll` по пути `HaloVPN:WintunDllPath`; по умолчанию это `C:\Program Files\HaloVPN\wintun.dll`. Build и runtime не скачивают DLL. При ручной установке перед запуском службы необходимо настроить `HaloVPN:AllowedUserSid` на SID пользователя Desktop.

Read-only preflight:

```powershell
.\scripts\preflight-windows.ps1 -?
```

Он проверяет ОС, Wintun exports, каталоги и ACL, SID, HTTPS/SPKI, bootstrap IPv4 и конфликт tunnel subnet, но ничего не устанавливает и не меняет сеть.

### Установщик тестера

`scripts/build-windows-oneclick.ps1` создаёт единый `publish/windows-oneclick/HaloVPN.exe`, содержащий Desktop, LocalSystem-службу, нативное Halo Protocol ядро и проверенный подписанный Wintun. При первом запуске bootstrapper запоминает SID инициирующего пользователя до UAC, проверяет и устанавливает ограниченный payload и запускает службу.

Когда тестер запускает полученный отдельно новый `HaloVPN.exe`, хэш встроенного релиза сравнивается с установленным marker. При различии предлагается in-place update. Новый payload полностью проверяется до остановки службы. Обновление сохраняет точный production `appsettings.json`, device data и persistent-guard journal, затем проверяет запуск новой службы. Локальный ограниченный backup восстанавливает предыдущие Desktop, Service, Wintun, license и launcher, если замена или запуск не удались.

Остановка службы для обновления не отправляет Disconnect, поэтому активный guard остаётся fail closed. Запуск уже установленного актуального release открывает Desktop. Установщик не требует от тестера PowerShell.

Setup проверяет SHA-256 приложенного payload, path traversal, состав компонентов и конкретный Wintun. Обновления распространяются как новый полный EXE; автоматического Internet download channel и доверенного signing-key root пока нет. Текущая private-сборка не подписана Authenticode, поэтому SmartScreen может показать неизвестного издателя.

### Persistent network guard

Служба создаёт Layer 3 adapter `HaloVPN`, добавляет для публичных node/bootstrap IPv4 точные host routes через исходный gateway, два IPv4 `/1` через Wintun, DNS адаптера и временный IPv6 block двумя явно именованными Windows Firewall rules. Journal содержит только typed inputs для реконструкции allowlisted rollback plan. Удаляются только HaloVPN-owned mutations.

Порядок применения:

1. открыть или создать Wintun adapter;
2. дождаться interface index;
3. назначить tunnel IPv4;
4. применить MTU;
5. добавить точный `/32` узла;
6. добавить точные bootstrap `/32`;
7. добавить full-tunnel `/1`;
8. применить DNS;
9. применить IPv6 guard;
10. записать валидный journal.

Ошибка до полного guard откатывает уже применённые owned mutations и оставляет обычную сеть. После установки guard transport failure не удаляет `/1` и IPv6 block: статус становится `ReconnectingProtected`, Wintun остаётся активным, а неотправленные пакеты ограниченно отбрасываются. Только explicit Disconnect или Logout удаляет guard. После аварии службы валидный journal восстанавливается как protected state, а не fail open.

До включения guard Desktop разрешает HTTPS hostname ControlPlane и передаёт службе не более 16 точных bootstrap IPv4. HTTP-соединения используют эти фиксированные socket destinations, сохраняя исходный hostname как request host и TLS SNI, обычную проверку сертификата и опциональный заранее настроенный SPKI PIN.

Клиент отправляет один и тот же сериализованный `HandshakeInit` до четырёх раз с начальным backoff 500 мс и общим timeout 10 секунд по умолчанию. После аутентификации он отправляет зашифрованный `KeepAlive` через 20 секунд без исходящего трафика. Узел возвращает один ограниченный аутентифицированный keepalive; после 65 секунд без аутентифицированного входящего трафика клиент переходит в protected reconnect.

Unit tests не меняют сеть хоста. Реальные Wintun-проверки требуют явно запущенного администратором integration flow и возможности немедленного rollback.

## Linux VPS

Используйте `deploy/linux/build-publish.sh Release`, затем следуйте [deploy/linux/README.md](../deploy/linux/README.md). Installer nftables требует явно заданный внешний интерфейс, принимает `HALOVPN_TUNNEL_SUBNET` и `HALOVPN_TUN_INTERFACE` и владеет только tables `halovpn_filter` и `halovpn_nat`. Он никогда не выполняет flush firewall хоста.

ControlPlane и Node работают отдельными systemd services. Node требуется `/dev/net/tun` и `CAP_NET_ADMIN`, но не custom kernel driver. Node проверяет source tunnel IPv4, блокирует client-to-client, multicast, broadcast, malformed packets, configured tunnel subnet, локальные интерфейсы VPS и denied destination CIDR до записи в TUN. Nftables дублирует критические outbound restrictions и разрешает NAT только из tunnel subnet через явно указанный external interface.

Read-only preflight использует явные `HALOVPN_*` environment values:

```bash
sudo -E ./deploy/linux/preflight.sh
```

Он сообщает prerequisites и конфликты без установки и без изменения routing, firewall или sysctl.

## Проверка и явные ограничения

Локальные автоматические тесты покрывают auth lifecycle, token rotation/reuse, device limits и leases, два параллельных нативных Noise-клиента, spoofing/client isolation, destination policy, authorization-cache outage, session/handshake bounds, Windows route/DNS/firewall planning, IPC parsing, DPAPI и обновление установщика. Тесты Stage 1 на tamper, replay и 10 000 loopback-сообщений сохранены.

Исходный код и локальные тесты сами по себе не доказывают корректность маршрутов конкретного VPS, nftables NAT до Internet, TLS provisioning или реальной установки Wintun. Эти результаты фиксируются отдельно для каждого развёртывания.

Реализован только IPv4 full tunnel. Split tunnel, IPv6 transport, публичная регистрация, платежи, web administration, маскировка трафика и обход DPI отсутствуют. Destination addresses, DNS queries и содержимое пакетов не являются audit-log данными.
