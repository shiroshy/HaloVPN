using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace HaloVPN.Setup;

internal static partial class Program
{
    private const string ServiceName = "HaloVPN";
    private const string ExpectedWintunSha256 = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE";
    private const string PayloadMagic = "HALOVPN_PAYLOAD1";
    private const int PayloadFooterSize = 56;
    private const long MaximumPayloadBytes = 512L * 1024 * 1024;
    private const long MaximumExtractedBytes = 768L * 1024 * 1024;
    private const int MaximumArchiveEntries = 2048;
    private const uint MessageInformation = 0x40;
    private const uint MessageError = 0x10;
    private const uint MessageYesNo = 0x04;
    private const int MessageResultYes = 6;

    private static readonly string InstallRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "HaloVPN");
    private static readonly string ServiceDirectory = Path.Combine(InstallRoot, "Service");
    private static readonly string DesktopDirectory = Path.Combine(InstallRoot, "Desktop");
    private static readonly string LicenseDirectory = Path.Combine(InstallRoot, "licenses");
    private static readonly string InstalledDesktop = Path.Combine(DesktopDirectory, "HaloVPN.Desktop.exe");
    private static readonly string InstalledLauncher = Path.Combine(InstallRoot, "HaloVPN.exe");
    private static readonly string ReleaseMarker = Path.Combine(InstallRoot, "release.sha256");
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "HaloVPN");

    [STAThread]
    private static int Main(string[] args)
    {
        var verifyOnly = args.Contains("--verify", StringComparer.Ordinal);
        try
        {
            if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041) ||
                RuntimeInformation.OSArchitecture != Architecture.X64)
            {
                throw new PlatformNotSupportedException("HaloVPN поддерживает Windows 10/11 x64.");
            }

            if (verifyOnly)
            {
                VerifyEmbeddedPayload();
                return 0;
            }

            var installRequested = args.Contains("--install", StringComparer.Ordinal);
            var updateRequested = args.Contains("--update", StringComparer.Ordinal);
            var confirmed = args.Contains("--confirmed", StringComparer.Ordinal);
            var allowedSid = GetArgument(args, "--allowed-sid");
            if (!installRequested && !updateRequested && IsInstalled())
            {
                if (IsCurrentRelease())
                {
                    StartDesktop();
                    return 0;
                }

                if (MessageBox(
                        0,
                        "Доступна новая версия HaloVPN.\n\n" +
                        "Обновить Desktop и службу сейчас? Настройки и ключ устройства будут сохранены.",
                        "Обновление HaloVPN",
                        MessageYesNo | MessageInformation) != MessageResultYes)
                {
                    StartDesktop();
                    return 0;
                }

                allowedSid ??= GetCurrentUserSid();
                if (!IsAdministrator())
                {
                    var previousDesktopLauncherHash = GetExistingDesktopLauncherHash();
                    var exitCode = RunElevatedOperation("--update", allowedSid, confirmed: true);
                    if (exitCode == 0)
                    {
                        TryCreateDesktopLauncher(previousDesktopLauncherHash);
                        StartDesktop();
                    }

                    return exitCode;
                }

                updateRequested = true;
                confirmed = true;
            }

            if (!IsAdministrator() && !updateRequested)
            {
                allowedSid ??= GetCurrentUserSid();
                var exitCode = RunElevatedOperation("--install", allowedSid, confirmed: false);
                if (exitCode == 0)
                {
                    TryCreateDesktopLauncher(previousHash: null);
                    StartDesktop();
                }

                return exitCode;
            }
            if (!IsAdministrator())
            {
                allowedSid ??= GetCurrentUserSid();
                var exitCode = RunElevatedOperation(
                    updateRequested ? "--update" : "--install",
                    allowedSid,
                    confirmed);
                if (exitCode == 0)
                {
                    StartDesktop();
                }

                return exitCode;
            }

            allowedSid ??= GetCurrentUserSid();
            ValidateUserSid(allowedSid);
            if (updateRequested)
            {
                if (!confirmed &&
                    MessageBox(
                        0,
                        "Обновить существующую установку HaloVPN?\n\n" +
                        "Сетевой guard останется защищённым во время перезапуска службы.",
                        "Обновление HaloVPN",
                        MessageYesNo | MessageInformation) != MessageResultYes)
                {
                    return 20;
                }

                Update();
                MessageBox(
                    0,
                    "HaloVPN успешно обновлён. Настройки, ключ устройства и состояние guard сохранены.",
                    "HaloVPN",
                    MessageInformation);
                return 0;
            }

            if (MessageBox(
                    0,
                    "Установить HaloVPN для текущего пользователя?\n\n" +
                    "Будет установлена LocalSystem-служба, официальный Wintun и приложение HaloVPN.",
                    "Установка HaloVPN",
                    MessageYesNo | MessageInformation) != MessageResultYes)
            {
                return 20;
            }

            Install(allowedSid);
            MessageBox(
                0,
                "HaloVPN установлен.\n\nПриложение сейчас откроется автоматически. " +
                "Для входа понадобятся адрес ControlPlane, логин и пароль.",
                "HaloVPN",
                MessageInformation);
            return 0;
        }
        catch (Exception exception)
        {
            if (!verifyOnly)
            {
                MessageBox(
                    0,
                    "Установка HaloVPN не завершена.\n\n" + SafeError(exception),
                    "Ошибка HaloVPN",
                    MessageError);
            }

            return 1;
        }
    }

    private static bool IsInstalled() =>
        File.Exists(InstalledDesktop) &&
        File.Exists(Path.Combine(ServiceDirectory, "HaloVPN.WindowsService.exe")) &&
        File.Exists(Path.Combine(ServiceDirectory, "appsettings.json"));

    private static bool IsCurrentRelease()
    {
        if (!File.Exists(ReleaseMarker))
        {
            return false;
        }

        var installedHash = File.ReadAllText(ReleaseMarker).Trim();
        return installedHash.Equals(GetCurrentPayloadHash(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ??
            throw new InvalidOperationException("Не удалось определить SID текущего пользователя.");
    }

    private static void ValidateUserSid(string value)
    {
        var sid = new SecurityIdentifier(value);
        if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
            sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
            !value.StartsWith("S-1-5-21-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SID пользователя не подходит для доступа Desktop к службе.");
        }
    }

    private static int RunElevatedOperation(string operation, string allowedSid, bool confirmed)
    {
        var executable = Environment.ProcessPath ??
            throw new InvalidOperationException("Путь к HaloVPN.exe недоступен.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
        };
        start.ArgumentList.Add(operation);
        start.ArgumentList.Add("--allowed-sid");
        start.ArgumentList.Add(allowedSid);
        if (confirmed)
        {
            start.ArgumentList.Add("--confirmed");
        }

        try
        {
            using var process = Process.Start(start) ??
                throw new InvalidOperationException("Не удалось запустить установщик с правами администратора.");
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            return 20;
        }
    }

    private static void Install(string allowedSid)
    {
        if (Directory.Exists(InstallRoot) || ServiceExists())
        {
            throw new InvalidOperationException(
                "Обнаружена существующая или незавершённая установка. " +
                "Запустите уже установленный HaloVPN либо обратитесь к владельцу для безопасного обновления.");
        }

        var temporaryRoot = Path.Combine(
            Path.GetTempPath(),
            "halovpn-setup-" + Guid.NewGuid().ToString("N"));
        var serviceCreated = false;
        try
        {
            Directory.CreateDirectory(temporaryRoot);
            ExtractAndValidatePayload(temporaryRoot);

            Directory.CreateDirectory(ServiceDirectory);
            Directory.CreateDirectory(DesktopDirectory);
            CopyDirectory(Path.Combine(temporaryRoot, "Service"), ServiceDirectory);
            CopyDirectory(Path.Combine(temporaryRoot, "Desktop"), DesktopDirectory);
            File.Copy(Path.Combine(temporaryRoot, "wintun.dll"), Path.Combine(InstallRoot, "wintun.dll"));

            var licenseSource = Path.Combine(temporaryRoot, "licenses");
            if (Directory.Exists(licenseSource))
            {
                CopyDirectory(licenseSource, Path.Combine(InstallRoot, "licenses"));
            }

            var processPath = Environment.ProcessPath ??
                throw new InvalidOperationException("Путь к HaloVPN.exe недоступен.");
            File.Copy(processPath, InstalledLauncher);

            Directory.CreateDirectory(DataDirectory);
            var aclResult = RunTool(
                "icacls.exe",
                [
                    DataDirectory,
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ]);
            if (aclResult.ExitCode != 0)
            {
                throw new InvalidOperationException("Не удалось защитить каталог ключа устройства.");
            }

            WriteServiceConfiguration(allowedSid);
            var serviceExecutable = Path.Combine(ServiceDirectory, "HaloVPN.WindowsService.exe");
            var createResult = RunTool(
                "sc.exe",
                [
                    "create",
                    ServiceName,
                    "binPath=",
                    $"\"{serviceExecutable}\"",
                    "start=",
                    "auto",
                    "obj=",
                    "LocalSystem",
                    "DisplayName=",
                    "HaloVPN",
                ]);
            if (createResult.ExitCode != 0)
            {
                throw new InvalidOperationException("Не удалось зарегистрировать службу HaloVPN.");
            }

            serviceCreated = true;
            _ = RunTool(
                "sc.exe",
                ["description", ServiceName, "HaloVPN protected Windows tunnel service"]);
            if (!StartServiceAndVerify())
            {
                throw new InvalidOperationException("Служба HaloVPN не запустилась.");
            }

            WriteReleaseMarker();
            TryCreateStartMenuLauncher(previousHash: null);
        }
        catch
        {
            if (serviceCreated)
            {
                _ = RunTool("sc.exe", ["stop", ServiceName]);
                _ = RunTool("sc.exe", ["delete", ServiceName]);
            }

            SafeDeleteInstallRoot();
            throw;
        }
        finally
        {
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }
        }
    }

    private static void Update()
    {
        if (!IsInstalled() || !ServiceExists())
        {
            throw new InvalidOperationException("Существующая установка HaloVPN неполна; автоматическое обновление отменено.");
        }

        var temporaryRoot = Path.Combine(
            Path.GetTempPath(),
            "halovpn-update-" + Guid.NewGuid().ToString("N"));
        var backupRoot = InstallRoot + ".update-backup-" + Guid.NewGuid().ToString("N");
        var configPath = Path.Combine(ServiceDirectory, "appsettings.json");
        var configHash = HashFile(configPath);
        var oldLauncherHash = File.Exists(InstalledLauncher)
            ? HashFile(InstalledLauncher)
            : null;
        var filesMoved = false;
        var backupComplete = false;
        var serviceStopRequested = false;
        try
        {
            Directory.CreateDirectory(temporaryRoot);
            ExtractAndValidatePayload(temporaryRoot);
            CloseInstalledDesktop();
            serviceStopRequested = true;
            _ = RunTool("sc.exe", ["stop", ServiceName]);
            WaitForProcessExit("HaloVPN.WindowsService", TimeSpan.FromSeconds(30));

            Directory.CreateDirectory(backupRoot);
            filesMoved = true;
            Directory.Move(ServiceDirectory, Path.Combine(backupRoot, "Service"));
            Directory.Move(DesktopDirectory, Path.Combine(backupRoot, "Desktop"));
            if (Directory.Exists(LicenseDirectory))
            {
                Directory.Move(LicenseDirectory, Path.Combine(backupRoot, "licenses"));
            }
            MoveFileToBackup(Path.Combine(InstallRoot, "wintun.dll"), backupRoot);
            MoveFileToBackup(InstalledLauncher, backupRoot);
            MoveFileToBackup(ReleaseMarker, backupRoot);
            backupComplete = true;

            Directory.CreateDirectory(ServiceDirectory);
            Directory.CreateDirectory(DesktopDirectory);
            CopyDirectory(Path.Combine(temporaryRoot, "Service"), ServiceDirectory);
            CopyDirectory(Path.Combine(temporaryRoot, "Desktop"), DesktopDirectory);
            File.Copy(Path.Combine(temporaryRoot, "wintun.dll"), Path.Combine(InstallRoot, "wintun.dll"));
            var licenseSource = Path.Combine(temporaryRoot, "licenses");
            if (Directory.Exists(licenseSource))
            {
                CopyDirectory(licenseSource, LicenseDirectory);
            }

            File.Copy(
                Path.Combine(backupRoot, "Service", "appsettings.json"),
                configPath);
            var updatedConfigHash = HashFile(configPath);
            if (!updatedConfigHash.Equals(configHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Production appsettings.json изменился во время обновления.");
            }

            var processPath = Environment.ProcessPath ??
                throw new InvalidOperationException("Путь к HaloVPN.exe недоступен.");
            File.Copy(processPath, InstalledLauncher);
            if (!StartServiceAndVerify())
            {
                throw new InvalidOperationException("Обновлённая служба HaloVPN не запустилась.");
            }
            serviceStopRequested = false;

            WriteReleaseMarker();
            TryCreateStartMenuLauncher(oldLauncherHash);
            Directory.Delete(backupRoot, recursive: true);
            filesMoved = false;
        }
        catch (Exception updateException)
        {
            if (filesMoved)
            {
                if (!TryRollbackUpdate(backupRoot, backupComplete))
                {
                    throw new InvalidOperationException(
                        "Обновление не завершено, а автоматический rollback службы не удался. " +
                        "Persistent guard не удалялся; обратитесь к владельцу.",
                        updateException);
                }

                filesMoved = false;
                if (Directory.Exists(backupRoot))
                {
                    Directory.Delete(backupRoot, recursive: true);
                }
            }
            else if (serviceStopRequested && !StartServiceAndVerify())
            {
                throw new InvalidOperationException(
                    "Обновление не началось, но служба не смогла возобновить работу. " +
                    "Persistent guard не удалялся; обратитесь к владельцу.",
                    updateException);
            }

            throw new InvalidOperationException(
                "Обновление отменено; предыдущая версия восстановлена.",
                updateException);
        }
        finally
        {
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }

            if (!filesMoved && Directory.Exists(backupRoot))
            {
                Directory.Delete(backupRoot, recursive: true);
            }
        }
    }

    private static bool TryRollbackUpdate(string backupRoot, bool backupComplete)
    {
        try
        {
            _ = RunTool("sc.exe", ["stop", ServiceName]);
            WaitForProcessExit("HaloVPN.WindowsService", TimeSpan.FromSeconds(15));
            RestoreDirectoryFromBackup("Service", ServiceDirectory, backupRoot, backupComplete);
            RestoreDirectoryFromBackup("Desktop", DesktopDirectory, backupRoot, backupComplete);
            RestoreDirectoryFromBackup("licenses", LicenseDirectory, backupRoot, backupComplete);
            RestoreFileFromBackup("wintun.dll", backupRoot, backupComplete);
            RestoreFileFromBackup("HaloVPN.exe", backupRoot, backupComplete);
            RestoreFileFromBackup("release.sha256", backupRoot, backupComplete);
            return StartServiceAndVerify();
        }
        catch
        {
            return false;
        }
    }

    private static void VerifyEmbeddedPayload()
    {
        var temporaryRoot = Path.Combine(
            Path.GetTempPath(),
            "halovpn-verify-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(temporaryRoot);
            ExtractAndValidatePayload(temporaryRoot);
        }
        finally
        {
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }
        }
    }

    private static void ExtractAndValidatePayload(string destination)
    {
        var archivePath = CopyVerifiedPayloadToTemporaryFile(destination);
        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count is 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException("Payload содержит недопустимое количество файлов.");
        }

        long totalLength = 0;
        var root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        foreach (var entry in archive.Entries)
        {
            var normalized = entry.FullName.Replace('\\', '/');
            if (normalized.StartsWith("/", StringComparison.Ordinal) ||
                normalized.Contains("../", StringComparison.Ordinal) ||
                normalized.Contains(':', StringComparison.Ordinal))
            {
                throw new InvalidDataException("Payload содержит небезопасный путь.");
            }

            var topLevel = normalized.Split('/', 2)[0];
            if (topLevel is not ("Service" or "Desktop" or "licenses" or "wintun.dll"))
            {
                throw new InvalidDataException("Payload содержит неизвестный компонент.");
            }

            totalLength = checked(totalLength + entry.Length);
            if (totalLength > MaximumExtractedBytes)
            {
                throw new InvalidDataException("Распакованный payload превышает лимит.");
            }

            var target = Path.GetFullPath(Path.Combine(destination, normalized.Replace('/', Path.DirectorySeparatorChar)));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Payload выходит за каталог установки.");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target);
        }

        RequirePayloadFile(destination, "Service", "HaloVPN.WindowsService.exe");
        RequirePayloadFile(destination, "Service", "halo_protocol.dll");
        RequirePayloadFile(destination, "Desktop", "HaloVPN.Desktop.exe");
        var wintunPath = RequirePayloadFile(destination, "wintun.dll");
        var actualWintunHash = HashFile(wintunPath);
        if (!actualWintunHash.Equals(ExpectedWintunSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Wintun DLL не соответствует проверенной версии.");
        }
    }

    private static string CopyVerifiedPayloadToTemporaryFile(string destination)
    {
        var executable = Environment.ProcessPath ??
            throw new InvalidOperationException("Путь к HaloVPN.exe недоступен.");
        using var source = File.Open(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (source.Length < PayloadFooterSize)
        {
            throw new InvalidDataException("HaloVPN.exe не содержит payload.");
        }

        source.Position = source.Length - PayloadFooterSize;
        Span<byte> footer = stackalloc byte[PayloadFooterSize];
        source.ReadExactly(footer);
        if (!footer[..16].SequenceEqual(Encoding.ASCII.GetBytes(PayloadMagic)))
        {
            throw new InvalidDataException("HaloVPN.exe содержит неверный footer.");
        }

        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(footer.Slice(16, 8));
        if (payloadLength <= 0 || payloadLength > MaximumPayloadBytes ||
            payloadLength > source.Length - PayloadFooterSize)
        {
            throw new InvalidDataException("Размер payload недопустим.");
        }

        var expectedHash = footer[24..].ToArray();
        var payloadOffset = source.Length - PayloadFooterSize - payloadLength;
        source.Position = payloadOffset;
        var archivePath = Path.Combine(destination, "payload.zip");
        using (var output = File.Create(archivePath))
        using (var hashing = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            var buffer = new byte[128 * 1024];
            long remaining = payloadLength;
            while (remaining > 0)
            {
                var read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read == 0)
                {
                    throw new EndOfStreamException("Payload неожиданно завершился.");
                }

                output.Write(buffer, 0, read);
                hashing.AppendData(buffer, 0, read);
                remaining -= read;
            }

            if (!CryptographicOperations.FixedTimeEquals(hashing.GetHashAndReset(), expectedHash))
            {
                throw new InvalidDataException("SHA-256 payload не совпадает.");
            }
        }

        return archivePath;
    }

    private static string RequirePayloadFile(string root, params string[] segments)
    {
        var path = segments.Aggregate(root, Path.Combine);
        return File.Exists(path)
            ? path
            : throw new InvalidDataException($"Payload не содержит {string.Join('/', segments)}.");
    }

    private static void CopyDirectory(string source, string destination)
    {
        var sourceRoot = Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar);
        foreach (var directory in Directory.EnumerateDirectories(sourceRoot, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(sourceRoot, directory)));
        }

        foreach (var file in Directory.EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(sourceRoot, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }

    private static void CloseInstalledDesktop()
    {
        foreach (var process in Process.GetProcessesByName("HaloVPN.Desktop"))
        {
            using (process)
            {
                string? executablePath;
                try
                {
                    executablePath = process.MainModule?.FileName;
                }
                catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
                {
                    continue;
                }

                if (!string.Equals(
                        Path.GetFullPath(executablePath ?? string.Empty),
                        Path.GetFullPath(InstalledDesktop),
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                _ = process.CloseMainWindow();
                if (!process.WaitForExit(5_000))
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(5_000);
                }
            }
        }
    }

    private static void WaitForProcessExit(string processName, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var processes = Process.GetProcessesByName(processName);
            try
            {
                if (processes.Length == 0)
                {
                    return;
                }
            }
            finally
            {
                foreach (var process in processes)
                {
                    process.Dispose();
                }
            }

            Thread.Sleep(250);
        }

        throw new TimeoutException($"Процесс {processName} не остановился за отведённое время.");
    }

    private static void MoveFileToBackup(string path, string backupRoot)
    {
        if (File.Exists(path))
        {
            File.Move(path, Path.Combine(backupRoot, Path.GetFileName(path)));
        }
    }

    private static void RestoreFileFromBackup(string name, string backupRoot, bool removeReplacement)
    {
        var source = Path.Combine(backupRoot, name);
        var destination = Path.Combine(InstallRoot, name);
        if (File.Exists(source))
        {
            DeleteFileIfPresent(destination);
            File.Move(source, destination);
        }
        else if (removeReplacement)
        {
            DeleteFileIfPresent(destination);
        }
    }

    private static void RestoreDirectoryFromBackup(
        string name,
        string destination,
        string backupRoot,
        bool removeReplacement)
    {
        var source = Path.Combine(backupRoot, name);
        if (Directory.Exists(source))
        {
            DeleteDirectoryIfPresent(destination);
            Directory.Move(source, destination);
        }
        else if (removeReplacement)
        {
            DeleteDirectoryIfPresent(destination);
        }
    }

    private static void DeleteDirectoryIfPresent(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }

    private static void DeleteFileIfPresent(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static void WriteServiceConfiguration(string allowedSid)
    {
        static string Json(string value) =>
            "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

        var deviceKeyPath = Path.Combine(DataDirectory, "device-key.json");
        var journalPath = Path.Combine(DataDirectory, "network-plan.json");
        var wintunPath = Path.Combine(InstallRoot, "wintun.dll");
        var json = $$"""
        {
          "HaloVPN": {
            "PipeName": "HaloVPN.Service.v1",
            "AllowedUserSid": {{Json(allowedSid)}},
            "DeviceKeyPath": {{Json(deviceKeyPath)}},
            "WintunDllPath": {{Json(wintunPath)}},
            "NetworkJournalPath": {{Json(journalPath)}},
            "AdapterName": "HaloVPN",
            "HandshakeAttempts": 4,
            "HandshakeInitialDelay": "00:00:00.500",
            "HandshakeMaximumDelay": "00:00:02",
            "HandshakeTimeout": "00:00:10",
            "KeepAliveInterval": "00:00:20",
            "LivenessTimeout": "00:01:05"
          },
          "Logging": {
            "LogLevel": {
              "Default": "Information",
              "Microsoft.Hosting.Lifetime": "Information"
            }
          }
        }
        """;
        File.WriteAllText(
            Path.Combine(ServiceDirectory, "appsettings.json"),
            json,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static bool ServiceExists() =>
        RunTool("sc.exe", ["query", ServiceName]).ExitCode == 0;

    private static bool StartServiceAndVerify()
    {
        var startResult = RunTool("sc.exe", ["start", ServiceName]);
        if (startResult.ExitCode != 0 && !IsServiceProcessRunning())
        {
            return false;
        }

        var timeout = Stopwatch.StartNew();
        while (timeout.Elapsed < TimeSpan.FromSeconds(15))
        {
            if (IsServiceProcessRunning())
            {
                Thread.Sleep(TimeSpan.FromSeconds(1));
                return IsServiceProcessRunning();
            }

            Thread.Sleep(TimeSpan.FromMilliseconds(250));
        }

        return false;
    }

    private static bool IsServiceProcessRunning()
    {
        var processes = Process.GetProcessesByName("HaloVPN.WindowsService");
        try
        {
            return processes.Any(process => !process.HasExited);
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    private static ToolResult RunTool(string fileName, IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ??
            throw new InvalidOperationException($"Не удалось запустить {fileName}.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{fileName} не завершился за 30 секунд.");
        }

        Task.WaitAll(output, error);
        return new ToolResult(process.ExitCode, output.Result, error.Result);
    }

    private static void StartDesktop()
    {
        if (!File.Exists(InstalledDesktop))
        {
            throw new FileNotFoundException("Установленный HaloVPN Desktop не найден.", InstalledDesktop);
        }

        _ = Process.Start(new ProcessStartInfo(InstalledDesktop)
        {
            UseShellExecute = true,
        });
    }

    private static string? GetExistingDesktopLauncherHash()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var path = Path.Combine(desktop, "HaloVPN.exe");
        return File.Exists(path)
            ? HashFile(path)
            : null;
    }

    private static void TryCreateDesktopLauncher(string? previousHash)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        TryCreateLauncher(Path.Combine(desktop, "HaloVPN.exe"), previousHash);
    }

    private static void TryCreateStartMenuLauncher(string? previousHash)
    {
        var programs = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
        TryCreateLauncher(Path.Combine(programs, "HaloVPN.exe"), previousHash);
    }

    private static void TryCreateLauncher(string destination, string? previousHash)
    {
        try
        {
            if (File.Exists(destination))
            {
                if (string.IsNullOrWhiteSpace(previousHash))
                {
                    return;
                }

                var actualHash = HashFile(destination);
                if (!actualHash.Equals(previousHash, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                File.Delete(destination);
            }

            _ = CreateHardLink(destination, InstalledLauncher, 0);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A launcher is a convenience only; installation and guard state do not depend on it.
        }
    }

    private static void WriteReleaseMarker()
    {
        File.WriteAllText(
            ReleaseMarker,
            GetCurrentPayloadHash() + Environment.NewLine,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static string GetCurrentPayloadHash()
    {
        var executable = Environment.ProcessPath ??
            throw new InvalidOperationException("Путь к HaloVPN.exe недоступен.");
        using var source = File.Open(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (source.Length < PayloadFooterSize)
        {
            throw new InvalidDataException("HaloVPN.exe не содержит payload.");
        }

        source.Position = source.Length - PayloadFooterSize;
        Span<byte> footer = stackalloc byte[PayloadFooterSize];
        source.ReadExactly(footer);
        if (!footer[..16].SequenceEqual(Encoding.ASCII.GetBytes(PayloadMagic)))
        {
            throw new InvalidDataException("HaloVPN.exe содержит неверный footer.");
        }

        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(footer.Slice(16, 8));
        if (payloadLength <= 0 || payloadLength > MaximumPayloadBytes ||
            payloadLength > source.Length - PayloadFooterSize)
        {
            throw new InvalidDataException("Размер payload недопустим.");
        }

        return Convert.ToHexString(footer[24..]);
    }

    private static string HashFile(string path)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void SafeDeleteInstallRoot()
    {
        var expected = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "HaloVPN"));
        var actual = Path.GetFullPath(InstallRoot);
        if (actual.Equals(expected, StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists(actual))
        {
            Directory.Delete(actual, recursive: true);
        }
    }

    private static string? GetArgument(IReadOnlyList<string> args, string name)
    {
        for (var index = 0; index < args.Count - 1; index++)
        {
            if (args[index].Equals(name, StringComparison.Ordinal))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private static string SafeError(Exception exception) => exception switch
    {
        PlatformNotSupportedException => exception.Message,
        InvalidOperationException => exception.Message,
        InvalidDataException => exception.Message,
        UnauthorizedAccessException => "Windows запретила доступ к каталогу установки.",
        IOException => "Ошибка чтения или записи файлов установки.",
        _ => exception.GetType().Name,
    };

    [LibraryImport("user32.dll", EntryPoint = "MessageBoxW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int MessageBox(nint window, string text, string caption, uint type);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string newFileName, string existingFileName, nint securityAttributes);

    private sealed record ToolResult(int ExitCode, string StandardOutput, string StandardError);
}
