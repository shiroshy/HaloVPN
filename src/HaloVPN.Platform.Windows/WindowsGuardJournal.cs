using System.Text.Json;

namespace HaloVPN.Platform.Windows;

public sealed class WindowsGuardJournal(string path)
{
    private const int MaximumJournalBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task SaveAsync(WindowsGuardDescriptor descriptor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        descriptor.Validate();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(descriptor, JsonOptions);
        if (bytes.Length > MaximumJournalBytes)
        {
            throw new InvalidDataException("Persistent network guard journal is too large.");
        }

        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("Network journal path has no parent."));
        var temporaryPath = fullPath + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public async Task<WindowsGuardDescriptor?> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumJournalBytes)
        {
            throw new InvalidDataException("Persistent network guard journal has an invalid size.");
        }

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var descriptor = JsonSerializer.Deserialize<WindowsGuardDescriptor>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Persistent network guard journal is invalid.");
        descriptor.Validate();
        return descriptor;
    }

    public void Delete()
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
