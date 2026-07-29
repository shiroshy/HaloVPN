namespace HaloVPN.Platform.Windows;

public sealed class NetworkCommandFailedException(
    NetworkCommand command,
    NetworkCommandContext context,
    int exitCode,
    string standardOutput,
    string standardError)
    : InvalidOperationException($"Network mutation {context.MutationKind} failed with exit code {exitCode}.")
{
    public NetworkCommand Command { get; } = command;
    public NetworkCommandContext Context { get; } = context;
    public int ExitCode { get; } = exitCode;
    public string StandardOutput { get; } = standardOutput;
    public string StandardError { get; } = standardError;
}

public static class InterfaceAppearanceWaiter
{
    public static async Task WaitAsync(
        Func<bool> isAvailable,
        TimeSpan timeout,
        TimeSpan pollingInterval,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(isAvailable);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30) ||
            pollingInterval <= TimeSpan.Zero || pollingInterval > timeout)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var deadline = timeProvider.GetUtcNow() + timeout;
        while (timeProvider.GetUtcNow() < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (isAvailable())
            {
                return;
            }

            await Task.Delay(pollingInterval, timeProvider, cancellationToken).ConfigureAwait(false);
        }

        if (!isAvailable())
        {
            throw new TimeoutException("Wintun interface did not appear within the configured timeout.");
        }
    }
}
