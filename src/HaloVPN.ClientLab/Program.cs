using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Transport;

namespace HaloVPN.ClientLab;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = ClientOptions.Parse(args);
            return await RunAsync(options, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or SocketException or NativeProtocolException or NativeProtocolUnavailableException or OperationCanceledException)
        {
            Console.Error.WriteLine($"ClientLab failed: {exception.Message}");
            return 2;
        }
    }

    private static async Task<int> RunAsync(ClientOptions options, CancellationToken cancellationToken)
    {
        var privateKey = KeyMaterial.ReadPrivateKeyFile(options.PrivateKeyPath);
        var serverPublicKey = KeyMaterial.ParsePublicKey(options.ServerPublicKey);
        try
        {
            using var session = NativeProtocolSession.CreateClient(privateKey, serverPublicKey);
            await using var carrier = new UdpCarrier(new IPEndPoint(
                options.ServerEndPoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any,
                0));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.Timeout);
            await using var receiver = carrier.ReceiveAsync(timeout.Token).GetAsyncEnumerator();

            var initial = new ArrayBufferWriter<byte>(512);
            EnsureSuccess(session.WriteHandshake(initial), "handshake init");
            await carrier.SendAsync(initial.WrittenMemory, options.ServerEndPoint, timeout.Token).ConfigureAwait(false);

            if (!await receiver.MoveNextAsync().ConfigureAwait(false))
            {
                throw new OperationCanceledException("No handshake response was received.");
            }
            if (!Equals(receiver.Current.RemoteEndPoint, options.ServerEndPoint))
            {
                throw new InvalidDataException("The handshake response arrived from an unexpected endpoint.");
            }

            EnsureSuccess(
                session.ReadHandshake(receiver.Current.Payload.Span, new ArrayBufferWriter<byte>()),
                "handshake response");
            Console.WriteLine($"connection={session.ConnectionId:X16} phase=established");

            var ping = Encoding.ASCII.GetBytes("ping");
            for (var index = 0; index < options.Count; index++)
            {
                timeout.CancelAfter(options.Timeout);
                var encrypted = new ArrayBufferWriter<byte>(128);
                EnsureSuccess(session.Encrypt(ping, encrypted), "encrypt ping");
                await carrier.SendAsync(encrypted.WrittenMemory, options.ServerEndPoint, timeout.Token).ConfigureAwait(false);

                if (!await receiver.MoveNextAsync().ConfigureAwait(false))
                {
                    throw new OperationCanceledException("No pong response was received.");
                }

                if (!Equals(receiver.Current.RemoteEndPoint, options.ServerEndPoint))
                {
                    throw new InvalidDataException("A datagram arrived from an unexpected endpoint.");
                }

                var plaintext = new ArrayBufferWriter<byte>(16);
                EnsureSuccess(session.Decrypt(receiver.Current.Payload.Span, plaintext), "decrypt pong");
                if (!plaintext.WrittenSpan.SequenceEqual("pong"u8))
                {
                    throw new InvalidDataException("The authenticated response was not the expected pong value.");
                }
            }

            var close = new ArrayBufferWriter<byte>(128);
            EnsureSuccess(session.WriteClose(0, 0, close), "close");
            await carrier.SendAsync(close.WrittenMemory, options.ServerEndPoint, timeout.Token).ConfigureAwait(false);
            Console.WriteLine($"connection={session.ConnectionId:X16} phase=closed messages={options.Count}");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private static void EnsureSuccess(ProtocolOperationResult result, string operation)
    {
        if (!result.Success)
        {
            throw new InvalidOperationException($"{operation} failed with safe code {result.ErrorCode}.");
        }
    }

    private sealed record ClientOptions(
        IPEndPoint ServerEndPoint,
        string PrivateKeyPath,
        string ServerPublicKey,
        int Count,
        TimeSpan Timeout)
    {
        internal static ClientOptions Parse(string[] args)
        {
            var server = ParseEndPoint(Get(args, "--server"));
            var count = int.Parse(Get(args, "--count"), System.Globalization.CultureInfo.InvariantCulture);
            var timeoutSeconds = double.Parse(Get(args, "--timeout"), System.Globalization.CultureInfo.InvariantCulture);
            if (count <= 0 || count > 1_000_000 || timeoutSeconds is <= 0 or > 300)
            {
                throw new ArgumentOutOfRangeException(nameof(args), "Count or timeout is outside the laboratory bounds.");
            }

            return new ClientOptions(
                server,
                Get(args, "--private-key"),
                Get(args, "--server-public"),
                count,
                TimeSpan.FromSeconds(timeoutSeconds));
        }

        private static IPEndPoint ParseEndPoint(string text)
        {
            var separator = text.LastIndexOf(':');
            if (separator <= 0 || !IPAddress.TryParse(text[..separator].Trim('[', ']'), out var address) ||
                !int.TryParse(text[(separator + 1)..], out var port) || port is < 1 or > 65_535)
            {
                throw new ArgumentException("--server must use the numeric address:port form.");
            }

            return new IPEndPoint(address, port);
        }

        private static string Get(string[] args, string name)
        {
            var index = Array.IndexOf(args, name);
            if (index < 0 || index == args.Length - 1)
            {
                throw new ArgumentException($"Missing required option {name}.");
            }

            return args[index + 1];
        }
    }
}
