using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using HaloVPN.Protocol.Abstractions;
using HaloVPN.Protocol.Interop;
using HaloVPN.Transport;

namespace HaloVPN.ServerLab;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = ServerOptions.Parse(args);
            return await RunAsync(options, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or SocketException or NativeProtocolException or NativeProtocolUnavailableException or OperationCanceledException)
        {
            Console.Error.WriteLine($"ServerLab failed: {exception.Message}");
            return 2;
        }
    }

    private static async Task<int> RunAsync(ServerOptions options, CancellationToken cancellationToken)
    {
        var privateKey = KeyMaterial.ReadPrivateKeyFile(options.PrivateKeyPath);
        var clientPublicKey = KeyMaterial.ParsePublicKey(options.ClientPublicKey);
        try
        {
            await using var carrier = new UdpCarrier(new IPEndPoint(options.ListenAddress, options.Port));
            if (options.Verbose)
            {
                Console.WriteLine($"Listening endpoint={carrier.LocalEndPoint} phase=waiting");
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.HandshakeTimeout);
            await using var receiver = carrier.ReceiveAsync(timeout.Token).GetAsyncEnumerator();
            var limiter = new PendingHandshakeLimiter(new UdpSessionOptions
            {
                HandshakeTimeout = options.HandshakeTimeout,
                IdleTimeout = options.IdleTimeout,
            });

            NativeProtocolSession? session = null;
            EndPoint? authenticatedEndPoint = null;
            IDisposable? pendingLease = null;
            try
            {
                while (session is null)
                {
                    if (!await receiver.MoveNextAsync().ConfigureAwait(false))
                    {
                        throw new OperationCanceledException("Handshake receive ended before authentication.");
                    }

                    var datagram = receiver.Current;
                    if (!HaloEnvelope.TryParse(datagram.Payload.Span, out var envelope, out _) ||
                        envelope.Header.MessageType != ProtocolMessageType.HandshakeInit ||
                        !limiter.TryAcquire(datagram.ReceivedAt, out pendingLease))
                    {
                        continue;
                    }

                    var candidate = NativeProtocolSession.CreateServer(privateKey, clientPublicKey);
                    var response = new ArrayBufferWriter<byte>(512);
                    var result = candidate.ReadHandshake(datagram.Payload.Span, response);
                    if (!result.Success)
                    {
                        candidate.Dispose();
                        pendingLease?.Dispose();
                        pendingLease = null;
                        continue;
                    }

                    await carrier.SendAsync(response.WrittenMemory, datagram.RemoteEndPoint, timeout.Token).ConfigureAwait(false);
                    session = candidate;
                    authenticatedEndPoint = datagram.RemoteEndPoint;
                    pendingLease?.Dispose();
                    pendingLease = null;
                }

                timeout.CancelAfter(options.IdleTimeout);
                if (options.Verbose)
                {
                    Console.WriteLine($"connection={session.ConnectionId:X16} endpoint={authenticatedEndPoint} phase=established");
                }

                var pong = Encoding.ASCII.GetBytes("pong");
                while (session.State == ProtocolSessionState.Established)
                {
                    if (!await receiver.MoveNextAsync().ConfigureAwait(false))
                    {
                        break;
                    }

                    timeout.CancelAfter(options.IdleTimeout);
                    var datagram = receiver.Current;
                    if (!Equals(datagram.RemoteEndPoint, authenticatedEndPoint))
                    {
                        continue;
                    }

                    if (!HaloEnvelope.TryParse(datagram.Payload.Span, out var envelope, out _))
                    {
                        continue;
                    }

                    var plaintext = new ArrayBufferWriter<byte>(32);
                    var decrypted = session.Decrypt(datagram.Payload.Span, plaintext);
                    if (!decrypted.Success)
                    {
                        if (options.Verbose)
                        {
                            Console.WriteLine($"connection={session.ConnectionId:X16} reject={decrypted.ErrorCode}");
                        }

                        continue;
                    }

                    if (session.State == ProtocolSessionState.Closed)
                    {
                        break;
                    }

                    if (envelope.Header.MessageType != ProtocolMessageType.Data)
                    {
                        continue;
                    }

                    var response = new ArrayBufferWriter<byte>(128);
                    var encrypted = session.Encrypt(pong, response);
                    if (!encrypted.Success)
                    {
                        throw new InvalidOperationException($"Encrypt failed with {encrypted.ErrorCode}.");
                    }

                    await carrier.SendAsync(response.WrittenMemory, authenticatedEndPoint!, timeout.Token).ConfigureAwait(false);
                }

                if (options.Verbose)
                {
                    Console.WriteLine($"connection={session.ConnectionId:X16} phase=closed");
                }

                return 0;
            }
            finally
            {
                pendingLease?.Dispose();
                session?.Dispose();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private sealed record ServerOptions(
        IPAddress ListenAddress,
        int Port,
        string PrivateKeyPath,
        string ClientPublicKey,
        TimeSpan HandshakeTimeout,
        TimeSpan IdleTimeout,
        bool Verbose)
    {
        internal static ServerOptions Parse(string[] args)
        {
            var listen = IPAddress.Parse(Get(args, "--listen"));
            var port = int.Parse(Get(args, "--port"), System.Globalization.CultureInfo.InvariantCulture);
            if (port is < IPEndPoint.MinPort or > IPEndPoint.MaxPort)
            {
                throw new ArgumentOutOfRangeException(nameof(args), "UDP port is outside the valid range.");
            }

            return new ServerOptions(
                listen,
                port,
                Get(args, "--private-key"),
                Get(args, "--client-public"),
                TimeSpan.FromSeconds(10),
                TimeSpan.FromSeconds(30),
                args.Contains("--verbose", StringComparer.Ordinal));
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
