using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HaloVPN.Contracts;

namespace HaloVPN.Desktop;

internal sealed class ControlPlaneClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _client;
    private readonly object _refreshSync = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Task<AuthTokensResponse>? _refreshFlight;
    private string? _accessToken;

    internal ControlPlaneClient(Uri baseAddress, string? expectedSpkiPin, IReadOnlyList<IPAddress> bootstrapAddresses)
    {
        if (baseAddress.Scheme != Uri.UriSchemeHttps &&
            !(baseAddress.IsLoopback && Environment.GetEnvironmentVariable("HALOVPN_ALLOW_HTTP_DEVELOPMENT") == "1"))
        {
            throw new InvalidOperationException("ControlPlane must use HTTPS (HTTP loopback requires HALOVPN_ALLOW_HTTP_DEVELOPMENT=1).");
        }

        if (bootstrapAddresses.Count is < 1 or > 16 || bootstrapAddresses.Any(value => value.AddressFamily != AddressFamily.InterNetwork))
        {
            throw new InvalidOperationException("ControlPlane must resolve to one or more bounded IPv4 bootstrap addresses.");
        }

        var endpoints = bootstrapAddresses.Distinct().ToArray();
        var nextEndpoint = -1;
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (context, cancellationToken) =>
            {
                Exception? lastError = null;
                for (var attempt = 0; attempt < endpoints.Length; attempt++)
                {
                    var selected = endpoints[(uint)Interlocked.Increment(ref nextEndpoint) % (uint)endpoints.Length];
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(selected, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception exception) when (exception is SocketException or IOException)
                    {
                        socket.Dispose();
                        lastError = exception;
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw new HttpRequestException("No configured ControlPlane bootstrap endpoint was reachable.", lastError);
            },
        };
        if (!string.IsNullOrWhiteSpace(expectedSpkiPin))
        {
            var expected = Convert.FromBase64String(expectedSpkiPin);
            if (expected.Length != 32)
            {
                throw new InvalidOperationException("The configured SPKI pin must be a Base64 SHA-256 value.");
            }

            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                ValidatePinnedCertificate(certificate, errors, expected);
        }

        _client = new HttpClient(handler) { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(30) };
    }

    internal async Task<AuthTokensResponse> LoginAsync(string username, string password, CancellationToken cancellationToken)
    {
        var response = await _client.PostAsJsonAsync("api/auth/login", new LoginRequest(username, password), JsonOptions, cancellationToken).ConfigureAwait(false);
        var tokens = await ReadSuccessAsync<AuthTokensResponse>(response, cancellationToken).ConfigureAwait(false);
        _accessToken = tokens.AccessToken;
        return tokens;
    }

    internal async Task<DeviceRegistrationResponse> RegisterDeviceAsync(string publicKey, CancellationToken cancellationToken)
    {
        using var request = Authorized(HttpMethod.Post, "api/devices/register");
        request.Content = JsonContent.Create(new RegisterDeviceRequest(Environment.MachineName, publicKey), options: JsonOptions);
        var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var registration = await ReadSuccessAsync<DeviceRegistrationResponse>(response, cancellationToken).ConfigureAwait(false);
        _accessToken = registration.Tokens.AccessToken;
        return registration;
    }

    internal async Task<AuthTokensResponse> RefreshAsync(string refreshToken, CancellationToken cancellationToken)
    {
        Task<AuthTokensResponse> flight;
        lock (_refreshSync)
        {
            flight = _refreshFlight ??= RefreshCoreAsync(refreshToken, _lifetime.Token);
        }

        try
        {
            return await flight.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (flight.IsCompleted)
            {
                lock (_refreshSync)
                {
                    if (ReferenceEquals(_refreshFlight, flight))
                    {
                        _refreshFlight = null;
                    }
                }
            }
        }
    }

    internal async Task LogoutAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var response = await _client.PostAsJsonAsync("api/auth/logout", new LogoutRequest(refreshToken), JsonOptions, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.NoContent)
        {
            await ThrowApiErrorAsync(response, cancellationToken).ConfigureAwait(false);
        }

        _accessToken = null;
    }

    public void Dispose()
    {
        _lifetime.Cancel();
        _accessToken = null;
        _client.Dispose();
        _lifetime.Dispose();
    }

    private async Task<AuthTokensResponse> RefreshCoreAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var response = await _client.PostAsJsonAsync("api/auth/refresh", new RefreshRequest(refreshToken), JsonOptions, cancellationToken).ConfigureAwait(false);
        var tokens = await ReadSuccessAsync<AuthTokensResponse>(response, cancellationToken).ConfigureAwait(false);
        _accessToken = tokens.AccessToken;
        return tokens;
    }

    private HttpRequestMessage Authorized(HttpMethod method, string path)
    {
        if (string.IsNullOrEmpty(_accessToken))
        {
            throw new InvalidOperationException("No access token is available.");
        }

        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
        return request;
    }

    private static bool ValidatePinnedCertificate(System.Security.Cryptography.X509Certificates.X509Certificate? certificate, System.Net.Security.SslPolicyErrors errors, byte[] expected)
    {
        if (certificate is null)
        {
            return false;
        }

        var certificate2 = certificate as X509Certificate2;
        var ownsCertificate = certificate2 is null;
        certificate2 ??= new X509Certificate2(certificate);
        byte[] exported;
        try
        {
            exported = certificate2.PublicKey.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException)
        {
            if (ownsCertificate)
            {
                certificate2.Dispose();
            }

            return false;
        }

        try
        {
            var actual = SHA256.HashData(exported);
            try
            {
                const System.Net.Security.SslPolicyErrors disallowed =
                    System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch |
                    System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable;
                return CryptographicOperations.FixedTimeEquals(actual, expected) && (errors & disallowed) == 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exported);
            if (ownsCertificate)
            {
                certificate2.Dispose();
            }
        }
    }

    private static async Task<T> ReadSuccessAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                await ThrowApiErrorAsync(response, cancellationToken).ConfigureAwait(false);
            }

            return await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("ControlPlane returned an empty response.");
        }
    }

    private static async Task ThrowApiErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var error = await response.Content.ReadFromJsonAsync<ApiErrorResponse>(JsonOptions, cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException(error?.Message ?? $"ControlPlane request failed ({(int)response.StatusCode}).");
    }
}
