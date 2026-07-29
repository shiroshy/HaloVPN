using System.Windows;
using System.Net.Http;
using System.Net;
using System.Net.Sockets;
using System.IO;
using HaloVPN.Contracts;
using HaloVPN.Platform.Windows;

namespace HaloVPN.Desktop;

public partial class MainWindow : Window
{
    private readonly ServiceClient _service = new();
    private readonly DpapiTokenStore _tokenStore = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "HaloVPN",
        "refresh-token.bin"));
    private ControlPlaneClient? _controlPlane;
    private VpnProfileResponse? _profile;
    private string? _refreshToken;
    private IReadOnlyList<string> _bootstrapIpv4Addresses = [];

    public MainWindow() => InitializeComponent();

    private async void Login_Click(object sender, RoutedEventArgs e)
    {
        await RunUiOperationAsync(async cancellationToken =>
        {
            if (!Uri.TryCreate(ControlPlaneUrlBox.Text.TrimEnd('/') + "/", UriKind.Absolute, out var baseAddress))
            {
                throw new InvalidOperationException("Enter a valid ControlPlane URL.");
            }

            var resolved = await Dns.GetHostAddressesAsync(baseAddress.Host, cancellationToken).ConfigureAwait(true);
            var bootstrap = resolved.Where(value => value.AddressFamily == AddressFamily.InterNetwork).Distinct().Take(16).ToArray();
            if (bootstrap.Length == 0)
            {
                throw new InvalidOperationException("ControlPlane hostname has no IPv4 bootstrap address.");
            }

            _bootstrapIpv4Addresses = bootstrap.Select(value => value.ToString()).ToArray();
            _controlPlane?.Dispose();
            _controlPlane = new ControlPlaneClient(baseAddress, Environment.GetEnvironmentVariable("HALOVPN_CONTROLPLANE_SPKI_PIN"), bootstrap);
            var tokens = await _controlPlane.LoginAsync(UsernameBox.Text, PasswordBox.Password, cancellationToken).ConfigureAwait(true);
            PasswordBox.Clear();
            var serviceResponse = await _service.SendAsync(IpcMessageType.GetPublicKey, null, cancellationToken).ConfigureAwait(true);
            var publicKey = serviceResponse.PublicKey ?? throw new InvalidDataException("HaloVPN Service did not return its device public key.");
            var registration = await _controlPlane.RegisterDeviceAsync(publicKey, cancellationToken).ConfigureAwait(true);
            _refreshToken = registration.Tokens.RefreshToken;
            await _tokenStore.SaveAsync(_refreshToken, cancellationToken).ConfigureAwait(true);
            _profile = registration.Profile;
            NodeText.Text = _profile.NodeName;
            AddressText.Text = $"Tunnel address: {_profile.AssignedClientIpv4}";
            StateText.Text = "Disconnected";
            DiagnosticText.Text = "Ready to connect.";
            LoginPanel.Visibility = Visibility.Collapsed;
            MainPanel.Visibility = Visibility.Visible;
        }).ConfigureAwait(true);
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        await RunUiOperationAsync(async cancellationToken =>
        {
            var profile = _profile ?? throw new InvalidOperationException("No VPN profile is loaded.");
            var response = await _service.SendAsync(IpcMessageType.Connect, profile, cancellationToken, _bootstrapIpv4Addresses).ConfigureAwait(true);
            StateText.Text = response.Status?.State ?? "Connected";
            DiagnosticText.Text = response.Status?.DiagnosticCode ?? "Noise tunnel established.";
        }).ConfigureAwait(true);
    }

    private async void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        await RunUiOperationAsync(async cancellationToken =>
        {
            var response = await _service.SendAsync(IpcMessageType.Disconnect, null, cancellationToken).ConfigureAwait(true);
            StateText.Text = response.Status?.State ?? "Disconnected";
            DiagnosticText.Text = response.Status?.DiagnosticCode ?? "Tunnel stopped and owned network changes removed.";
        }).ConfigureAwait(true);
    }

    private async void Logout_Click(object sender, RoutedEventArgs e)
    {
        await RunUiOperationAsync(async cancellationToken =>
        {
            await _service.SendAsync(IpcMessageType.Disconnect, null, cancellationToken).ConfigureAwait(true);
            if (_controlPlane is not null && _refreshToken is not null)
            {
                await _controlPlane.LogoutAsync(_refreshToken, cancellationToken).ConfigureAwait(true);
            }

            _tokenStore.Delete();
            _refreshToken = null;
            _profile = null;
            _bootstrapIpv4Addresses = [];
            _controlPlane?.Dispose();
            _controlPlane = null;
            MainPanel.Visibility = Visibility.Collapsed;
            LoginPanel.Visibility = Visibility.Visible;
            MessageText.Text = "Logged out.";
        }).ConfigureAwait(true);
    }

    private async Task RunUiOperationAsync(Func<CancellationToken, Task> operation)
    {
        SetButtons(false);
        MessageText.Text = string.Empty;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            await operation(timeout.Token).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidOperationException or OperationCanceledException)
        {
            MessageText.Text = exception is OperationCanceledException ? "Operation timed out or was cancelled." : exception.Message;
        }
        finally
        {
            PasswordBox.Clear();
            SetButtons(true);
        }
    }

    private void SetButtons(bool enabled)
    {
        LoginButton.IsEnabled = enabled;
        ConnectButton.IsEnabled = enabled;
        DisconnectButton.IsEnabled = enabled;
    }
}
