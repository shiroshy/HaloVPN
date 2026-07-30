using System.Windows;
using System.Windows.Media;
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
    private string _serviceState = "Disconnected";
    private bool _isBusy;

    public MainWindow()
    {
        InitializeComponent();
        UpdateConnectionVisual(_serviceState);
    }

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
            var spkiPin = string.IsNullOrWhiteSpace(SpkiPinBox.Text)
                ? Environment.GetEnvironmentVariable("HALOVPN_CONTROLPLANE_SPKI_PIN")
                : SpkiPinBox.Text.Trim();
            _controlPlane = new ControlPlaneClient(baseAddress, spkiPin, bootstrap);
            var tokens = await _controlPlane.LoginAsync(UsernameBox.Text, PasswordBox.Password, cancellationToken).ConfigureAwait(true);
            PasswordBox.Clear();
            var serviceResponse = await _service.SendAsync(IpcMessageType.GetPublicKey, null, cancellationToken).ConfigureAwait(true);
            var publicKey = serviceResponse.PublicKey ?? throw new InvalidDataException("HaloVPN Service did not return its device public key.");
            var registration = await _controlPlane.RegisterDeviceAsync(publicKey, cancellationToken).ConfigureAwait(true);
            _refreshToken = registration.Tokens.RefreshToken;
            await _tokenStore.SaveAsync(_refreshToken, cancellationToken).ConfigureAwait(true);
            _profile = registration.Profile;
            NodeText.Text = _profile.NodeName;
            AddressText.Text = _profile.AssignedClientIpv4;
            DiagnosticText.Text = "Готово к защищённому подключению";
            UpdateConnectionVisual("Disconnected");
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
            UpdateConnectionVisual(response.Status?.State ?? "Connected");
            DiagnosticText.Text = response.Status?.DiagnosticCode ?? "Noise-туннель установлен";
        }).ConfigureAwait(true);
    }

    private async void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        await RunUiOperationAsync(async cancellationToken =>
        {
            var response = await _service.SendAsync(IpcMessageType.Disconnect, null, cancellationToken).ConfigureAwait(true);
            UpdateConnectionVisual(response.Status?.State ?? "Disconnected");
            DiagnosticText.Text = response.Status?.DiagnosticCode ?? "Защищённый туннель остановлен";
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
            UpdateConnectionVisual("Disconnected");
            ShowMessage("Вы вышли из аккаунта.", isError: false);
        }).ConfigureAwait(true);
    }

    private async Task RunUiOperationAsync(Func<CancellationToken, Task> operation)
    {
        SetButtons(false);
        ShowMessage(null, isError: false);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            await operation(timeout.Token).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidOperationException or OperationCanceledException)
        {
            ShowMessage(
                exception is OperationCanceledException ? "Операция завершилась по тайм-ауту." : exception.Message,
                isError: true);
        }
        finally
        {
            PasswordBox.Clear();
            SetButtons(true);
        }
    }

    private void SetButtons(bool enabled)
    {
        _isBusy = !enabled;
        LoginButton.IsEnabled = enabled;
        LogoutButton.IsEnabled = enabled;
        UpdateConnectionVisual(_serviceState);
    }

    private void UpdateConnectionVisual(string state)
    {
        _serviceState = state;
        var normalized = state.Trim();
        var connected = normalized.Equals("Connected", StringComparison.OrdinalIgnoreCase);
        var reconnecting = normalized.Contains("Reconnecting", StringComparison.OrdinalIgnoreCase);
        var protectedFault = normalized.Contains("Protected", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("Guarded", StringComparison.OrdinalIgnoreCase);

        if (connected)
        {
            StateText.Text = "Подключено";
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(90, 232, 184));
            HaloGlow.Stroke = new SolidColorBrush(Color.FromRgb(90, 232, 184));
            HaloShadow.Color = Color.FromRgb(90, 232, 184);
            ConnectActionText.Text = "ЗАЩИЩЕНО";
        }
        else if (reconnecting || protectedFault)
        {
            StateText.Text = reconnecting ? "Защищённое переподключение" : "Защита активна";
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(255, 190, 92));
            HaloGlow.Stroke = new SolidColorBrush(Color.FromRgb(255, 190, 92));
            HaloShadow.Color = Color.FromRgb(255, 190, 92);
            ConnectActionText.Text = "ЗАЩИЩЕНО";
        }
        else
        {
            StateText.Text = "Отключено";
            StatusDot.Fill = (Brush)FindResource("TextSecondaryBrush");
            HaloGlow.Stroke = (Brush)FindResource("AccentGradientBrush");
            HaloShadow.Color = Color.FromRgb(76, 201, 255);
            ConnectActionText.Text = "ПОДКЛЮЧИТЬ";
        }

        ConnectButton.IsEnabled = !_isBusy && !connected && !reconnecting && !protectedFault;
        DisconnectButton.IsEnabled = !_isBusy && (connected || reconnecting || protectedFault);
    }

    private void ShowMessage(string? message, bool isError)
    {
        MessageText.Text = message ?? string.Empty;
        MessageText.Foreground = isError
            ? (Brush)FindResource("DangerBrush")
            : (Brush)FindResource("TextSecondaryBrush");
        MessageBorder.Visibility = string.IsNullOrWhiteSpace(message)
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
