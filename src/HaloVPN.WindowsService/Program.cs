using HaloVPN.WindowsService;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "HaloVPN");
builder.Services.Configure<WindowsVpnServiceOptions>(builder.Configuration.GetSection("HaloVPN"));
builder.Services.AddSingleton<ProcessNetworkCommandExecutor>();
builder.Services.AddSingleton<VpnServiceCoordinator>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
