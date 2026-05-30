using BadBlocker.Guard;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(opts => opts.ServiceName = "BadBlockerGuard");
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
