using BadBlocker.Service;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(opts => opts.ServiceName = "BadBlockerService");
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
