using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;
using Microsoft.AspNetCore.Authorization;
using SecureLab.Api.Security;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();
builder.Services.AddScoped<AuthorizationAudit>();
builder.Services.AddSingleton<IAuthorizationHandler, IncidentAccessHandler>();

builder.AddLab03Identity();
builder.AddCsrfProtection();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                  .WithMethods("GET")
                  .WithHeaders("X-Lab-Cors-Probe")
                  .AllowCredentials();
        });
    });
}

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

const string contentSecurityPolicy =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    + "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
    + "form-action 'self'; frame-ancestors 'none'";
const string cspHeaderName = "Content-Security-Policy";

app.Use(async (context, next) =>
{
    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");

    context.Response.OnStarting(() =>
    {
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        if (!isDevelopmentApiReference)
        {
            context.Response.Headers[cspHeaderName] = contentSecurityPolicy;
        }

        return Task.CompletedTask;
    });

    await next(context);
});

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapIncidentEndpoints();
app.MapIncidentCommentEndpoints();
app.MapLab03Identity();
app.MapCsrfEndpoints();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
