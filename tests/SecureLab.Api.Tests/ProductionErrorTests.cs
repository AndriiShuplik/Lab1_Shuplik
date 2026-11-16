using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SecureLab.Api.Tests;

public sealed class ProductionErrorTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string UnreachableConnection =
        "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
        + "Password=unreachable-study-value;Include Error Detail=false";

    [Fact]
    public async Task UnexpectedError_InProduction_IsSafe_HasTraceId_AndKeepsBrowserHeaders()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab", UnreachableConnection);
        });
        Assert.Equal("Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        using var client = production.CreateClient();
        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = "NotARealPassword1!" });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var raw = await response.Content.ReadAsStringAsync();
        using var body = JsonDocument.Parse(raw);
        Assert.Equal(500, body.RootElement.GetProperty("status").GetInt32());
        Assert.Matches("^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$",
            body.RootElement.GetProperty("traceId").GetString());
        Assert.DoesNotContain("Npgsql", raw);
        Assert.DoesNotContain("54399", raw);
        Assert.DoesNotContain("unreachable-study-value", raw);
        Assert.DoesNotContain(" at ", raw);

        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        var csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
    }
}
