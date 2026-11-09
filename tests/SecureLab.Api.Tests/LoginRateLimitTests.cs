using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class LoginRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private WebApplicationFactory<Program> TightHost() => factory.WithWebHostBuilder(builder =>
    {
        builder.UseSetting("LoginRateLimit:PermitLimit", "3");
        builder.UseSetting("LoginRateLimit:WindowSeconds", "2");
    });

    private static HttpClient NewClient(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    private static Task<HttpResponseMessage> AttemptAsync(HttpClient client, string userName, string password) =>
        client.PostAsJsonAsync("/api/auth/login", new { userName, password });

    [Fact]
    public async Task FourthAttemptInWindow_Returns429_RegardlessOfUserName()
    {
        using var host = TightHost();
        using var client = NewClient(host);

        for (var i = 0; i < 3; i++)
        {
            using var rejected = await AttemptAsync(client, "alice", "Wrong-Password-1!");
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }

        using var other = await AttemptAsync(client, "nobody" + Guid.NewGuid().ToString("N")[..8], "Wrong-Password-1!");
        Assert.Equal(HttpStatusCode.TooManyRequests, other.StatusCode);
    }

    [Fact]
    public async Task AfterWindow_LoginWorksAgain()
    {
        using var host = TightHost();
        using var client = NewClient(host);

        for (var i = 0; i < 3; i++)
        {
            using var rejected = await AttemptAsync(client, "alice", "Wrong-Password-1!");
        }

        using var blocked = await AttemptAsync(client, "alice", StudyPassword);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);

        await Task.Delay(TimeSpan.FromMilliseconds(2500));

        using var recovered = await AttemptAsync(client, "alice", StudyPassword);
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }

    [Fact]
    public async Task SeparateHost_HasIndependentCounter()
    {
        using var first = TightHost();
        using var firstClient = NewClient(first);
        for (var i = 0; i < 4; i++)
        {
            using var burst = await AttemptAsync(firstClient, "alice", "Wrong-Password-1!");
        }

        using var second = TightHost();
        using var secondClient = NewClient(second);
        using var response = await AttemptAsync(secondClient, "alice", "Wrong-Password-1!");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}