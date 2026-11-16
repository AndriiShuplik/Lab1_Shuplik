using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class SearchRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string SearchRoute = "/api/incidents/search?q=usb";
    private static readonly Guid AliceUsbIncident = Guid.Parse("20000000-0000-0000-0000-000000000005");

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private WebApplicationFactory<Program> TightHost() => factory.WithWebHostBuilder(builder =>
    {
        builder.UseSetting("SearchRateLimit:PermitLimit", "3");
        builder.UseSetting("SearchRateLimit:WindowSeconds", "2");
    });

    private static async Task ExhaustAsync(HttpClient client)
    {
        for (var i = 0; i < 3; i++)
        {
            using var allowed = await client.GetAsync(SearchRoute);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }
    }

    [Fact]
    public async Task Search_WithinQuota_KeepsExpectedBehavior_ThenFourthRequestReturns429()
    {
        using var host = TightHost();
        using var alice = await host.LoginAsync("alice", StudyPassword);

        for (var i = 0; i < 3; i++)
        {
            using var response = await alice.GetAsync(SearchRoute);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var items = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Contains(items.EnumerateArray(), item => item.GetProperty("id").GetGuid() == AliceUsbIncident);
        }

        using var limited = await alice.GetAsync(SearchRoute);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task Search_PartitionsAreSeparate_ExhaustedQuotaOfOneUserDoesNotBlockAnother()
    {
        using var host = TightHost();
        using var alice = await host.LoginAsync("alice", StudyPassword);
        using var bob = await host.LoginAsync("bob", StudyPassword);

        await ExhaustAsync(alice);
        using var aliceBlocked = await alice.GetAsync(SearchRoute);
        Assert.Equal(HttpStatusCode.TooManyRequests, aliceBlocked.StatusCode);

        using var bobResponse = await bob.GetAsync(SearchRoute);
        Assert.Equal(HttpStatusCode.OK, bobResponse.StatusCode);
        var items = await bobResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.DoesNotContain(items.EnumerateArray(), item => item.GetProperty("id").GetGuid() == AliceUsbIncident);
    }

    [Fact]
    public async Task Search_Quota_DoesNotLimitOtherRoutes_AndRecoversAfterWindow()
    {
        using var host = TightHost();
        using var alice = await host.LoginAsync("alice", StudyPassword);

        await ExhaustAsync(alice);
        using var blocked = await alice.GetAsync(SearchRoute);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);

        using var me = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        await Task.Delay(TimeSpan.FromMilliseconds(2500));

        using var recovered = await alice.GetAsync(SearchRoute);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }

    [Fact]
    public async Task Search_Anonymous_Returns401_BeforeAnyQuotaIsSpent()
    {
        using var host = TightHost();
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        for (var i = 0; i < 5; i++)
        {
            using var response = await client.GetAsync(SearchRoute);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }
}
