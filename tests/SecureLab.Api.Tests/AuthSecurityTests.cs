using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthSecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string SessionCookie = ".AspNetCore.Identity.Application=";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private HttpClient NewClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true
    });

    private static Dictionary<string, object?> IncidentBody(string title, Guid? forgedOwner = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["title"] = title,
            ["description"] = "Created by an automated authentication test.",
            ["severity"] = "Low",
            ["occurredAtUtc"] = DateTimeOffset.UtcNow.AddHours(-1)
        };
        if (forgedOwner is not null)
        {
            body["ownerUserId"] = forgedOwner;
        }
        return body;
    }

    private static string UniqueTitle(string prefix) => prefix + " " + Guid.NewGuid().ToString("N")[..8];

    private async Task<Guid> OwnerOfAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Id == incidentId)
            .Select(item => item.OwnerUserId)
            .SingleAsync();
    }

    private async Task RemoveIncidentAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Id == incidentId).ExecuteDeleteAsync();
    }

    private static async Task<string> ShapeAsync(HttpResponseMessage response)
    {
        var parts = new List<string>
        {
            ((int)response.StatusCode).ToString(),
            response.Content.Headers.ContentType?.MediaType ?? ""
        };
        var text = await response.Content.ReadAsStringAsync();
        if (text.Length > 0)
        {
            using var document = JsonDocument.Parse(text);
            foreach (var property in document.RootElement.EnumerateObject()
                         .Where(item => item.Name != "traceId")
                         .OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                parts.Add(property.Name + "=" + property.Value.GetRawText());
            }
        }
        return string.Join("|", parts);
    }

    [Fact]
    public async Task A01_AnonymousCreate_Returns401_NotRedirect()
    {
        using var client = NewClient();
        using var response = await client.PostAsJsonAsync("/api/incidents", IncidentBody(UniqueTitle("anon")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_Login_ThenMe_ReturnsCurrentUserOnly()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync("/api/me");
        var document = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, document.GetProperty("id").GetGuid());
        Assert.Equal("alice", document.GetProperty("userName").GetString());
        var names = document.EnumerateObject().Select(item => item.Name).OrderBy(name => name).ToArray();
        Assert.Equal(new[] { "displayName", "id", "userName" }, names);
    }

    [Fact]
    public async Task A03_ForeignDemoHeader_DoesNotChangeCurrentUser()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await client.SendAsync(request);
        var document = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, document.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task A04_CreateWithoutOwner_UsesPrincipal()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        await client.UseAntiforgeryTokenAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", IncidentBody(UniqueTitle("owner-implicit")));
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        try
        {
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal(DbSeeder.BobId, await OwnerOfAsync(id));
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }

    [Fact]
    public async Task A05_ForgedOwnerInBody_IsIgnored()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        await client.UseAntiforgeryTokenAsync();
        using var response = await client.PostAsJsonAsync(
            "/api/incidents", IncidentBody(UniqueTitle("owner-forged"), DbSeeder.AliceId));
        var created = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = created.GetProperty("id").GetGuid();

        try
        {
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal(DbSeeder.BobId, await OwnerOfAsync(id));
            Assert.NotEqual(DbSeeder.AliceId, await OwnerOfAsync(id));
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }

    [Fact]
    public async Task A06_Logout_EndsSession()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        await client.UseAntiforgeryTokenAsync();
        using var before = await client.GetAsync("/api/auth/session-check");
        using var logout = await client.PostAsync("/api/auth/logout", null);
        using var after = await client.GetAsync("/api/auth/session-check");

        Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_LookTheSame()
    {
        using var first = NewClient();
        using var second = NewClient();
        using var unknown = await first.PostAsJsonAsync(
            "/api/auth/login", new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = "Wrong-Password-1!" });
        using var wrong = await second.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = "Wrong-Password-1!" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(await ShapeAsync(unknown), await ShapeAsync(wrong));
    }

    [Fact]
    public async Task Register_Duplicates_Return409_AndResponseHasNoSecrets()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var userName = "dup" + suffix;
        var email = $"dup{suffix}@example.test";
        using var client = NewClient();

        using var first = await client.PostAsJsonAsync("/api/auth/register",
            new { userName, email, displayName = "Duplicate Check", password = StudyPassword });
        var body = await first.Content.ReadFromJsonAsync<JsonElement>();
        using var sameName = await client.PostAsJsonAsync("/api/auth/register",
            new { userName, email = $"other{suffix}@example.test", displayName = "Duplicate Check", password = StudyPassword });
        using var sameEmail = await client.PostAsJsonAsync("/api/auth/register",
            new { userName = "other" + suffix, email, displayName = "Duplicate Check", password = StudyPassword });

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var names = body.EnumerateObject().Select(item => item.Name).OrderBy(name => name).ToArray();
        Assert.Equal(new[] { "displayName", "id", "userName" }, names);
        Assert.Equal(HttpStatusCode.Conflict, sameName.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
    }

    [Fact]
    public async Task Login_OverHttps_SetsExpectedCookieAttributes()
    {
        using var client = NewClient();
        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = response.Headers.GetValues("Set-Cookie").Single(value => value.StartsWith(SessionCookie));
        var attributes = cookie.Split(';').Skip(1).Select(part => part.Trim().ToLowerInvariant()).ToArray();

        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("path=/", attributes);
    }
}