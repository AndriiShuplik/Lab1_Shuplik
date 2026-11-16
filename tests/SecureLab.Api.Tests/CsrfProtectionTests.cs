using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class CsrfProtectionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string ProblemTitle = "Antiforgery token is missing or invalid.";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static string UniqueTitle(string prefix) => prefix + " " + Guid.NewGuid().ToString("N")[..8];

    private async Task<Guid> SeedAsync(Guid ownerId, string title, string description)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = ownerId,
            Title = title,
            Description = description,
            Severity = IncidentSeverity.Low,
            Status = IncidentStatus.New,
            OccurredAtUtc = now.AddHours(-1),
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
        db.Incidents.Add(incident);
        await db.SaveChangesAsync();
        return incident.Id;
    }

    private async Task<(string Title, string Description, IncidentStatus Status)?> SnapshotAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var row = await db.Incidents.AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new { item.Title, item.Description, item.Status })
            .SingleOrDefaultAsync();
        return row is null ? null : (row.Title, row.Description, row.Status);
    }

    private async Task<int> CountByTitleAsync(string title)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.CountAsync(item => item.Title == title);
    }

    private async Task RemoveAsync(params Guid[] ids)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => ids.Contains(item.Id)).ExecuteDeleteAsync();
    }

    private static async Task AssertAntiforgeryRejectionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ProblemTitle, body.GetProperty("title").GetString());
        Assert.True(body.TryGetProperty("traceId", out _));
        Assert.False(body.TryGetProperty("errors", out _));
    }

    private static HttpRequestMessage Put(Guid id, string title, string description, string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/api/incidents/{id}")
        {
            Content = JsonContent.Create(new { title, description })
        };
        if (token is not null)
        {
            request.Headers.Add(CsrfContract.HeaderName, token);
        }

        return request;
    }

    private sealed record TokenResponse(string Token);

    private static async Task<string> TokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync(CsrfContract.TokenRoute);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.False(string.IsNullOrWhiteSpace(body?.Token));
        return body!.Token;
    }

    [Fact]
    public async Task RegCsrf01_PutWithoutOrWithInvalidToken_IsRejected_StateIsUnchanged_ValidPairSucceeds()
    {
        var title = UniqueTitle("csrf-put");
        const string originalDescription = "Original description for the CSRF regression.";
        var id = await SeedAsync(DbSeeder.AliceId, title, originalDescription);
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            var before = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
            Assert.Equal(title, before.GetProperty("title").GetString());

            using (var missing = await alice.SendAsync(Put(id, "changed without token", "changed")))
            {
                await AssertAntiforgeryRejectionAsync(missing);
            }

            var afterMissing = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
            Assert.Equal(title, afterMissing.GetProperty("title").GetString());
            Assert.Equal(originalDescription, afterMissing.GetProperty("description").GetString());

            using (var invalid = await alice.SendAsync(Put(id, "changed with invalid token", "changed", "not-a-real-token")))
            {
                await AssertAntiforgeryRejectionAsync(invalid);
            }

            var snapshot = await SnapshotAsync(id);
            Assert.Equal(title, snapshot!.Value.Title);
            Assert.Equal(originalDescription, snapshot.Value.Description);

            var token = await TokenAsync(alice);
            using (var accepted = await alice.SendAsync(Put(id, "changed with valid pair", "changed description", token)))
            {
                Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            }

            var afterAccepted = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
            Assert.Equal("changed with valid pair", afterAccepted.GetProperty("title").GetString());
            Assert.Equal("changed description", afterAccepted.GetProperty("description").GetString());
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task Perimeter_EveryCookieMutation_RejectsMissingToken_AndKeepsState()
    {
        var createTitle = UniqueTitle("csrf-create");
        var editedId = await SeedAsync(DbSeeder.AliceId, UniqueTitle("csrf-edit"), "Description for the perimeter test.");
        var deletedId = await SeedAsync(DbSeeder.AliceId, UniqueTitle("csrf-delete"), "Description for the perimeter test.");
        var triagedId = await SeedAsync(DbSeeder.AliceId, UniqueTitle("csrf-triage"), "Description for the perimeter test.");
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            using var morgan = await factory.LoginAsync("morgan", StudyPassword);
            var editedBefore = await SnapshotAsync(editedId);

            using (var create = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title = createTitle,
                description = "Created by the perimeter test.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
            }))
            {
                await AssertAntiforgeryRejectionAsync(create);
            }

            Assert.Equal(0, await CountByTitleAsync(createTitle));

            using (var update = await alice.SendAsync(Put(editedId, "changed", "changed")))
            {
                await AssertAntiforgeryRejectionAsync(update);
            }

            Assert.Equal(editedBefore, await SnapshotAsync(editedId));

            using (var delete = await alice.DeleteAsync($"/api/incidents/{deletedId}"))
            {
                await AssertAntiforgeryRejectionAsync(delete);
            }

            Assert.NotNull(await SnapshotAsync(deletedId));

            using (var triage = await morgan.PostAsync($"/api/incidents/{triagedId}/triage", null))
            {
                await AssertAntiforgeryRejectionAsync(triage);
            }

            Assert.Equal(IncidentStatus.New, (await SnapshotAsync(triagedId))!.Value.Status);

            using (var logout = await alice.PostAsync("/api/auth/logout", null))
            {
                await AssertAntiforgeryRejectionAsync(logout);
            }

            using var stillSignedIn = await alice.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.NoContent, stillSignedIn.StatusCode);
        }
        finally
        {
            await RemoveAsync(editedId, deletedId, triagedId);
            await TestCleanup.DeleteByTitleAsync(factory, createTitle);
        }
    }

    [Fact]
    public async Task Token_IssuedForAnotherUser_IsRejected_AndStateIsUnchanged()
    {
        var title = UniqueTitle("csrf-other-user");
        var id = await SeedAsync(DbSeeder.BobId, title, "Description for the cross-user token test.");
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            using var bob = await factory.LoginAsync("bob", StudyPassword);
            var aliceToken = await TokenAsync(alice);
            _ = await TokenAsync(bob);

            using var response = await bob.SendAsync(Put(id, "changed by borrowed token", "changed", aliceToken));

            await AssertAntiforgeryRejectionAsync(response);
            Assert.Equal(title, (await SnapshotAsync(id))!.Value.Title);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task TokenRoute_WithoutSession_Returns401()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var response = await client.GetAsync(CsrfContract.TokenRoute);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidPair_AllowsCreate_AndLogout()
    {
        var title = UniqueTitle("csrf-create-ok");
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            await alice.UseAntiforgeryTokenAsync();

            using var created = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Created with a valid token pair.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
            });
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            Assert.Equal(1, await CountByTitleAsync(title));

            using var logout = await alice.PostAsync("/api/auth/logout", null);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
            using var after = await alice.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }
}
