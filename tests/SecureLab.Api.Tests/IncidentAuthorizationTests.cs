using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentAuthorizationTests(SessionsFixture sessions) : IClassFixture<SessionsFixture>
{
    private static readonly Guid BobSecondIncident = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid AliceUsbIncident = Guid.Parse("20000000-0000-0000-0000-000000000005");
    private static readonly Guid BobComment = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalComment = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private static string UniqueTitle(string prefix) => prefix + " " + Guid.NewGuid().ToString("N")[..8];

    private static object NewIncident(string title) => new
    {
        title,
        description = "Created by an automated authorization test.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
    };

    private static async Task<Guid> CreateAsync(HttpClient client, string prefix)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", NewIncident(UniqueTitle(prefix)));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("id").GetGuid();
    }

    private async Task RemoveAsync(Guid id)
    {
        using var scope = sessions.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }

    private async Task<(string Title, string Description, string Status, Guid Owner)> SnapshotAsync(Guid id)
    {
        using var scope = sessions.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var row = await db.Incidents.AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new { item.Title, item.Description, item.Status, item.OwnerUserId })
            .SingleAsync();
        return (row.Title, row.Description, row.Status.ToString(), row.OwnerUserId);
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

    [Theory]
    [InlineData("GET", "/api/incidents")]
    [InlineData("GET", "/api/incidents/search")]
    [InlineData("GET", "/api/incidents/severity-summary")]
    [InlineData("GET", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("PUT", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("DELETE", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000001/triage")]
    [InlineData("GET", "/api/incident-comments/30000000-0000-0000-0000-000000000001")]
    public async Task A01_AnonymousRequest_Returns401_NotRedirect(string method, string path)
    {
        using var client = sessions.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A02_Update_AsOwner_ChangesOnlyContent()
    {
        var bob = await sessions.Bob;
        var id = await CreateAsync(bob, "owner-update");
        try
        {
            var before = await SnapshotAsync(id);
            using var response = await bob.PutAsJsonAsync(
                $"/api/incidents/{id}",
                new { title = UniqueTitle("changed"), description = "Changed by the owner." });
            var after = await SnapshotAsync(id);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.NotEqual(before.Title, after.Title);
            Assert.Equal("Changed by the owner.", after.Description);
            Assert.Equal(before.Status, after.Status);
            Assert.Equal(before.Owner, after.Owner);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A03_Details_AsNonOwner_ReturnsNotFound_WithoutResourceData()
    {
        var alice = await sessions.Alice;
        var bob = await sessions.Bob;
        var id = await CreateAsync(bob, "foreign-read");
        try
        {
            using var response = await alice.GetAsync($"/api/incidents/{id}");
            var text = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.DoesNotContain(id.ToString(), text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A03R_Analyst_CanReadOthersIncident_ButCannotMutateIt()
    {
        var alice = await sessions.Alice;
        var morgan = await sessions.Morgan;
        var id = await CreateAsync(alice, "analyst-read");
        try
        {
            var before = await SnapshotAsync(id);
            using var read = await morgan.GetAsync($"/api/incidents/{id}");
            using var update = await morgan.PutAsJsonAsync(
                $"/api/incidents/{id}", new { title = "Changed by analyst", description = "Analyst must not edit." });
            using var delete = await morgan.DeleteAsync($"/api/incidents/{id}");
            var after = await SnapshotAsync(id);

            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
            Assert.Equal(before, after);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A04_UpdateAndDelete_AsNonOwner_ReturnNotFound_AndDoNotChangeResource()
    {
        var alice = await sessions.Alice;
        var bob = await sessions.Bob;
        var id = await CreateAsync(bob, "foreign-write");
        try
        {
            var before = await SnapshotAsync(id);
            using var update = await alice.PutAsJsonAsync(
                $"/api/incidents/{id}", new { title = "Changed by Alice", description = "Alice must not edit this." });
            using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
            var after = await SnapshotAsync(id);

            Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
            Assert.Equal(before, after);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A05_List_AsReporter_ReturnsOnlyOwnIncidents()
    {
        var alice = await sessions.Alice;
        var items = await alice.GetFromJsonAsync<List<JsonElement>>("/api/incidents");
        var ids = items!.Select(item => item.GetProperty("id").GetGuid()).ToArray();

        Assert.Contains(DbSeeder.AliceIncidentId, ids);
        Assert.Contains(AliceUsbIncident, ids);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, ids);
        Assert.DoesNotContain(BobSecondIncident, ids);
    }

    [Fact]
    public async Task A06_Triage_AsReporter_Returns403_AndStatusDoesNotChange()
    {
        var alice = await sessions.Alice;
        var id = await CreateAsync(alice, "reporter-triage");
        try
        {
            using var response = await alice.PostAsync($"/api/incidents/{id}/triage", null);
            var after = await SnapshotAsync(id);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("New", after.Status);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A07_Triage_AsAnalyst_MovesNewToTriaged_AndRejectsRepeat()
    {
        var bob = await sessions.Bob;
        var morgan = await sessions.Morgan;
        var id = await CreateAsync(bob, "analyst-triage");
        try
        {
            using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            var afterFirst = await SnapshotAsync(id);
            using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", null);

            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal("Triaged", afterFirst.Status);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A08a_Update_WithExtraProtectedFields_IgnoresThem()
    {
        var bob = await sessions.Bob;
        var id = await CreateAsync(bob, "overposting");
        try
        {
            using var response = await bob.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = UniqueTitle("overposted"),
                description = "Update with extra fields.",
                ownerUserId = DbSeeder.AliceId,
                role = "Administrator",
                status = "Closed"
            });
            var after = await SnapshotAsync(id);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(DbSeeder.BobId, after.Owner);
            Assert.Equal("New", after.Status);
        }
        finally
        {
            await RemoveAsync(id);
        }
    }

    [Fact]
    public async Task A10_ForeignAndUnknownId_ReturnIdenticalResponses()
    {
        var alice = await sessions.Alice;
        var bob = await sessions.Bob;
        var foreignId = await CreateAsync(bob, "same-response");
        var unknownId = Guid.NewGuid();
        var body = new { title = "Probe title", description = "Probe description." };
        try
        {
            foreach (var method in new[] { HttpMethod.Get, HttpMethod.Put, HttpMethod.Delete })
            {
                var foreign = await ShapeOfAsync(method, foreignId);
                var unknown = await ShapeOfAsync(method, unknownId);

                Assert.StartsWith("404|application/problem+json", foreign);
                Assert.Equal(unknown, foreign);
            }
        }
        finally
        {
            await RemoveAsync(foreignId);
        }

        async Task<string> ShapeOfAsync(HttpMethod method, Guid target)
        {
            using var request = new HttpRequestMessage(method, $"/api/incidents/{target}");
            if (method == HttpMethod.Put)
            {
                request.Content = JsonContent.Create(body);
            }
            using var response = await alice.SendAsync(request);
            return await ShapeAsync(response);
        }
    }

    [Fact]
    public async Task A11_Search_ReturnsOnlyRecordsVisibleToSubject()
    {
        var alice = await sessions.Alice;
        var bob = await sessions.Bob;
        var morgan = await sessions.Morgan;
        var query = "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");

        var forAlice = await alice.GetFromJsonAsync<JsonElement>(query);
        var forBob = await bob.GetFromJsonAsync<JsonElement>(query);
        var forMorgan = await morgan.GetFromJsonAsync<JsonElement>(query);

        Assert.Equal(0, forAlice.GetArrayLength());
        Assert.Equal(BobSecondIncident, Assert.Single(forBob.EnumerateArray()).GetProperty("id").GetGuid());
        Assert.Equal(BobSecondIncident, Assert.Single(forMorgan.EnumerateArray()).GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task A11_SeveritySummary_ReflectsOnlyRecordsVisibleToSubject()
    {
        var alice = await sessions.Alice;
        var morgan = await sessions.Morgan;

        var forAlice = await alice.GetFromJsonAsync<JsonElement>("/api/incidents/severity-summary?status=InProgress");
        var forMorgan = await morgan.GetFromJsonAsync<JsonElement>("/api/incidents/severity-summary?status=InProgress");

        Assert.Equal(0, forAlice.GetArrayLength());
        Assert.Contains(forMorgan.EnumerateArray(), item =>
            item.GetProperty("severity").GetString() == "High" && item.GetProperty("count").GetInt32() >= 1);
    }

    [Fact]
    public async Task A12_ForeignAndInternalComments_AreHiddenFromReporter_AndVisibleToAnalyst()
    {
        var alice = await sessions.Alice;
        var morgan = await sessions.Morgan;

        using var foreign = await alice.GetAsync($"/api/incident-comments/{BobComment}");
        using var internalOwn = await alice.GetAsync($"/api/incident-comments/{InternalComment}");
        var aliceDetails = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var aliceCommentIds = aliceDetails.GetProperty("comments").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid()).ToArray();

        using var analyst = await morgan.GetAsync($"/api/incident-comments/{InternalComment}");
        var analystComment = await analyst.Content.ReadFromJsonAsync<JsonElement>();
        var morganDetails = await morgan.GetFromJsonAsync<JsonElement>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var morganCommentIds = morganDetails.GetProperty("comments").EnumerateArray()
            .Select(item => item.GetProperty("id").GetGuid()).ToArray();

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, internalOwn.StatusCode);
        Assert.DoesNotContain(InternalComment, aliceCommentIds);
        Assert.Equal(HttpStatusCode.OK, analyst.StatusCode);
        Assert.True(analystComment.GetProperty("isInternal").GetBoolean());
        Assert.Contains(InternalComment, morganCommentIds);
    }
}