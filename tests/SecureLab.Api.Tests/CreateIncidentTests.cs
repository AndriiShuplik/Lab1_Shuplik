using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecureLab.Api.Tests;

public sealed class CreateIncidentTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private Task<HttpResponseMessage> PostAsync(
        string title, string description, string severity, DateTimeOffset occurredAtUtc) =>
        _client.PostAsJsonAsync("/api/incidents", new { title, description, severity, occurredAtUtc });

    private static async Task<JsonElement> ErrorsAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT", json, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        return document.RootElement.GetProperty("errors").Clone();
    }

    [Fact]
    public async Task Post_ValidRequest_Returns201WithResponseContract()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        try
        {
            using var response = await PostAsync(
                $"  {title}  ", "Опис для перевірки коректного створення.", "medium",
                DateTimeOffset.UtcNow.AddMinutes(-10));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.NotNull(response.Headers.Location);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = document.RootElement;
            Assert.Equal(title, root.GetProperty("title").GetString());
            Assert.Equal("Medium", root.GetProperty("severity").GetString());
            Assert.Equal("New", root.GetProperty("status").GetString());
            Assert.False(root.TryGetProperty("ownerUserId", out _));
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_InvalidFields_Returns400WithAllFieldErrors()
    {
        using var response = await PostAsync(" ", "", "7", DateTimeOffset.UtcNow.AddDays(1));
        var errors = await ErrorsAsync(response);
        foreach (var key in new[] { "title", "description", "severity", "occurredAtUtc" })
            Assert.True(errors.TryGetProperty(key, out _));
    }

    [Fact]
    public async Task Post_NumericSeverity_Returns400()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        try
        {
            using var response = await PostAsync(
                title, "Опис для перевірки числового значення severity.", "7",
                DateTimeOffset.UtcNow.AddMinutes(-10));
            var errors = await ErrorsAsync(response);
            Assert.True(errors.TryGetProperty("severity", out _));
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_MissingOccurredAt_Returns400()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Опис для перевірки відсутнього часу події.",
                severity = "Low"
            });
            var errors = await ErrorsAsync(response);
            Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_DuplicateActiveTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var moment = DateTimeOffset.UtcNow.AddMinutes(-10);
        try
        {
            using var first = await PostAsync(title, "Опис для перевірки предметного конфлікту.", "Low", moment);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);
            using var second = await PostAsync(title, "Опис для перевірки предметного конфлікту.", "Low", moment);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json", second.Content.Headers.ContentType?.MediaType);
            using var document = JsonDocument.Parse(await second.Content.ReadAsStringAsync());
            Assert.False(document.RootElement.TryGetProperty("errors", out _));
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_DuplicateClosedTitle_Returns201()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var moment = DateTimeOffset.UtcNow.AddMinutes(-10);
        try
        {
            using var first = await PostAsync(title, "Опис для перевірки закритого дубліката.", "Low", moment);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);
            await TestCleanup.CloseByTitleAsync(factory, title);
            using var second = await PostAsync(title, "Опис для перевірки закритого дубліката.", "Low", moment);
            Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_HighSeverityDescriptionBoundary_39Rejected40Accepted()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var moment = DateTimeOffset.UtcNow.AddMinutes(-10);
        try
        {
            using var rejected = await PostAsync(title, new string('x', 39), "High", moment);
            var errors = await ErrorsAsync(rejected);
            Assert.True(errors.TryGetProperty("description", out _));
            using var accepted = await PostAsync(title, new string('x', 40), "High", moment);
            Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_OccurredAtOlderThanYear_Returns400_WithinYearReturns201()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        try
        {
            using var tooOld = await PostAsync(
                title, "Опис для перевірки нижньої межі часу події.", "Low",
                DateTimeOffset.UtcNow.AddDays(-400));
            var errors = await ErrorsAsync(tooOld);
            Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
            using var accepted = await PostAsync(
                title, "Опис для перевірки допустимого часу події.", "Low",
                DateTimeOffset.UtcNow.AddDays(-30));
            Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_OffsetDate_IsStoredAsUtc()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var moment = DateTimeOffset.UtcNow.AddDays(-1).ToOffset(TimeSpan.FromHours(3));
        try
        {
            using var response = await PostAsync(
                title, "Опис для перевірки нормалізації зміщення в UTC.", "Low", moment);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var stored = document.RootElement.GetProperty("occurredAtUtc").GetDateTimeOffset();
            Assert.Equal(TimeSpan.Zero, stored.Offset);
            Assert.Equal(moment.UtcDateTime, stored.UtcDateTime);
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }

    [Fact]
    public async Task Post_ExtraServerManagedFields_AreIgnored()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var sentId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Опис для перевірки server-managed полів.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                id = sentId,
                ownerUserId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                status = "Closed",
                createdAtUtc = DateTimeOffset.Parse("2000-01-01T00:00:00Z")
            });
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            using var created = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var createdId = created.RootElement.GetProperty("id").GetGuid();
            Assert.NotEqual(sentId, createdId);
            Assert.Equal("New", created.RootElement.GetProperty("status").GetString());

            var details = await _client.GetFromJsonAsync<JsonElement>($"/api/incidents/{createdId}");
            Assert.Equal("New", details.GetProperty("status").GetString());
            Assert.Equal("Аліса Коваль", details.GetProperty("ownerDisplayName").GetString());
            Assert.True(details.GetProperty("createdAtUtc").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddMinutes(-5));
        }
        finally
        {
            await TestCleanup.DeleteByTitleAsync(factory, title);
        }
    }
}