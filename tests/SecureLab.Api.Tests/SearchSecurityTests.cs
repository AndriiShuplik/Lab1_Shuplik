using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class SearchSecurityTests(SessionsFixture sessions) : IClassFixture<SessionsFixture>
{
    private static Guid SeedId(int number) =>
        Guid.Parse($"20000000-0000-0000-0000-{number:000000000000}");

    private static async Task<List<SearchIncidentResponse>> SearchAsync(HttpClient client, string query)
    {
        var items = await client.GetFromJsonAsync<List<SearchIncidentResponse>>("/api/incidents/search" + query);
        return items ?? throw new InvalidOperationException("Порожня відповідь пошуку.");
    }

    private static async Task AssertOrderAsync(Task<HttpClient> user, string query, params int[] expected)
    {
        var items = await SearchAsync(await user, query);
        Assert.Equal(expected.Select(SeedId), items.Select(item => item.Id));
    }

    [Fact]
    public async Task Search_ControlInput_ReturnsEmptySet_AndUsbReturnsOnlyUsbRecord()
    {
        var alice = await sessions.Alice;
        var control = await SearchAsync(alice, "?q=" + Uri.EscapeDataString("zz-no-match' OR TRUE -- "));
        Assert.Empty(control);

        var usb = await SearchAsync(alice, "?q=USB");
        var only = Assert.Single(usb);
        Assert.Equal(SeedId(5), only.Id);
    }

    [Fact]
    public async Task Search_LegitimateApostrophe_ForOwner_ReturnsExpectedRecord()
    {
        var bob = await sessions.Bob;
        var items = await SearchAsync(bob, "?q=" + Uri.EscapeDataString("O'Brien"));
        var only = Assert.Single(items);
        Assert.Equal(SeedId(4), only.Id);
        Assert.Equal("O'Brien classroom report", only.Title);
    }

    [Fact]
    public async Task Search_ApostropheInsideWord_ReturnsExpectedRecord()
    {
        var alice = await sessions.Alice;
        var items = await SearchAsync(alice, "?q=" + Uri.EscapeDataString("комп'ютерного"));
        var only = Assert.Single(items);
        Assert.Equal(SeedId(3), only.Id);
    }

    [Theory]
    [InlineData("%")]
    [InlineData("_")]
    [InlineData("U%B")]
    [InlineData("U_B")]
    [InlineData("\\")]
    public async Task Search_WildcardCharacters_AreMatchedLiterally(string value)
    {
        var alice = await sessions.Alice;
        var items = await SearchAsync(alice, "?q=" + Uri.EscapeDataString(value));
        Assert.Empty(items);
    }

    [Fact]
    public async Task Search_UnknownSortBy_Returns400WithSortByKey()
    {
        var alice = await sessions.Alice;
        using var response = await alice.GetAsync("/api/incidents/search?sortBy=price");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SELECT", json, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("sortBy", out _));
    }

    [Fact]
    public Task Search_DefaultOrder_ForReporter_NewestFirstThenById() =>
        AssertOrderAsync(sessions.Alice, "", 5, 3, 1);

    [Fact]
    public Task Search_SortByCreatedAtUtc_ForReporter_NewestFirstThenById() =>
        AssertOrderAsync(sessions.Alice, "?sortBy=createdAtUtc", 5, 3, 1);

    [Fact]
    public Task Search_SortBySeverity_ForReporter_FollowsContractRanks() =>
        AssertOrderAsync(sessions.Alice, "?sortBy=severity", 1, 3, 5);

    [Fact]
    public Task Search_SortByStatus_ForReporter_FollowsContractRanks() =>
        AssertOrderAsync(sessions.Alice, "?sortBy=status", 3, 5, 1);

    [Fact]
    public Task Search_DefaultOrder_ForAnalyst_NewestFirstThenById() =>
        AssertOrderAsync(sessions.Morgan, "", 4, 5, 3, 2, 1);

    [Fact]
    public Task Search_SortBySeverity_ForAnalyst_FollowsContractRanks() =>
        AssertOrderAsync(sessions.Morgan, "?sortBy=severity", 2, 1, 3, 4, 5);

    [Fact]
    public Task Search_SortByStatus_ForAnalyst_FollowsContractRanks() =>
        AssertOrderAsync(sessions.Morgan, "?sortBy=status", 3, 4, 5, 1, 2);
}