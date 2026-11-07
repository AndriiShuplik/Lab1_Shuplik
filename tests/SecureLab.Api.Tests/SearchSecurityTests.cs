using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class SearchSecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static Guid SeedId(int number) =>
        Guid.Parse($"20000000-0000-0000-0000-{number:000000000000}");

    private async Task<List<SearchIncidentResponse>> SearchAsync(string query)
    {
        var items = await _client.GetFromJsonAsync<List<SearchIncidentResponse>>("/api/incidents/search" + query);
        return items ?? throw new InvalidOperationException("Порожня відповідь пошуку.");
    }

    private async Task AssertOrderAsync(string query, params int[] expected)
    {
        var items = await SearchAsync(query);
        Assert.Equal(expected.Select(SeedId), items.Select(item => item.Id));
    }

    [Fact]
    public async Task Search_ControlInput_ReturnsEmptySet_AndUsbReturnsOnlyUsbRecord()
    {
        var control = await SearchAsync("?q=" + Uri.EscapeDataString("zz-no-match' OR TRUE -- "));
        Assert.Empty(control);

        var usb = await SearchAsync("?q=USB");
        var only = Assert.Single(usb);
        Assert.Equal(SeedId(5), only.Id);
    }

    [Fact]
    public async Task Search_LegitimateApostrophe_ReturnsExpectedRecord()
    {
        var items = await SearchAsync("?q=" + Uri.EscapeDataString("O'Brien"));
        var only = Assert.Single(items);
        Assert.Equal(SeedId(4), only.Id);
        Assert.Equal("O'Brien classroom report", only.Title);
    }

    [Fact]
    public async Task Search_ApostropheInsideWord_ReturnsExpectedRecord()
    {
        var items = await SearchAsync("?q=" + Uri.EscapeDataString("комп'ютерного"));
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
        var items = await SearchAsync("?q=" + Uri.EscapeDataString(value));
        Assert.Empty(items);
    }

    [Fact]
    public async Task Search_UnknownSortBy_Returns400WithSortByKey()
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=price");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SELECT", json, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("sortBy", out _));
    }

    [Fact]
    public Task Search_DefaultOrder_NewestFirstThenById() =>
        AssertOrderAsync("", 4, 5, 3, 2, 1);

    [Fact]
    public Task Search_SortByCreatedAtUtc_NewestFirstThenById() =>
        AssertOrderAsync("?sortBy=createdAtUtc", 4, 5, 3, 2, 1);

    [Fact]
    public Task Search_SortBySeverity_FollowsContractRanks() =>
        AssertOrderAsync("?sortBy=severity", 2, 1, 3, 4, 5);

    [Fact]
    public Task Search_SortByStatus_FollowsContractRanks() =>
        AssertOrderAsync("?sortBy=status", 3, 4, 5, 1, 2);
}