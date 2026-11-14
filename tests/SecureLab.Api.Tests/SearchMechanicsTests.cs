using System.Net;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SessionsFixture sessions) : IClassFixture<SessionsFixture>
{
    [Fact]
    public async Task Search_ForSignedInUser_ReturnsJson()
    {
        var alice = await sessions.Alice;
        using var response = await alice.GetAsync("/api/incidents/search?q=навчальн");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}