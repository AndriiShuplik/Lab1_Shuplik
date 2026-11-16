using System.Net.Http.Json;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public static class AntiforgeryTestExtensions
{
    private sealed record TokenResponse(string Token);

    public static async Task UseAntiforgeryTokenAsync(this HttpClient client)
    {
        client.DefaultRequestHeaders.Remove(CsrfContract.HeaderName);
        using var response = await client.GetAsync(CsrfContract.TokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
        {
            throw new InvalidOperationException("Missing request token.");
        }

        client.DefaultRequestHeaders.Add(CsrfContract.HeaderName, body.Token);
    }

    public static async Task<HttpClient> WithAntiforgeryTokenAsync(this Task<HttpClient> clientTask)
    {
        var client = await clientTask;
        await client.UseAntiforgeryTokenAsync();
        return client;
    }
}
