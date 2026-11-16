using System.Net;

namespace SecureLab.Api.Tests;

public sealed class BrowserSecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string AllowedOrigin = "http://localhost:4173";
    private const string DisallowedOrigin = "http://localhost:4174";

    private static HttpRequestMessage Health(string origin, HttpMethod? method = null)
    {
        var request = new HttpRequestMessage(method ?? HttpMethod.Get, "/health");
        request.Headers.Add("Origin", origin);
        return request;
    }

    [Fact]
    public async Task Cors_AllowedOrigin_GetsExactAllowOriginAndCredentials()
    {
        using var client = factory.CreateClient();
        using var response = await client.SendAsync(Health(AllowedOrigin));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(AllowedOrigin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Credentials")));
    }

    [Fact]
    public async Task Cors_DisallowedOrigin_GetsNoCorsHeaders_ButRequestIsStillServed()
    {
        using var client = factory.CreateClient();
        using var response = await client.SendAsync(Health(DisallowedOrigin));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task Cors_Preflight_AllowedOrigin_ListsExactMethodAndHeader()
    {
        using var client = factory.CreateClient();
        using var request = Health(AllowedOrigin, HttpMethod.Options);
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "x-lab-cors-probe");
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(AllowedOrigin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("GET", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Methods")));
        Assert.Equal("X-Lab-Cors-Probe", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Headers")));
    }

    [Fact]
    public async Task Cors_Preflight_DisallowedOrigin_HasNoAccessControlHeaders()
    {
        using var client = factory.CreateClient();
        using var request = Health(DisallowedOrigin, HttpMethod.Options);
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "x-lab-cors-probe");
        using var response = await client.SendAsync(request);

        Assert.DoesNotContain(response.Headers, header => header.Key.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("http://localhost:4173.evil.test")]
    [InlineData("http://localhost:4173/")]
    [InlineData("https://localhost:4173")]
    public async Task Cors_OriginsThatAreNotExactlyTheAllowedOne_AreNotReflected(string origin)
    {
        using var client = factory.CreateClient();
        using var response = await client.SendAsync(Health(origin));

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/browser-lab.html")]
    [InlineData("/auth-lab.html")]
    [InlineData("/health")]
    public async Task Responses_CarryEnforcedCspAndBrowserHeaders(string path)
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync(path);

        var csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("Content-Security-Policy-Report-Only"));
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("script-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.DoesNotContain("unsafe-eval", csp);
        Assert.DoesNotContain("*", csp);
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
    }

    [Theory]
    [InlineData("/browser-lab.js")]
    [InlineData("/auth-lab.js")]
    [InlineData("/app.js")]
    [InlineData("/csrf.js")]
    public async Task ClientScripts_DoNotUseDangerousHtmlSinks(string path)
    {
        using var client = factory.CreateClient();
        var script = await client.GetStringAsync(path);

        Assert.DoesNotContain("innerHTML", script);
        Assert.DoesNotContain("outerHTML", script);
        Assert.DoesNotContain("insertAdjacentHTML", script);
        Assert.DoesNotContain("document.write", script);
        Assert.DoesNotContain("eval(", script);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/browser-lab.html")]
    [InlineData("/auth-lab.html")]
    public async Task ClientPages_HaveNoInlineScriptsStylesOrHandlers(string path)
    {
        using var client = factory.CreateClient();
        var html = await client.GetStringAsync(path);

        Assert.DoesNotContain("<style", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" style=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"\son[a-z]+\s*=", html);
        Assert.DoesNotMatch(@"<script(?![^>]*\ssrc=)", html);
    }
}
