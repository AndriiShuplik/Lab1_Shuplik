using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class SessionRevocationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task SecurityStampChange_InvalidatesIssuedSession_NewLoginWorks()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Configure<SecurityStampValidatorOptions>(options =>
                    options.ValidationInterval = TimeSpan.Zero)));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var userName = "rev" + Guid.NewGuid().ToString("N")[..8];
        using var register = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = userName + "@example.test",
            displayName = "Session Revocation",
            password = StudyPassword
        });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        try
        {
            using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password = StudyPassword });
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

            using var before = await client.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);

            using (var scope = host.Services.CreateScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = await users.FindByNameAsync(userName)
                    ?? throw new InvalidOperationException("Test user not found.");
                var update = await users.UpdateSecurityStampAsync(user);
                Assert.True(update.Succeeded);
            }

            using var after = await client.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);

            using var relogin = await client.PostAsJsonAsync("/api/auth/login", new { userName, password = StudyPassword });
            Assert.Equal(HttpStatusCode.NoContent, relogin.StatusCode);
            using var again = await client.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }
        finally
        {
            using var scope = host.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByNameAsync(userName);
            if (user is not null)
            {
                await users.DeleteAsync(user);
            }
        }
    }
}