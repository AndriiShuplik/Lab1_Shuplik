using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class TriageAuditTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private sealed class ListLoggerProvider(List<string> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new ListLogger(sink, categoryName);

        public void Dispose()
        {
        }

        private sealed class ListLogger(List<string> sink, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (sink)
                {
                    sink.Add($"{category}|{logLevel}|{formatter(state, exception)}");
                }
            }
        }
    }

    private async Task<Guid> SeedNewIncidentAsync(Guid owner, string title)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = owner,
            Title = title,
            Description = "Description for the triage audit test.",
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

    private async Task<IncidentStatus?> StatusAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => (IncidentStatus?)item.Status)
            .SingleOrDefaultAsync();
    }

    [Fact]
    public async Task Triage_AllowedForAnalyst_IsAudited_DeniedForReporter_IsAudited_AndStatusIsUnchanged()
    {
        var sink = new List<string>();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging => logging.AddProvider(new ListLoggerProvider(sink))));
        var allowedId = await SeedNewIncidentAsync(DbSeeder.AliceId, "audit-allowed " + Guid.NewGuid().ToString("N")[..8]);
        var deniedId = await SeedNewIncidentAsync(DbSeeder.AliceId, "audit-denied " + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            using var morgan = await host.LoginAsync("morgan", StudyPassword);
            await morgan.UseAntiforgeryTokenAsync();
            using var alice = await host.LoginAsync("alice", StudyPassword);
            await alice.UseAntiforgeryTokenAsync();

            using var denied = await alice.PostAsync($"/api/incidents/{deniedId}/triage", null);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Equal(IncidentStatus.New, await StatusAsync(deniedId));

            using var allowed = await morgan.PostAsync($"/api/incidents/{allowedId}/triage", null);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            Assert.Equal(IncidentStatus.Triaged, await StatusAsync(allowedId));

            string[] lines;
            lock (sink)
            {
                lines = sink.Where(line => line.Contains("authorization.", StringComparison.Ordinal)).ToArray();
            }

            var allowedLine = Assert.Single(lines, line => line.Contains("authorization.allowed", StringComparison.Ordinal));
            Assert.Contains($"subject={DbSeeder.MorganId}", allowedLine);
            Assert.Contains("action=incident.triage", allowedLine);
            Assert.Contains($"resource={allowedId}", allowedLine);
            Assert.Contains("result=allowed", allowedLine);
            Assert.Matches(@"at=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", allowedLine);
            Assert.Contains("trace=", allowedLine);

            var deniedLine = Assert.Single(lines, line => line.Contains("authorization.denied", StringComparison.Ordinal));
            Assert.Contains($"subject={DbSeeder.AliceId}", deniedLine);
            Assert.Contains("action=incident.triage", deniedLine);
            Assert.Contains($"resource={deniedId}", deniedLine);
            Assert.Contains("result=denied", deniedLine);

            foreach (var line in lines)
            {
                Assert.DoesNotContain(StudyPassword, line, StringComparison.Ordinal);
                Assert.DoesNotContain("cookie", line, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("password", line, StringComparison.OrdinalIgnoreCase);
            }
        }
        finally
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Id == allowedId || item.Id == deniedId).ExecuteDeleteAsync();
        }
    }
}
