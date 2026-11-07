using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

internal static class TestCleanup
{
    public static async Task DeleteByTitleAsync(SecureLabApiFactory factory, string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    public static async Task CloseByTitleAsync(SecureLabApiFactory factory, string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents
            .Where(item => item.Title == title)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Status, IncidentStatus.Closed));
    }
}