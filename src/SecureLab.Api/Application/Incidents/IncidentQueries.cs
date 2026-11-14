using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking().VisibleTo(user);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        var includeInternal = IncidentAccess.IsAnalyst(user);

        return dbContext.Incidents
            .AsNoTracking()
            .VisibleTo(user)
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternal || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var query = dbContext.Incidents.AsNoTracking().VisibleTo(user);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        var groups = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new { Severity = group.Key, Count = group.Count() })
            .ToListAsync(cancellationToken);

        var result = groups
            .OrderByDescending(group => group.Count)
            .ThenBy(group => group.Severity.ToString(), StringComparer.Ordinal)
            .Select(group => new IncidentSeveritySummaryResponse(
                group.Severity.ToString(),
                group.Count))
            .ToList();

        logger.LogInformation(
            "Built severity summary with {GroupCount} groups for status filter {Status}",
            result.Count,
            status);

        return result;
    }
}