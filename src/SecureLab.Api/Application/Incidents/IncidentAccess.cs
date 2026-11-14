using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
}

public static class IncidentAccess
{
    public static Guid? GetUserId(ClaimsPrincipal user) =>
        Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    public static bool IsAnalyst(ClaimsPrincipal user) => user.IsInRole(DbSeeder.AnalystRole);

    public static bool CanTriage(ClaimsPrincipal user) => IsAnalyst(user);

    public static bool IsOwner(ClaimsPrincipal user, Incident incident) =>
        GetUserId(user) is { } userId && incident.OwnerUserId == userId;

    public static IQueryable<Incident> VisibleTo(this IQueryable<Incident> query, ClaimsPrincipal user)
    {
        if (IsAnalyst(user))
        {
            return query;
        }

        var userId = GetUserId(user) ?? Guid.Empty;
        return query.Where(incident => incident.OwnerUserId == userId);
    }
}

public sealed class IncidentAccessHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident resource)
    {
        var knownOperation = requirement.Name == IncidentOperations.Update.Name
            || requirement.Name == IncidentOperations.Delete.Name;

        if (knownOperation && IncidentAccess.IsOwner(context.User, resource))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}