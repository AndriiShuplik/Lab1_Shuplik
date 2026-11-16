using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Security;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    private const string NotFoundTitle = "Інцидент не знайдено";

    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces<IncidentUpdatedResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .AddEndpointFilter<AntiforgeryFilter>();

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .AddEndpointFilter<AntiforgeryFilter>();

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces<IncidentStatusResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .AddEndpointFilter<AntiforgeryFilter>();

        return endpoints;
    }

    private static bool TryParseStatus(string? status, out IncidentStatus? parsed, out IResult? error)
    {
        parsed = null;
        error = null;
        if (status is null)
        {
            return true;
        }

        if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
            || !Enum.IsDefined(candidate))
        {
            error = Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
            });
            return false;
        }

        parsed = candidate;
        return true;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        ClaimsPrincipal user,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryParseStatus(status, out var parsedStatus, out var error))
            return error!;

        return Results.Ok(await queries.GetListAsync(parsedStatus, user, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        ClaimsPrincipal user,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, user, cancellationToken);
        return incident is null
            ? ResourceProblems.NotFound(NotFoundTitle)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        ClaimsPrincipal user,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryParseStatus(status, out var parsedStatus, out var error))
            return error!;

        return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, user, cancellationToken));
    }

    private static IResult Refuse(ClaimsPrincipal user) =>
        IncidentAccess.IsAnalyst(user)
            ? ResourceProblems.Forbidden()
            : ResourceProblems.NotFound(NotFoundTitle);

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        ClaimsPrincipal user,
        IAuthorizationService authorization,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return ResourceProblems.NotFound(NotFoundTitle);

        var decision = await authorization.AuthorizeAsync(user, incident, IncidentOperations.Update);
        if (!decision.Succeeded)
            return Refuse(user);

        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Заголовок обов’язковий."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Заголовок не довший за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов’язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не довший за 4000 символів."];

        if (errors.Count > 0)
            return Results.ValidationProblem(errors);

        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.Ok(new IncidentUpdatedResponse(
            incident.Id,
            incident.Title,
            incident.Description,
            incident.UpdatedAtUtc));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        ClaimsPrincipal user,
        IAuthorizationService authorization,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return ResourceProblems.NotFound(NotFoundTitle);

        var decision = await authorization.AuthorizeAsync(user, incident, IncidentOperations.Delete);
        if (!decision.Succeeded)
            return Refuse(user);

        if (incident.Status != IncidentStatus.New)
            return ResourceProblems.Conflict("Видалити можна лише інцидент у стані New.");

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        ClaimsPrincipal user,
        HttpContext httpContext,
        AuthorizationAudit audit,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!IncidentAccess.CanTriage(user))
        {
            audit.Denied(httpContext, "incident.triage", id);
            return ResourceProblems.Forbidden();
        }

        var incident = await dbContext.Incidents
            .FirstOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return ResourceProblems.NotFound(NotFoundTitle);

        if (incident.Status != IncidentStatus.New)
            return ResourceProblems.Conflict("Triage дозволений лише для інциденту у стані New.");

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.Ok(new IncidentStatusResponse(
            incident.Id,
            incident.Status.ToString(),
            incident.UpdatedAtUtc));
    }
}