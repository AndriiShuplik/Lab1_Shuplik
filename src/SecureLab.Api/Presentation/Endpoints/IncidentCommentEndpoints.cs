using System.Security.Claims;
using SecureLab.Api.Application.Incidents;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentCommentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incident-comments")
            .WithTags("Incident comments")
            .RequireAuthorization();

        group.MapGet("/{id:guid}", GetByIdAsync)
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

        private static async Task<IResult> GetByIdAsync(
        Guid id,
        ClaimsPrincipal user,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var isAnalyst = IncidentAccess.IsAnalyst(user);
        var userId = IncidentAccess.GetUserId(user);

        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Where(item => isAnalyst
                || (item.Incident.OwnerUserId == userId && !item.IsInternal))
            .Select(item => new IncidentCommentDetailsResponse(
                item.Id,
                item.Incident.Id,
                item.Author.DisplayName,
                item.Text,
                item.IsInternal,
                item.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null
            ? ResourceProblems.NotFound("Коментар не знайдено")
            : Results.Ok(comment);
    }
}