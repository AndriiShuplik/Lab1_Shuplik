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
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new IncidentCommentDetailsResponse(
                item.Id,
                item.Incident.Id,
                item.Author.DisplayName,
                item.Text,
                item.IsInternal,
                item.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null
            ? Results.Problem(
                title: "Коментар не знайдено",
                detail: $"Коментар '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(comment);
    }
}