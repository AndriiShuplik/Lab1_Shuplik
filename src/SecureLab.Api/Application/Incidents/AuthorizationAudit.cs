using System.Diagnostics;

namespace SecureLab.Api.Application.Incidents;

public sealed class AuthorizationAudit(ILogger<AuthorizationAudit> logger)
{
    public void Denied(HttpContext httpContext, string action, Guid resourceId)
    {
        var subject = IncidentAccess.GetUserId(httpContext.User);
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} result=denied at={TimestampUtc:O} trace={TraceId}",
            subject,
            action,
            resourceId,
            DateTimeOffset.UtcNow,
            traceId);
    }
}