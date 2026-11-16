using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

public static class CsrfEndpoints
{
    public static void AddCsrfProtection(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = CsrfContract.HeaderName;
            options.Cookie.Name = CsrfContract.CookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        });
    }

    public static void MapCsrfEndpoints(this WebApplication app)
    {
        app.MapGet(CsrfContract.TokenRoute, (IAntiforgery antiforgery, HttpContext httpContext) =>
            Results.Ok(new { token = antiforgery.GetAndStoreTokens(httpContext).RequestToken }))
            .RequireAuthorization();
    }
}
