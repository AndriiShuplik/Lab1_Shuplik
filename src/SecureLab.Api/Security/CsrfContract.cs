namespace SecureLab.Api.Security;

public static class CsrfContract
{
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string TokenRoute = "/api/auth/csrf-token";
    public const string CookieName = "SecureLab.Antiforgery";
}
