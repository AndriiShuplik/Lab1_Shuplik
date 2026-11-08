using System.Net.Mail;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegisterRequest input, UserManager<ApplicationUser> users) =>
        {
            var errors = ValidateRegistration(input);
            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors);
            }

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };

            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                return MapIdentityFailure(result);
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded)
            {
                throw new InvalidOperationException("Default role assignment failed.");
            }

            return Results.Created("/api/me", new RegisterResponse(user.Id, user.UserName!, user.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });
                app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        });
               app.MapGet("/api/me", async (HttpContext context, UserManager<ApplicationUser> users) =>
        {
            var idValue = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(idValue, out var userId))
            {
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
            }

            var user = await users.FindByIdAsync(userId.ToString());
            if (user is null)
            {
                return Results.Unauthorized();
            }

            return Results.Ok(new MeResponse(user.Id, user.UserName!, user.DisplayName));
        }).RequireAuthorization();
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static Dictionary<string, string[]> ValidateRegistration(RegisterRequest input)
    {
        var errors = new Dictionary<string, string[]>();

        var userName = input.UserName?.Trim();
        if (string.IsNullOrEmpty(userName) || userName.Length is < 3 or > 64)
        {
            errors["userName"] = ["User name must be 3-64 characters."];
        }
        else if (!userName.All(c => char.IsAsciiLetterOrDigit(c) || "-._@+".Contains(c)))
        {
            errors["userName"] = ["User name may contain only Latin letters, digits and - . _ @ +"];
        }

        var email = input.Email?.Trim();
        if (string.IsNullOrEmpty(email) || email.Length > 256
            || !MailAddress.TryCreate(email, out var parsed) || parsed?.Address != email)
        {
            errors["email"] = ["A valid email address up to 256 characters is required."];
        }

        var displayName = input.DisplayName?.Trim();
        if (string.IsNullOrEmpty(displayName) || displayName.Length > 120)
        {
            errors["displayName"] = ["Display name must be 1-120 characters."];
        }

        if (string.IsNullOrEmpty(input.Password) || input.Password.Length is < 10 or > 128)
        {
            errors["password"] = ["Password must be 10-128 characters."];
        }

        return errors;
    }

    private static IResult MapIdentityFailure(IdentityResult result)
    {
        var codes = result.Errors.Select(error => error.Code).ToHashSet();

        if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
        {
            return Results.Problem(title: "Registration conflict", statusCode: StatusCodes.Status409Conflict);
        }

        var errors = new Dictionary<string, string[]>();
        if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
        {
            errors["password"] = ["Password must contain upper and lower case letters, a digit and a symbol."];
        }

        if (codes.Contains("InvalidUserName"))
        {
            errors["userName"] = ["User name contains characters that are not allowed."];
        }

        if (codes.Contains("InvalidEmail"))
        {
            errors["email"] = ["Email address is not valid."];
        }

        return errors.Count > 0
            ? Results.ValidationProblem(errors)
            : Results.Problem(title: "Registration failed", statusCode: StatusCodes.Status400BadRequest);
    }
}

public sealed record RegisterRequest(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record RegisterResponse(Guid Id, string UserName, string DisplayName);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record MeResponse(Guid Id, string UserName, string DisplayName);