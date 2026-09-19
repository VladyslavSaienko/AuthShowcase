using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using AuthShowcase.Api.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthShowcase.Api.Auth.Basic;

public class BasicAuthenticationSchemeOptions : AuthenticationSchemeOptions;

/// <summary>
/// RFC 7617 Basic auth. Deliberately included as a baseline: credentials travel on every
/// request, base64-encoded (not encrypted), so this is only acceptable over HTTPS and even
/// then offers no protection against a compromised client, logging middleware, or replay.
/// </summary>
public class BasicAuthenticationHandler(
    IOptionsMonitor<BasicAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    UserManager<AppUser> userManager)
    : AuthenticationHandler<BasicAuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader) ||
            !authHeader.ToString().StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        string email, password;
        try
        {
            var encoded = authHeader.ToString()["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var separatorIndex = decoded.IndexOf(':');
            if (separatorIndex < 0)
            {
                return AuthenticateResult.Fail("Malformed Basic credentials.");
            }
            email = decoded[..separatorIndex];
            password = decoded[(separatorIndex + 1)..];
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Malformed Basic credentials.");
        }

        var user = await userManager.FindByEmailAsync(email);
        if (user is null || !await userManager.CheckPasswordAsync(user, password))
        {
            return AuthenticateResult.Fail("Invalid username or password.");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Basic realm=\"AuthShowcase\"";
        return base.HandleChallengeAsync(properties);
    }
}
