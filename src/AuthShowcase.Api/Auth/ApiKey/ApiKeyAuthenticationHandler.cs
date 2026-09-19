using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthShowcase.Api.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthShowcase.Api.Auth.ApiKey;

public class ApiKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions;

/// <summary>
/// Simple service-to-service auth: a static shared secret in the X-Api-Key header.
/// No expiry, no rotation built in — that's the trade-off vs. JWT/HMAC: trivial to
/// implement and use, but a leaked key is valid forever until someone manually revokes it.
/// </summary>
public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AppDbContext db)
    : AuthenticationHandler<ApiKeyAuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string HeaderName = "X-Api-Key";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderName, out var apiKeyHeader) || string.IsNullOrWhiteSpace(apiKeyHeader))
        {
            return AuthenticateResult.NoResult();
        }

        var apiKey = apiKeyHeader.ToString();
        var client = await db.ApiClients.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientKey == apiKey, Context.RequestAborted);

        if (client is null)
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, client.Id.ToString()),
            new("client_id", client.ClientKey),
            new("scope", client.AllowedScopes),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
