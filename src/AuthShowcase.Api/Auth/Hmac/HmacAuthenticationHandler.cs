using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using AuthShowcase.Api.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthShowcase.Api.Auth.Hmac;

public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    /// <summary>How far a request's timestamp may drift from "now" before it's rejected as a replay.</summary>
    public TimeSpan ReplayWindow { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Request-signing auth in the style of Stripe/GitHub webhooks: the caller signs
/// "{timestamp}.{rawBody}" with a shared secret and sends the signature + timestamp as
/// headers. A timestamp window defeats naive replay of a captured request; it does NOT
/// protect against a compromised secret, so secrets still need rotation and transport security.
/// </summary>
public class HmacAuthenticationHandler(
    IOptionsMonitor<HmacAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AppDbContext db)
    : AuthenticationHandler<HmacAuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string ClientIdHeader = "X-Client-Id";
    private const string TimestampHeader = "X-Timestamp";
    private const string SignatureHeader = "X-Signature";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ClientIdHeader, out var clientIdHeader) ||
            !Request.Headers.TryGetValue(TimestampHeader, out var timestampHeader) ||
            !Request.Headers.TryGetValue(SignatureHeader, out var signatureHeader))
        {
            return AuthenticateResult.NoResult();
        }

        if (!long.TryParse(timestampHeader, out var unixSeconds))
        {
            return AuthenticateResult.Fail("Malformed timestamp.");
        }

        var timestamp = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        var drift = DateTimeOffset.UtcNow - timestamp;
        if (drift.Duration() > Options.ReplayWindow)
        {
            return AuthenticateResult.Fail("Timestamp outside the allowed replay window.");
        }

        var client = await db.ApiClients.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientKey == clientIdHeader.ToString(), Context.RequestAborted);
        if (client is null)
        {
            return AuthenticateResult.Fail("Unknown client.");
        }

        Request.EnableBuffering();
        string body;
        using (var reader = new StreamReader(Request.Body, Encoding.UTF8, leaveOpen: true))
        {
            body = await reader.ReadToEndAsync(Context.RequestAborted);
        }
        Request.Body.Position = 0;

        var payload = $"{unixSeconds}.{body}";
        var expected = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(client.HmacSecret), Encoding.UTF8.GetBytes(payload)));

        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signatureHeader.ToString().ToLowerInvariant())))
        {
            return AuthenticateResult.Fail("Signature mismatch.");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, client.Id.ToString()),
            new("client_id", client.ClientKey),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
