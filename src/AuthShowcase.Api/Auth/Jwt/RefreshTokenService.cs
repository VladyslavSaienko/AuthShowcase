using System.Security.Cryptography;
using AuthShowcase.Api.Data;
using AuthShowcase.Api.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthShowcase.Api.Auth.Jwt;

public enum RefreshOutcome
{
    Success,
    NotFound,
    Expired,
    Revoked,
    ReuseDetected,
}

public class RefreshTokenService(AppDbContext db, IOptions<JwtOptions> options)
{
    private readonly JwtOptions _options = options.Value;

    /// <summary>Starts a brand-new session (login). Returns the family id (sid) and the opaque refresh token to hand to the client.</summary>
    public async Task<(Guid Sid, string RefreshToken)> StartFamilyAsync(Guid userId, CancellationToken ct)
    {
        var family = new TokenFamily
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        db.TokenFamilies.Add(family);

        var refreshToken = await IssueRefreshTokenAsync(family.Id, ct);
        return (family.Id, refreshToken);
    }

    public async Task<(RefreshOutcome Outcome, Guid? UserId, Guid? Sid, string? NewRefreshToken)> RotateAsync(string presentedToken, CancellationToken ct)
    {
        if (!TryParse(presentedToken, out var id, out var secret))
        {
            return (RefreshOutcome.NotFound, null, null, null);
        }

        var stored = await db.RefreshTokens
            .Include(t => t.Family)
            .FirstOrDefaultAsync(t => t.Id == id, ct);

        if (stored is null || !VerifySecret(secret, stored.TokenHash))
        {
            return (RefreshOutcome.NotFound, null, null, null);
        }

        if (stored.Family.RevokedAt is not null)
        {
            return (RefreshOutcome.Revoked, null, null, null);
        }

        if (stored.ConsumedAt is not null)
        {
            // Reuse of an already-rotated refresh token: treat as token theft, kill the whole session.
            stored.Family.RevokedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            return (RefreshOutcome.ReuseDetected, null, null, null);
        }

        if (stored.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return (RefreshOutcome.Expired, null, null, null);
        }

        stored.ConsumedAt = DateTimeOffset.UtcNow;
        var newToken = await IssueRefreshTokenAsync(stored.FamilyId, ct);

        return (RefreshOutcome.Success, stored.Family.UserId, stored.FamilyId, newToken);
    }

    public async Task<bool> RevokeAsync(string presentedToken, CancellationToken ct)
    {
        if (!TryParse(presentedToken, out var id, out _))
        {
            return false;
        }

        var stored = await db.RefreshTokens
            .Include(t => t.Family)
            .FirstOrDefaultAsync(t => t.Id == id, ct);

        if (stored is null)
        {
            return false;
        }

        stored.Family.RevokedAt ??= DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return true;
    }

    private async Task<string> IssueRefreshTokenAsync(Guid familyId, CancellationToken ct)
    {
        var id = Guid.NewGuid();
        var secretBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(secretBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        db.RefreshTokens.Add(new RefreshToken
        {
            Id = id,
            FamilyId = familyId,
            TokenHash = Hash(secret),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_options.RefreshTokenDays),
        });

        await db.SaveChangesAsync(ct);
        return $"{id:N}.{secret}";
    }

    private static bool TryParse(string presentedToken, out Guid id, out string secret)
    {
        id = Guid.Empty;
        secret = string.Empty;
        var parts = presentedToken.Split('.', 2);
        if (parts.Length != 2 || !Guid.TryParse(parts[0], out id))
        {
            return false;
        }
        secret = parts[1];
        return true;
    }

    private static string Hash(string secret)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(bytes);
    }

    private static bool VerifySecret(string secret, string storedHash) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(Hash(secret)),
            System.Text.Encoding.UTF8.GetBytes(storedHash));

    /// <summary>Used by the JWT bearer handler to check whether an access token's session has been revoked.</summary>
    public Task<bool> IsFamilyRevokedAsync(Guid sid, CancellationToken ct) =>
        db.TokenFamilies.Where(f => f.Id == sid).Select(f => f.RevokedAt != null).SingleOrDefaultAsync(ct);
}
