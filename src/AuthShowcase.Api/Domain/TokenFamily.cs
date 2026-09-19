namespace AuthShowcase.Api.Domain;

/// <summary>
/// One login "session": a chain of rotated refresh tokens sharing a "sid" claim.
/// Revoking a family invalidates every access token minted under that sid immediately,
/// even ones that have not expired yet.
/// </summary>
public class TokenFamily
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public List<RefreshToken> RefreshTokens { get; set; } = [];
}

public class RefreshToken
{
    public Guid Id { get; set; }
    public Guid FamilyId { get; set; }
    public TokenFamily Family { get; set; } = null!;
    public string TokenHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
