namespace AuthShowcase.Shared.Dtos;

public sealed record RegisterRequest(string Email, string Password, DateOnly DateOfBirth, string Subscription = "free");

public sealed record LoginRequest(string Email, string Password);

public sealed record TokenResponse(string AccessToken, string RefreshToken, DateTimeOffset ExpiresAt);

public sealed record RefreshRequest(string RefreshToken);

public sealed record RevokeRequest(string RefreshToken);
