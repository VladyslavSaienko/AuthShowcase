using Microsoft.AspNetCore.Identity;

namespace AuthShowcase.Api.Domain;

public class AppUser : IdentityUser<Guid>
{
    public DateOnly DateOfBirth { get; set; }
    public string Subscription { get; set; } = "free";
    public string? TotpSecret { get; set; }
    public bool IsTotpEnabled { get; set; }
}

public class AppRole : IdentityRole<Guid>
{
}
