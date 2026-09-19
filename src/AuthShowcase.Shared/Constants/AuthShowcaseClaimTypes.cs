namespace AuthShowcase.Shared.Constants;

public static class AuthShowcaseClaimTypes
{
    public const string DateOfBirth = "date_of_birth";
    public const string Subscription = "subscription";
    public const string OriginalAdminId = "original_admin_id";
}

public static class AuthShowcaseRoles
{
    public const string Admin = "Admin";
    public const string User = "User";
}

public static class AuthShowcasePolicies
{
    public const string MinimumAge = "MinimumAge";
    public const string PremiumSubscription = "PremiumSubscription";
    public const string NoteOwner = "NoteOwner";
    public const string MultiScheme = "MultiScheme";
}

public static class AuthShowcaseSchemes
{
    public const string Jwt = "Jwt";
    public const string Cookie = "Cookie";
    public const string Basic = "Basic";
    public const string ApiKey = "ApiKey";
    public const string Hmac = "Hmac";
    public const string Certificate = "Certificate";
    public const string MultiScheme = "MultiScheme";
}
