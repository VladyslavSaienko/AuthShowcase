namespace AuthShowcase.Api.Domain;

public class ApiClient
{
    public Guid Id { get; set; }
    public string ClientKey { get; set; } = string.Empty;
    public string HmacSecret { get; set; } = string.Empty;
    public string AllowedScopes { get; set; } = string.Empty;
}
