namespace AuthShowcase.Api.Domain;

public class ImpersonationSession
{
    public Guid Id { get; set; }
    public Guid AdminUserId { get; set; }
    public Guid TargetUserId { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }
    public string Reason { get; set; } = string.Empty;
}
