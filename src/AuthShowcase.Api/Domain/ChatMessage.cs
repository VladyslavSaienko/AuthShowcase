namespace AuthShowcase.Api.Domain;

public class ChatMessage
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Text { get; set; } = string.Empty;
    public DateTimeOffset SentAt { get; set; }
}
