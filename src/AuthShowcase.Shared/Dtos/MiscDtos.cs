namespace AuthShowcase.Shared.Dtos;

public sealed record TotpEnrollResponse(string SharedKey, string OtpAuthUri);

public sealed record TotpVerifyRequest(string Code);

public sealed record RequestLinkRequest(string Email);

public sealed record ImpersonateRequest(string Reason);

public sealed record HmacWebhookPayload(string EventType, string Data);

public sealed record ChatMessageDto(string UserId, string Text, DateTimeOffset SentAt);
