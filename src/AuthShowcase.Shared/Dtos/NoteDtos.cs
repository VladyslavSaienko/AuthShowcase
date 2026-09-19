namespace AuthShowcase.Shared.Dtos;

public sealed record NoteDto(Guid Id, Guid OwnerId, string Title, string Content, DateTimeOffset CreatedAt);

public sealed record CreateNoteRequest(string Title, string Content);

public sealed record UpdateNoteRequest(string Title, string Content);
