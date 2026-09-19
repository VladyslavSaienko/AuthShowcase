using AuthShowcase.Api.Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthShowcase.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<AppUser, AppRole, Guid>(options)
{
    public DbSet<Note> Notes => Set<Note>();
    public DbSet<ApiClient> ApiClients => Set<ApiClient>();
    public DbSet<ImpersonationSession> ImpersonationSessions => Set<ImpersonationSession>();
    public DbSet<ChatMessage> ChatMessages => Set<ChatMessage>();
    public DbSet<TokenFamily> TokenFamilies => Set<TokenFamily>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Note>(e =>
        {
            e.HasKey(n => n.Id);
            e.Property(n => n.Title).HasMaxLength(200).IsRequired();
            e.HasIndex(n => n.OwnerId);
        });

        builder.Entity<ApiClient>(e =>
        {
            e.HasKey(c => c.Id);
            e.HasIndex(c => c.ClientKey).IsUnique();
        });

        builder.Entity<ImpersonationSession>(e =>
        {
            e.HasKey(s => s.Id);
        });

        builder.Entity<ChatMessage>(e =>
        {
            e.HasKey(m => m.Id);
        });

        builder.Entity<TokenFamily>(e =>
        {
            e.HasKey(f => f.Id);
            e.HasIndex(f => f.UserId);
        });

        builder.Entity<RefreshToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.HasOne(t => t.Family)
                .WithMany(f => f.RefreshTokens)
                .HasForeignKey(t => t.FamilyId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
