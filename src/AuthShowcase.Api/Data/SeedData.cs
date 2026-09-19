using AuthShowcase.Api.Domain;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthShowcase.Api.Data;

/// <summary>Dev/demo seed data: roles and a couple of API clients with well-known credentials
/// so the README's curl examples and the OpenAPI page work out of the box.</summary>
public static class SeedData
{
    /// <summary>Doubles as the X-Api-Key value (ApiKey scheme) and the X-Client-Id value (Hmac scheme) —
    /// one seeded ApiClient row is enough to demo both.</summary>
    public const string DemoClientKey = "ask_demo_9f6c2f2f7c5d4e0aa2b6b7b9d5f3a1c4";
    public const string DemoHmacSecret = "whsec_demo_5e2c7a1b9d3f4468a7c0e1d2f3a4b5c6";

    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<AppRole>>();

        foreach (var roleName in new[] { AuthShowcaseRoles.Admin, AuthShowcaseRoles.User })
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new AppRole { Name = roleName });
            }
        }

        if (!await db.ApiClients.AnyAsync(c => c.ClientKey == DemoClientKey))
        {
            db.ApiClients.Add(new ApiClient
            {
                Id = Guid.NewGuid(),
                ClientKey = DemoClientKey,
                HmacSecret = DemoHmacSecret,
                AllowedScopes = "api.internal",
            });
            await db.SaveChangesAsync();
        }
    }
}
