using AuthShowcase.Api.Domain;
using AuthShowcase.Shared.Constants;
using AuthShowcase.Shared.Dtos;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/cookie")]
public class CookieAuthController(UserManager<AppUser> userManager) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Unauthorized(new { error = "invalid_credentials" });
        }

        var roles = await userManager.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new(AuthShowcaseClaimTypes.DateOfBirth, user.DateOfBirth.ToString("yyyy-MM-dd")),
            new(AuthShowcaseClaimTypes.Subscription, user.Subscription),
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var identity = new ClaimsIdentity(claims, AuthShowcaseSchemes.Cookie);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(AuthShowcaseSchemes.Cookie, principal, new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8),
        });

        return NoContent();
    }

    [HttpPost("logout")]
    [Authorize(AuthenticationSchemes = AuthShowcaseSchemes.Cookie)]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(AuthShowcaseSchemes.Cookie);
        return NoContent();
    }
}
