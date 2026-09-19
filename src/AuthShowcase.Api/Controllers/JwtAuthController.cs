using System.Security.Claims;
using AuthShowcase.Api.Auth.Jwt;
using AuthShowcase.Api.Domain;
using AuthShowcase.Shared.Constants;
using AuthShowcase.Shared.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/jwt")]
public class JwtAuthController(
    UserManager<AppUser> userManager,
    JwtTokenService tokenService,
    RefreshTokenService refreshTokenService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        var user = new AppUser
        {
            UserName = request.Email,
            Email = request.Email,
            DateOfBirth = request.DateOfBirth,
            Subscription = request.Subscription,
        };

        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = BuildErrors(result) });
        }

        return await IssueTokensAsync(user, ct);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Unauthorized(new { error = "invalid_credentials" });
        }

        return await IssueTokensAsync(user, ct);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken ct)
    {
        var (outcome, userId, sid, newRefreshToken) = await refreshTokenService.RotateAsync(request.RefreshToken, ct);

        if (outcome != RefreshOutcome.Success || userId is null || sid is null || newRefreshToken is null)
        {
            return Unauthorized(new { error = outcome.ToString() });
        }

        var user = await userManager.FindByIdAsync(userId.ToString()!);
        if (user is null)
        {
            return Unauthorized(new { error = "user_not_found" });
        }

        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, expiresAt) = tokenService.CreateAccessToken(user, sid.Value, roles);
        return Ok(new TokenResponse(accessToken, newRefreshToken, expiresAt));
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke(RevokeRequest request, CancellationToken ct)
    {
        var revoked = await refreshTokenService.RevokeAsync(request.RefreshToken, ct);
        return revoked ? NoContent() : NotFound();
    }

    [HttpGet("whoami")]
    [Authorize(AuthenticationSchemes = AuthShowcaseSchemes.Jwt)]
    public IActionResult WhoAmI()
    {
        return Ok(new
        {
            userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub"),
            email = User.FindFirstValue(ClaimTypes.Email),
            sid = User.FindFirst("sid")?.Value,
            scheme = AuthShowcaseSchemes.Jwt,
        });
    }

    private async Task<IActionResult> IssueTokensAsync(AppUser user, CancellationToken ct)
    {
        var (sid, refreshToken) = await refreshTokenService.StartFamilyAsync(user.Id, ct);
        var roles = await userManager.GetRolesAsync(user);
        var (accessToken, expiresAt) = tokenService.CreateAccessToken(user, sid, roles);
        return Ok(new TokenResponse(accessToken, refreshToken, expiresAt));
    }

    private static Dictionary<string, string[]> BuildErrors(IdentityResult result) =>
        result.Errors
            .GroupBy(e => e.Code)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
}
