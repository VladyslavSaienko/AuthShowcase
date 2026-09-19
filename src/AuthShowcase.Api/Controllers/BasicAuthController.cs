using System.Security.Claims;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/basic")]
[Authorize(AuthenticationSchemes = AuthShowcaseSchemes.Basic)]
public class BasicAuthController : ControllerBase
{
    [HttpGet("whoami")]
    public IActionResult WhoAmI()
    {
        return Ok(new
        {
            userId = User.FindFirstValue(ClaimTypes.NameIdentifier),
            email = User.FindFirstValue(ClaimTypes.Email),
            scheme = AuthShowcaseSchemes.Basic,
        });
    }
}
