using System.Security.Claims;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/apikey")]
[Authorize(AuthenticationSchemes = AuthShowcaseSchemes.ApiKey)]
public class ApiKeyController : ControllerBase
{
    [HttpGet("whoami")]
    public IActionResult WhoAmI()
    {
        return Ok(new
        {
            clientId = User.FindFirstValue("client_id"),
            scope = User.FindFirstValue("scope"),
            scheme = AuthShowcaseSchemes.ApiKey,
        });
    }
}
