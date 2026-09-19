using System.Security.Claims;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/certificate")]
[Authorize(AuthenticationSchemes = AuthShowcaseSchemes.Certificate)]
public class CertificateAuthController : ControllerBase
{
    [HttpGet("whoami")]
    public IActionResult WhoAmI()
    {
        return Ok(new
        {
            subject = User.FindFirstValue(ClaimTypes.NameIdentifier),
            thumbprint = User.FindFirstValue("cert_thumbprint"),
            scheme = AuthShowcaseSchemes.Certificate,
        });
    }
}
