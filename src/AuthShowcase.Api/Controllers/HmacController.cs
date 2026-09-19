using System.Security.Claims;
using AuthShowcase.Shared.Constants;
using AuthShowcase.Shared.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthShowcase.Api.Controllers;

[ApiController]
[Route("auth/hmac")]
[Authorize(AuthenticationSchemes = AuthShowcaseSchemes.Hmac)]
public class HmacController : ControllerBase
{
    [HttpPost("webhook")]
    public IActionResult Webhook(HmacWebhookPayload payload)
    {
        return Ok(new
        {
            received = true,
            clientId = User.FindFirstValue("client_id"),
            eventType = payload.EventType,
        });
    }
}
