using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthShowcase.Api.Auth.ApiKey;
using AuthShowcase.Api.Auth.Basic;
using AuthShowcase.Api.Auth.Hmac;
using AuthShowcase.Api.Auth.Jwt;
using AuthShowcase.Api.Data;
using AuthShowcase.Api.Domain;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddDataProtection();

builder.Services.AddIdentityCore<AppUser>(options =>
    {
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true;
    })
    .AddRoles<AppRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddScoped<RefreshTokenService>();

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()!;

// mTLS: Kestrel must ask for (but not globally require) a client certificate on the
// HTTPS endpoint. "Allow" rather than "Require" so every other auth scheme keeps working
// over the same port; only the /auth/certificate/* endpoint enforces the cert via [Authorize].
var caCertPath = Path.Combine(builder.Environment.ContentRootPath,
    builder.Configuration["Certificates:CaCertPath"] ?? "../../certs/ca.crt");
var caCertificate = X509CertificateLoader.LoadCertificateFromFile(caCertPath);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        // Kestrel's own TLS-layer chain check only trusts the OS root store, which doesn't
        // (and shouldn't) know about our throwaway dev CA. Accept any cert at the handshake
        // and let the Certificate authentication handler do the real check against
        // CustomTrustStore below - otherwise the handshake itself gets aborted.
        httpsOptions.ClientCertificateValidation = (_, _, _) => true;
    });
});

builder.Services.AddAuthentication()
    .AddJwtBearer(AuthShowcaseSchemes.Jwt, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ClockSkew = TimeSpan.FromSeconds(30),
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var sidClaim = context.Principal?.FindFirst("sid")?.Value;
                if (sidClaim is null || !Guid.TryParse(sidClaim, out var sid))
                {
                    context.Fail("Missing sid claim.");
                    return;
                }

                var refreshTokenService = context.HttpContext.RequestServices.GetRequiredService<RefreshTokenService>();
                if (await refreshTokenService.IsFamilyRevokedAsync(sid, context.HttpContext.RequestAborted))
                {
                    context.Fail("Token has been revoked.");
                }
            },
        };
    })
    .AddCookie(AuthShowcaseSchemes.Cookie, options =>
    {
        options.Cookie.Name = "AuthShowcase.Cookie";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    })
    .AddScheme<BasicAuthenticationSchemeOptions, BasicAuthenticationHandler>(AuthShowcaseSchemes.Basic, _ => { })
    .AddScheme<ApiKeyAuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(AuthShowcaseSchemes.ApiKey, _ => { })
    .AddScheme<HmacAuthenticationSchemeOptions, HmacAuthenticationHandler>(AuthShowcaseSchemes.Hmac, _ => { })
    .AddCertificate(AuthShowcaseSchemes.Certificate, options =>
    {
        // Chained only: every accepted cert must chain to our dev CA (CustomTrustStore below).
        // CertificateTypes.All would also accept bare self-signed certs with no chain check at
        // all, which defeats the point of running our own CA for this demo.
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.CustomTrustStore = [caCertificate];
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var claims = new List<System.Security.Claims.Claim>
                {
                    new(System.Security.Claims.ClaimTypes.NameIdentifier, context.ClientCertificate.Subject),
                    new("cert_thumbprint", context.ClientCertificate.Thumbprint),
                };
                context.Principal = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(claims, context.Scheme.Name));
                context.Success();
                return Task.CompletedTask;
            },
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

if (app.Environment.IsDevelopment())
{
    await SeedData.SeedAsync(app.Services);
}

app.Run();

public partial class Program;
