using System.Text;
using AuthShowcase.Api.Auth.Basic;
using AuthShowcase.Api.Auth.Jwt;
using AuthShowcase.Api.Data;
using AuthShowcase.Api.Domain;
using AuthShowcase.Shared.Constants;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
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
    .AddScheme<BasicAuthenticationSchemeOptions, BasicAuthenticationHandler>(AuthShowcaseSchemes.Basic, _ => { });

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

app.Run();

public partial class Program;
