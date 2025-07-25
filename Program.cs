using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);

// Конфигурация JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });

// Настройка YARP
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

// Middleware для перехвата /auth/login
app.MapWhen(ctx => ctx.Request.Path.StartsWithSegments("/auth/login"), appBuilder =>
{
    appBuilder.UseMiddleware<AuthMiddleware>();
});

app.MapReverseProxy();
app.Run();

// Middleware для обработки аутентификации
class AuthMiddleware
{
    private readonly IHttpClientFactory _clientFactory;
    private readonly IConfiguration _config;

    public AuthMiddleware(IHttpClientFactory clientFactory, IConfiguration config)
    {
        _clientFactory = clientFactory;
        _config = config;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Перенаправляем запрос в Auth Service
        var client = _clientFactory.CreateClient();
        var authServiceUrl = _config["Services:AuthService"] + "/auth/login";
        
        var response = await client.PostAsJsonAsync(authServiceUrl, 
            await context.Request.ReadFromJsonAsync<AuthRequest>());

        // 2. Возвращаем результат клиенту
        context.Response.StatusCode = (int)response.StatusCode;
        await response.Content.CopyToAsync(context.Response.Body);
    }
}

// Модели
public record AuthRequest(string Email, string Password);
public record TokenResponse(string AccessToken, string RefreshToken, int ExpiresIn);