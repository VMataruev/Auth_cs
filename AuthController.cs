using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using BCrypt.Net;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly JwtService _jwtService;

    public AuthController(JwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Примерная проверка (обычно тут база данных)
        if (request.Username == "admin" && BCrypt.Net.BCrypt.Verify(request.Password, BCrypt.Net.BCrypt.HashPassword("adminpass")))
        {
            var token = _jwtService.CreateToken(request.Username, "admin");
            Response.Cookies.Append("access_token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
            return Ok(new { message = "Вы вошли" });
        }

        return Unauthorized(new { message = "Неверные учетные данные" });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("access_token");
        return Ok(new { message = "Вы вышли" });
    }

    [HttpGet("protected")]
    public IActionResult ProtectedRoute()
    {
        var token = Request.Cookies["access_token"];
        if (token == null) return Unauthorized(new { message = "Не авторизован" });

        var principal = _jwtService.DecodeToken(token);
        if (principal == null) return Unauthorized(new { message = "Недействительный токен" });

        var username = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value;
        var rank = principal.FindFirst("rank")?.Value;

        return Ok(new { message = $"Привет, {username}", login = username, rank });
    }
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
