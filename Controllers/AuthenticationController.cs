using JwtTokenExample.Models;
using JwtTokenExample.Services;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenExample.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IEZAuthenticationService _authenticationService;

        private static readonly CookieOptions RefreshTokenCookieOptions = new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/Authentication/refresh"
        };

        public AuthenticationController(IEZAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost("login")]
        public IActionResult Authentication([FromBody] UserAuthenticationModel user)
        {
            if (!_authenticationService.UserLogin(user))
                return Unauthorized(new { message = "Invalid username or password." });

            var token = _authenticationService.GetAuthenticatedToken(user);

            // Set refresh token as HttpOnly cookie (browser sends it automatically)
            Response.Cookies.Append("refreshToken", token.RefreshToken!, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/Authentication/refresh",
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            // Only return access token in response body
            return Ok(new { token.AccessToken });
        }

        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
                return Unauthorized(new { message = "No refresh token provided." });

            var newTokens = _authenticationService.RefreshAccessToken(refreshToken);
            if (newTokens == null)
                return Unauthorized(new { message = "Invalid or expired refresh token." });

            // Rotate: set new refresh token cookie
            Response.Cookies.Append("refreshToken", newTokens.RefreshToken!, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/Authentication/refresh",
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            return Ok(new { newTokens.AccessToken });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/Authentication/refresh"
            });

            return Ok(new { message = "Logged out successfully." });
        }
    }
}
