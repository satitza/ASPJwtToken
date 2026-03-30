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
        private readonly IWebHostEnvironment _env;

        public AuthenticationController(IEZAuthenticationService authenticationService, IWebHostEnvironment env)
        {
            _authenticationService = authenticationService;
            _env = env;
        }

        private CookieOptions CreateRefreshTokenCookieOptions(DateTimeOffset? expires = null)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = !_env.IsDevelopment(),   // false on dev so localhost works
                SameSite = SameSiteMode.Lax,
                Path = "/Authentication",         // sent to all /Authentication/* endpoints
                Expires = expires
            };
        }

        [HttpPost("login")]
        public IActionResult Authentication([FromBody] UserAuthenticationModel user)
        {
            if (!_authenticationService.UserLogin(user))
                return Unauthorized(new { message = "Invalid username or password." });

            var token = _authenticationService.GetAuthenticatedToken(user);

            // Set refresh token as HttpOnly cookie (browser sends it automatically)
            Response.Cookies.Append("refreshToken", token.RefreshToken!,
                CreateRefreshTokenCookieOptions(DateTimeOffset.UtcNow.AddDays(7)));

            // Only return access token in response body
            return Ok(new { token.AccessToken });
        }

        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
                return Unauthorized(new
                {
                    message = "No refresh token provided.",
                    debug = new
                    {
                        hint = "Browser did not send the refreshToken cookie",
                        cookiesReceived = Request.Cookies.Keys.ToList(),
                        requestPath = Request.Path.Value
                    }
                });

            var (newTokens, failReason) = _authenticationService.RefreshAccessTokenDebug(refreshToken);
            if (newTokens == null)
                return Unauthorized(new
                {
                    message = "Invalid or expired refresh token.",
                    debug = new
                    {
                        hint = failReason,
                        tokenLength = refreshToken.Length
                    }
                });

            // Rotate: set new refresh token cookie
            Response.Cookies.Append("refreshToken", newTokens.RefreshToken!,
                CreateRefreshTokenCookieOptions(DateTimeOffset.UtcNow.AddDays(7)));

            return Ok(new { newTokens.AccessToken });
        }

        /// <summary>
        /// Debug: check what cookies the server sees on the /refresh path
        /// </summary>
        [HttpGet("debug-cookies")]
        public IActionResult DebugCookies()
        {
            return Ok(new
            {
                cookiesReceived = Request.Cookies.Keys.ToList(),
                hasRefreshToken = Request.Cookies.ContainsKey("refreshToken"),
                requestPath = Request.Path.Value,
                isSecure = Request.IsHttps,
                isDevelopment = _env.IsDevelopment()
            });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("refreshToken", CreateRefreshTokenCookieOptions());

            return Ok(new { message = "Logged out successfully." });
        }
    }
}
