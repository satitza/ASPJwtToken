using JwtTokenExample.Models;
using JwtTokenExample.Services;
using Microsoft.AspNetCore.Mvc;
using AuthenticationService = Microsoft.AspNetCore.Authentication.AuthenticationService;

namespace JwtTokenExample.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private IEZAuthenticationService _authenticationService;

        public AuthenticationController(IEZAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }


        [HttpPost("login")]
        public IActionResult Authentication([FromBody] UserAuthenticationModel user)
        {
            try
            {
                if (_authenticationService.UserLogin(user))
                {
                    return Ok(_authenticationService.GetAuthenticatedToken(user));
                }

                return Unauthorized("User authentication fail.");
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}