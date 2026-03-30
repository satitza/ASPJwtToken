using JwtTokenExample.Models;

namespace JwtTokenExample.Services
{
    public interface IEZAuthenticationService
    {
        bool UserLogin(UserAuthenticationModel user);

        AuthenticatedToken GetAuthenticatedToken(UserAuthenticationModel user);
    }
}