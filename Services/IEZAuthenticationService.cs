using JwtTokenExample.Models;

namespace JwtTokenExample.Services
{
    public interface IEZAuthenticationService
    {
        bool UserLogin(UserAuthenticationModel user);

        AuthenticatedToken GetAuthenticatedToken(UserAuthenticationModel user);

        AuthenticatedToken? RefreshAccessToken(string refreshToken);

        UserAuthenticationModel? GetUserByName(string userName);
    }
}
