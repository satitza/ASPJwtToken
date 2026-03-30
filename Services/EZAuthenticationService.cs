using JwtTokenExample.Models;
using System.IdentityModel.Tokens.Jwt;

namespace JwtTokenExample.Services
{
    public class EZAuthenticationService : IEZAuthenticationService
    {
        private List<UserAuthenticationModel>? _userList;

        public EZAuthenticationService()
        {
            _userList = new List<UserAuthenticationModel>
            {
                new UserAuthenticationModel { UserName = "admin", Password = "P@ssw0rd" },
                new UserAuthenticationModel { UserName = "user", Password = "P@ssw0rd" }
            };
        }

        public bool UserLogin(UserAuthenticationModel user)
        {
            return _userList.Any(w => w.UserName == user.UserName && w.Password == user.Password);
        }

        public AuthenticatedToken GetAuthenticatedToken(UserAuthenticationModel user)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                JWTTokenService jwtTokenService = new JWTTokenService(tokenHandler);
                return new AuthenticatedToken
                {
                    AccessToken = tokenHandler.WriteToken(jwtTokenService.GenerateAccessToken(user)),
                    RefreshToken = tokenHandler.WriteToken(jwtTokenService.GenerateRefreshToken(user))
                };
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}