using System.IdentityModel.Tokens.Jwt;
using JwtTokenExample.Models;

namespace JwtTokenExample.Services
{
    public class EZAuthenticationService : IEZAuthenticationService
    {
        private readonly List<UserAuthenticationModel> _userList;
        private readonly RsaKeyProvider _rsaKeyProvider;
        private readonly RefreshTokenStore _refreshTokenStore;

        public EZAuthenticationService(RsaKeyProvider rsaKeyProvider, RefreshTokenStore refreshTokenStore)
        {
            _rsaKeyProvider = rsaKeyProvider;
            _refreshTokenStore = refreshTokenStore;

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

        public UserAuthenticationModel? GetUserByName(string userName)
        {
            return _userList.FirstOrDefault(w => w.UserName == userName);
        }

        public AuthenticatedToken GetAuthenticatedToken(UserAuthenticationModel user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtService = new JWTTokenService(tokenHandler, _rsaKeyProvider);

            var (accessToken, _) = jwtService.GenerateAccessToken(user.UserName!, "1234");
            var (refreshToken, refreshJti, refreshExpires) = jwtService.GenerateRefreshToken(user.UserName!);

            var familyId = Guid.NewGuid().ToString();
            _refreshTokenStore.Store(refreshJti, familyId, user.UserName!, refreshExpires);

            return new AuthenticatedToken
            {
                AccessToken = tokenHandler.WriteToken(accessToken),
                RefreshToken = tokenHandler.WriteToken(refreshToken)
            };
        }

        public AuthenticatedToken? RefreshAccessToken(string refreshTokenStr)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtService = new JWTTokenService(tokenHandler, _rsaKeyProvider);

            var principal = jwtService.ValidateRefreshToken(refreshTokenStr);
            if (principal == null)
                return null;

            var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            var userName = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            if (jti == null || userName == null)
                return null;

            var storedToken = _refreshTokenStore.Get(jti);
            if (storedToken == null)
                return null;

            // Token reuse detection: if this token was already revoked,
            // someone might have stolen the token. Revoke the entire family.
            if (storedToken.IsRevoked)
            {
                _refreshTokenStore.RevokeFamily(storedToken.FamilyId);
                return null;
            }

            // Revoke the current refresh token (single use)
            _refreshTokenStore.Revoke(jti);

            // Issue new token pair with the same family
            var (newAccessToken, _) = jwtService.GenerateAccessToken(userName, "1234");
            var (newRefreshToken, newRefreshJti, newRefreshExpires) = jwtService.GenerateRefreshToken(userName);

            _refreshTokenStore.Store(newRefreshJti, storedToken.FamilyId, userName, newRefreshExpires);

            return new AuthenticatedToken
            {
                AccessToken = tokenHandler.WriteToken(newAccessToken),
                RefreshToken = tokenHandler.WriteToken(newRefreshToken)
            };
        }
    }
}
