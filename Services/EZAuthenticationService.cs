using System.IdentityModel.Tokens.Jwt;
using JwtTokenExample.Configuration;
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
            var (rawRefreshToken, refreshHash, refreshExpires) = jwtService.GenerateRefreshToken();

            var familyId = Guid.NewGuid().ToString();
            _refreshTokenStore.Store(refreshHash, familyId, user.UserName!, refreshExpires);

            return new AuthenticatedToken
            {
                AccessToken = tokenHandler.WriteToken(accessToken),
                RefreshToken = rawRefreshToken
            };
        }

        public AuthenticatedToken? RefreshAccessToken(string refreshTokenStr)
        {
            var (token, _) = RefreshAccessTokenDebug(refreshTokenStr);
            return token;
        }

        public (AuthenticatedToken? Token, string? FailReason) RefreshAccessTokenDebug(string refreshTokenStr)
        {
            // Step 1: Validate format BEFORE any store lookup (cheap rejection of garbage)
            if (!JWTTokenService.ValidateRefreshTokenFormat(refreshTokenStr))
                return (null, "Step 1 FAILED: Invalid refresh token format. "
                    + "Token must match pattern 'rt1.{Base64Url(32 bytes)}'.");

            // Step 2: Hash the token and look up in store
            var tokenHash = RefreshTokenStore.HashToken(refreshTokenStr);
            var storedToken = _refreshTokenStore.Get(tokenHash);
            if (storedToken == null)
                return (null, "Step 2 FAILED: Token not found in store. "
                    + "This happens when the server was restarted (in-memory store was cleared). Login again.");

            // Step 3: Check expiration
            if (storedToken.ExpiresAt < DataTypeHelper.GetDateTimeUTCPlus7())
                return (null, $"Step 3 FAILED: Token expired at {storedToken.ExpiresAt:yyyy-MM-dd HH:mm:ss}. "
                    + $"Server time (UTC+7): {DataTypeHelper.GetDateTimeUTCPlus7():yyyy-MM-dd HH:mm:ss}");

            // Step 4: Check revocation (token theft detection)
            if (storedToken.IsRevoked)
            {
                _refreshTokenStore.RevokeFamily(storedToken.FamilyId);
                return (null, "Step 4 FAILED: Token was already REVOKED (reuse detected!). Entire token family revoked.");
            }

            // Revoke the current refresh token (single use)
            _refreshTokenStore.Revoke(tokenHash);

            // Issue new token pair with the same family
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtService = new JWTTokenService(tokenHandler, _rsaKeyProvider);

            var (newAccessToken, _) = jwtService.GenerateAccessToken(storedToken.UserName, "1234");
            var (newRawRefreshToken, newRefreshHash, newRefreshExpires) = jwtService.GenerateRefreshToken();

            _refreshTokenStore.Store(newRefreshHash, storedToken.FamilyId, storedToken.UserName, newRefreshExpires);

            return (new AuthenticatedToken
            {
                AccessToken = tokenHandler.WriteToken(newAccessToken),
                RefreshToken = newRawRefreshToken
            }, null);
        }
    }
}
