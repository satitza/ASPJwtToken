using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using JwtTokenExample.Configuration;
using JwtTokenExample.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenExample.Services
{
    public class JWTTokenService
    {
        /// <summary>
        /// Refresh token format: "rt1.{Base64Url(32 random bytes)}"
        /// - "rt1" = version prefix for format validation (reject garbage before hitting the store)
        /// - 32 bytes = 256-bit entropy (brute-force resistant)
        /// </summary>
        private const string RefreshTokenPrefix = "rt1";
        private const int RefreshTokenByteLength = 32;

        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly RsaKeyProvider _rsaKeyProvider;

        public JWTTokenService(JwtSecurityTokenHandler tokenHandler, RsaKeyProvider rsaKeyProvider)
        {
            _tokenHandler = tokenHandler;
            _rsaKeyProvider = rsaKeyProvider;
        }

        public (SecurityToken Token, string Jti) GenerateAccessToken(string userName, string userId)
        {
            var jti = Guid.NewGuid().ToString();
            var signingKey = new RsaSecurityKey(_rsaKeyProvider.PrivateKey);

            var token = _tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userId),
                    new Claim(JwtRegisteredClaimNames.Email, userName),
                    new Claim(JwtRegisteredClaimNames.Jti, jti),
                    new Claim("user_id", userId, ClaimValueTypes.String),
                }),
                Expires = DataTypeHelper.GetDateTimeUTCPlus7().AddMinutes(1),
                Audience = "JwtSettings:Audience".GetConfigurationValue(),
                Issuer = "JwtSettings:Issuer".GetConfigurationValue(),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
            });

            return (token, jti);
        }

        /// <summary>
        /// Generate a cryptographically secure opaque refresh token.
        /// Format: "rt1.{Base64Url(32 bytes)}" — NOT a JWT.
        /// Returns raw token (for client) and SHA-256 hash (for storage).
        /// </summary>
        public (string RawToken, string TokenHash, DateTime ExpiresAt) GenerateRefreshToken()
        {
            var expiresAt = DataTypeHelper.GetDateTimeUTCPlus7().AddDays(1);

            var randomBytes = RandomNumberGenerator.GetBytes(RefreshTokenByteLength);
            var rawToken = $"{RefreshTokenPrefix}.{Base64UrlEncode(randomBytes)}";
            var tokenHash = RefreshTokenStore.HashToken(rawToken);

            return (rawToken, tokenHash, expiresAt);
        }

        /// <summary>
        /// Validate refresh token format WITHOUT hitting the store.
        /// Rejects malformed tokens early (timing-safe, no DB round-trip).
        /// </summary>
        public static bool ValidateRefreshTokenFormat(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return false;

            // Must start with "rt1."
            if (!token.StartsWith($"{RefreshTokenPrefix}.", StringComparison.Ordinal))
                return false;

            var payload = token.AsSpan(RefreshTokenPrefix.Length + 1);

            // Base64Url of 32 bytes = 43 chars (no padding)
            if (payload.Length != 43)
                return false;

            // Validate all chars are valid Base64Url
            foreach (var c in payload)
            {
                if (!IsBase64UrlChar(c))
                    return false;
            }

            return true;
        }

        private static bool IsBase64UrlChar(char c)
        {
            return c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
