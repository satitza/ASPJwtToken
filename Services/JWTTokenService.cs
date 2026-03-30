using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtTokenExample.Configuration;
using JwtTokenExample.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenExample.Services
{
    public class JWTTokenService
    {
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

        public (SecurityToken Token, string Jti, DateTime ExpiresAt) GenerateRefreshToken(string userName)
        {
            var jti = Guid.NewGuid().ToString();
            var expiresAt = DataTypeHelper.GetDateTimeUTCPlus7().AddDays(1);
            var signingKey = new RsaSecurityKey(_rsaKeyProvider.PrivateKey);

            var token = _tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userName),
                    new Claim(JwtRegisteredClaimNames.Jti, jti),
                    new Claim("token_type", "refresh"),
                }),
                Expires = expiresAt,
                Audience = "JwtSettings:Audience".GetConfigurationValue(),
                Issuer = "JwtSettings:Issuer".GetConfigurationValue(),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
            });

            return (token, jti, expiresAt);
        }

        public ClaimsPrincipal? ValidateRefreshToken(string token)
        {
            var validationKey = new RsaSecurityKey(_rsaKeyProvider.PublicKey);

            // Disable .NET's auto-mapping of JWT claims (e.g. "sub" → ClaimTypes.NameIdentifier)
            // so we can read claims by their original JWT names like "sub", "jti", etc.
            _tokenHandler.InboundClaimTypeMap.Clear();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "JwtSettings:Issuer".GetConfigurationValue(),
                ValidateAudience = true,
                ValidAudience = "JwtSettings:Audience".GetConfigurationValue(),
                ValidateLifetime = true,
                LifetimeValidator = (notBefore, expires, securityToken, parameters) =>
                    expires > DataTypeHelper.GetDateTimeUTCPlus7(),
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = validationKey
            };

            try
            {
                return _tokenHandler.ValidateToken(token, validationParameters, out _);
            }
            catch
            {
                return null;
            }
        }
    }
}
