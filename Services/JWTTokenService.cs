using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtTokenExample.Configuration;
using JwtTokenExample.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenExample.Services
{
    public class JWTTokenService
    {
        readonly JwtSecurityTokenHandler _tokenHandler;

        public JWTTokenService(JwtSecurityTokenHandler tokenHandler)
        {
            _tokenHandler = tokenHandler;
        }

        public SecurityToken GenerateAccessToken(UserAuthenticationModel user)
        {
            try
            {
                var secretKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes("JwtSettings:AccessTokenSecretKey".GetConfigurationValue()));
                var accessTokenSecurityObject = _tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Email, user.UserName),
                        new Claim("user_id", "1234", ClaimValueTypes.Integer),
                    }),
                    Expires = DataTypeHelper.GetDateTimeUTCPlus7().AddMinutes(1),
                    Audience = "JwtSettings:Audience".GetConfigurationValue(),
                    Issuer = "JwtSettings:Issuer".GetConfigurationValue(),
                    SigningCredentials =
                        new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256)
                });

                return accessTokenSecurityObject;
            }
            catch (Exception e)
            {
                throw;
            }
        }

        public SecurityToken GenerateRefreshToken(UserAuthenticationModel user)
        {
            try
            {
                var secretKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes("JwtSettings:RefreshTokenSecretKey".GetConfigurationValue()));
                var accessTokenSecurityObject = _tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                    }),
                    Expires = DataTypeHelper.GetDateTimeUTCPlus7().AddDays(1),
                    Audience = "JwtSettings:Audience".GetConfigurationValue(),
                    Issuer = "JwtSettings:Issuer".GetConfigurationValue(),
                    SigningCredentials =
                        new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256)
                });

                return accessTokenSecurityObject;
            }
            catch (Exception e)
            {
                throw;
            }
        }
    }
}