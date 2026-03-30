using System.Text;
using JwtTokenExample.Services;
using JwtTokenExample.Services.Soap;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace JwtTokenExample.Configuration
{
    public static class Extension
    {
        public static void ConfigureJwt(this IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "JwtSettings:Issuer".GetConfigurationValue(),
                        ValidateAudience = true,
                        ValidAudience = "JwtSettings:Audience".GetConfigurationValue(),
                        ValidateLifetime = true,
                        LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                            expires > DataTypeHelper.GetDateTimeUTCPlus7(),
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey =
                            new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes("JwtSettings:AccessTokenSecretKey"
                                    .GetConfigurationValue()))
                    };
                });
        }

        public static void ConfigureSwagger(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "API",
                    Version = "v1",
                    Description = "EZBuyer",
                    Contact = new OpenApiContact
                    {
                        Name = "Swagger API"
                    },
                });
                c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] { }
                    }
                });
            });
        }

        public static void ConfigureDependencyInjection(this IServiceCollection services)
        {
            services.AddSingleton<IEZAuthenticationService, EZAuthenticationService>();
            services.AddSingleton<ISoapService, SoapService>();
        }
    }
}