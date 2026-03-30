using JwtTokenExample.Services;
using JwtTokenExample.Services.Soap;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace JwtTokenExample.Configuration
{
    public static class Extension
    {
        public static void ConfigureJwt(this IServiceCollection services, RsaKeyProvider rsaKeyProvider)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    var validationKey = new RsaSecurityKey(rsaKeyProvider.PublicKey);

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
                        IssuerSigningKey = validationKey,
                        ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
                    };

                    // When access token expires, check for refresh token cookie
                    // and return a hint header so the browser knows to call /refresh
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception is SecurityTokenExpiredException)
                            {
                                context.Response.Headers.Add("X-Token-Expired", "true");
                            }
                            return Task.CompletedTask;
                        }
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
            services.AddSingleton<RefreshTokenStore>();
            services.AddSingleton<IEZAuthenticationService, EZAuthenticationService>();
            services.AddSingleton<ISoapService, SoapService>();
        }
    }
}
