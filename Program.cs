using JwtTokenExample.Configuration;
using JwtTokenExample.Services;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
DataTypeHelper.SetConfiguration(builder.Configuration);

// Initialize RSA key provider (generates keys if not exist)
var rsaKeyProvider = new RsaKeyProvider(builder.Configuration, builder.Environment);
builder.Services.AddSingleton(rsaKeyProvider);

// config jwt with RSA public key validation
builder.Services.ConfigureJwt(rsaKeyProvider);

// config swagger
builder.Services.ConfigureSwagger();

// config dependency injection
builder.Services.ConfigureDependencyInjection();

builder.Services.AddMvc(config =>
{
    config.InputFormatters.Insert(0, new XDocumentInputFormatter());
}).SetCompatibilityVersion(CompatibilityVersion.Latest).AddXmlSerializerFormatters();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
