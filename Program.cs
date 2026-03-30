using JwtTokenExample.Configuration;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
DataTypeHelper.SetConfiguration(builder.Configuration);

// Add services to the container.

// config jwt
builder.Services.ConfigureJwt();

// config swagger
builder.Services.ConfigureSwagger();

// config dependency injection
builder.Services.ConfigureDependencyInjection();

builder.Services.AddMvc(config =>
{
    config.InputFormatters.Insert(0, new XDocumentInputFormatter());
}).SetCompatibilityVersion(CompatibilityVersion.Latest).AddXmlSerializerFormatters();

//builder.Services.AddControllers();


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
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