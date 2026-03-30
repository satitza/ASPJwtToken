using System.Text;
using JwtTokenExample.Services.Soap;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenExample.Controllers.Soap;

[ApiController]
[Route("[controller]")]
public class SoapController : Controller
{
    private readonly ISoapService _soapService;

    public SoapController(ISoapService soapService)
    {
        _soapService = soapService;
    }

    /*[HttpPost("hello")]
    [Produces("text/xml")]
    [Consumes("text/xml")]
    public async Task<IActionResult> PostTextXML()
    {
        string xml;
        using (System.IO.StreamReader reader = new System.IO.StreamReader(Request.Body, Encoding.UTF8))
        {
            xml = await reader.ReadToEndAsync();
        }

        return Ok(xml);
    }*/
    
    [HttpPost("hello")]
    [Produces("text/xml")]
    //[Consumes("text/xml")]
    [Consumes("application/soap+xml")]
    public async Task<IActionResult> PostTextXML([FromBody] HelloRequest request)
    {
        var response = _soapService.Hello(request);
        return Ok(response);
    }
}