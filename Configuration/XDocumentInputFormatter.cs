using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Formatters;

namespace JwtTokenExample.Configuration;

public class XDocumentInputFormatter : InputFormatter, IInputFormatter, IApiRequestFormatMetadataProvider
{
    public XDocumentInputFormatter()
    {
        SupportedMediaTypes.Add("text/xml");
        SupportedMediaTypes.Add("application/xml");
    }

    protected override bool CanReadType(Type type)
    {
        if (type.IsAssignableFrom(typeof(XDocument))) return true;
        return base.CanReadType(type);
    }

    public override async Task<InputFormatterResult> ReadRequestBodyAsync(InputFormatterContext context)
    {
        var xmlDoc =
            await XDocument.LoadAsync(context.HttpContext.Request.Body, LoadOptions.None, CancellationToken.None);

        return await InputFormatterResult.SuccessAsync(xmlDoc);
    }
}