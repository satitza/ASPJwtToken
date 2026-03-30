namespace JwtTokenExample.Services.Soap;

using System.ServiceModel;

[ServiceContract(Namespace = "http://learnwebservices.com/services/hello")]
public interface ISoapService
{
    [OperationContract]
    HelloResponse Hello(HelloRequest request);
}

[MessageContract(WrapperName = "HelloRequest")]
public class HelloRequest
{
    [MessageBodyMember] public string Name { get; set; }
}

[MessageContract(WrapperName = "HelloResponse")]
public class HelloResponse
{
    [MessageBodyMember] public string Greeting { get; set; }
}

public class SoapService : ISoapService
{
    public HelloResponse Hello(HelloRequest request)
    {
        // Add your logic to handle the HelloRequest
        // Here, we'll simply return a response with a greeting
        return new HelloResponse { Greeting = $"Hello, {request.Name}!" };
    }
}