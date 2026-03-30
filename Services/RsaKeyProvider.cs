using System.Security.Cryptography;

namespace JwtTokenExample.Services
{
    public class RsaKeyProvider
    {
        private readonly RSA _privateKey;
        private readonly RSA _publicKey;

        public RSA PrivateKey => _privateKey;
        public RSA PublicKey => _publicKey;

        public RsaKeyProvider(IConfiguration configuration, IWebHostEnvironment environment)
        {
            var keysDir = Path.Combine(environment.ContentRootPath, "Keys");
            var privatePath = configuration.GetValue<string>("JwtSettings:PrivateKeyPath")
                              ?? Path.Combine(keysDir, "private.pem");
            var publicPath = configuration.GetValue<string>("JwtSettings:PublicKeyPath")
                             ?? Path.Combine(keysDir, "public.pem");

            if (!File.Exists(privatePath) || !File.Exists(publicPath))
            {
                Directory.CreateDirectory(keysDir);
                GenerateKeyPair(privatePath, publicPath);
            }

            _privateKey = RSA.Create();
            _privateKey.ImportFromPem(File.ReadAllText(privatePath));

            _publicKey = RSA.Create();
            _publicKey.ImportFromPem(File.ReadAllText(publicPath));
        }

        private static void GenerateKeyPair(string privatePath, string publicPath)
        {
            using var rsa = RSA.Create(2048);

            var privateKeyPem = rsa.ExportRSAPrivateKey();
            var publicKeyPem = rsa.ExportRSAPublicKey();

            File.WriteAllText(privatePath,
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                Convert.ToBase64String(privateKeyPem, Base64FormattingOptions.InsertLineBreaks) +
                "\n-----END RSA PRIVATE KEY-----");

            File.WriteAllText(publicPath,
                "-----BEGIN RSA PUBLIC KEY-----\n" +
                Convert.ToBase64String(publicKeyPem, Base64FormattingOptions.InsertLineBreaks) +
                "\n-----END RSA PUBLIC KEY-----");
        }
    }
}
