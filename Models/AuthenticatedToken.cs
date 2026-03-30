namespace JwtTokenExample.Models
{
    public class AuthenticatedToken
    {
        public string? AccessToken { get; set; }

        public string? RefreshToken { get; set; }
    }
}
