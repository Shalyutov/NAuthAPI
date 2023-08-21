namespace NAuthAPI
{
    public class AuthNames
    {
        public string Issuer;
        public string Audience;
        public AuthNames(string issuer, string audience)
        {
            Issuer = issuer;
            Audience = audience;
        }
        public AuthNames()
        {
            Issuer = "NAuth API";
            Audience = "NAuth App";
        }
    }
}
