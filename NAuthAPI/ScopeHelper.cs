using Org.BouncyCastle.Tls;
using System.Globalization;
using System.Security.Claims;

namespace NAuthAPI
{
    public class ScopeHelper
    {
        readonly static string stringScopes = "username surname name lastname email gender";
        readonly static string integerScopes = "phone";
        public static List<string> Scopes { get; private set; } = [.. "username surname name lastname email gender phone".Split(" ")];

        public static string GetClaimValueType(string scope)
        {
            if (stringScopes.Contains(scope))
            {
                return ClaimValueTypes.String;
            }
            else if (integerScopes.Contains(scope))
            {
                return ClaimValueTypes.UInteger64;
            }
            else
            {
                return string.Empty;
            }
        }
    }
}
