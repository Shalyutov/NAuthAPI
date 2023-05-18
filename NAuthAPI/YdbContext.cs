using Org.BouncyCastle.Asn1.X509;
using System;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;
using Ydb.Sdk.Table;
using Ydb.Sdk.Value;

namespace NAuthAPI
{
    public class YdbContext
    {
        private readonly TableClient _client;
        public YdbContext(TableClient client) => _client = client ?? throw new ArgumentNullException(nameof(client), "Клиент доступа к БД не может быть null");
        public async Task<Account?> GetAccount(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetIdentityQuery, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                ResultSet.Row record = sets[0].Rows[0];

                Claim upn = new Claim(ClaimTypes.Upn, username, ClaimValueTypes.String, "NAuth API");
                Claim surname = new Claim(ClaimTypes.Surname, record["surname"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, "NAuth API");
                Claim name = new Claim(ClaimTypes.Name, record["name"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, "NAuth API");
                Claim guid = new Claim(ClaimTypes.SerialNumber, record["guid"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, "NAuth API");
                string hash = record["hash"].GetOptionalUtf8() ?? "";
                string salt = record["salt"].GetOptionalUtf8() ?? "";

                List<Claim> claims = new List<Claim>() { upn, surname, name, guid };

                ClaimsIdentity identity = new ClaimsIdentity(claims, "Bearer");

                Account account = new Account(identity, hash, salt);
                return account;
            }
            else
            {
                return null;
            }
        }
        public async Task<bool> IsUsernameExists(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetIdentityQuery, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                if (sets[0].Rows.Count > 0)
                    return true;
                else
                    return false;
            }
            else
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
        }
        public async Task<bool> CreateAccount(Account account)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.SerialNumber)?.Value ?? "") },
                { "$username", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.Upn)?.Value ?? "") },
                { "$surname", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.Surname)?.Value ?? "") },
                { "$name", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.Name)?.Value ?? "") },
                { "$lastname", YdbValue.MakeUtf8(account.Identity.FindFirst("LastName")?.Value ?? "") },
                { "$hash", YdbValue.MakeUtf8(account.Hash) },
                { "$salt", YdbValue.MakeUtf8(account.Salt) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateIdentityQuery, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> CreateAuthKey(string keyId, string audience, string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) },
                { "$user", YdbValue.MakeUtf8(username) },
                { "$audience", YdbValue.MakeUtf8(audience) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateSignInQuery, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteAuthKey(string keyId)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) }
            };
            var queryResponse = await ExecuteQuery(Queries.DeleteKeyQuery, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteUserAuthKeys(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.DeleteUserKeysQuery, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> IsKeyValid(string keyId)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetKeyQuery, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                if (sets[0].Rows.Count > 0)
                    return true;
                else
                    return false;
            }
            else
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
        }
        public async Task<List<string>> GetUserKeys(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUserKeysQuery, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                List<string> keys = new List<string>();
                foreach (var row in sets[0].Rows)
                {
                    var kid = row["kid"].GetOptionalUtf8();
                    if (kid != null)
                    {
                        keys.Add(kid);
                    }
                }
                return keys;
            }
            else
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
        }
        public async Task<bool> UpdateAccount(string username, Dictionary<string, object> claims)
        {
            if (claims.Count == 0) return true;
            StringBuilder queryBuilder = new StringBuilder();
            StringBuilder bindings = new StringBuilder();
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(username) }
            };
            queryBuilder.AppendLine($"DECLARE $id AS Utf8;");
            var stringScopes = "surname name lastname email gender";
            var uint64Scopes = "phone";
            foreach (var record in claims)
            {
                if (stringScopes.Split(" ").Contains(record.Key))
                {
                    parameters.Add($"${record.Key}", YdbValue.MakeUtf8((string)record.Value));
                    queryBuilder.AppendLine($"DECLARE ${record.Key} AS Utf8;");
                    bindings.Append($"{record.Key} = ${record.Key}, ");
                }
                else if (uint64Scopes.Split(" ").Contains(record.Key))
                {
                    parameters.Add($"${record.Key}", YdbValue.MakeUint64((UInt64)record.Value));
                    queryBuilder.AppendLine($"DECLARE ${record.Key} AS Uint64;");
                    bindings.Append($"{record.Key} = ${record.Key}, ");
                }
            }
            if (bindings.Length > 1)
            {
                bindings.Remove(bindings.Length - 2, 2);//remove redundant comma
            }
            else
            {
                return true;
            }
            queryBuilder.AppendLine($"UPDATE users SET {bindings.ToString()} WHERE guid = $id");
            var queryResponse = await ExecuteQuery(queryBuilder.ToString(), parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<ExecuteDataQueryResponse> ExecuteQuery(string query, Dictionary<string, YdbValue> parameters)
        {
            var response = await _client.SessionExec(async session => 
                await session.ExecuteDataQuery(query, TxControl.BeginSerializableRW().Commit(), parameters)
            );
            if (response.Status.IsSuccess)
            {
                return (ExecuteDataQueryResponse)response;
            }
            else
            {
                throw new ApplicationException($"Запрос к базе данных не обработан: { response.Status.Issues[0].Message }");
            }
        }
    }
    class Queries
    {
        public static string GetIdentityQuery = @"
        DECLARE $id AS Utf8;
        SELECT
            hash, name, surname, guid, salt
        FROM
            users
        WHERE 
            username = $id;";
        public static string GetKeyQuery = @"
        DECLARE $id AS Utf8;
        SELECT
            kid, user, audience
        FROM
            keys
        WHERE 
            kid = $id;";
        public static string DeleteKeyQuery = @"
        DECLARE $id AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            kid = $id;";
        public static string DeleteUserKeysQuery = @"
        DECLARE $user AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            user = $user;";
        public static string GetUserKeysQuery = @"
        DECLARE $username AS Utf8;
        SELECT
            kid
        FROM
            keys
        WHERE 
            user = $user;";
        public static string UsernameQuery = @"
        DECLARE $id AS Utf8;
        SELECT
            guid
        FROM
            users
        WHERE 
            username = $id;";
        public static string CreateIdentityQuery = @"
        DECLARE $id As Utf8;
        DECLARE $username AS Utf8;
        DECLARE $surname AS Utf8;
        DECLARE $name AS Utf8;
        DECLARE $lastname AS Utf8;
        DECLARE $hash AS Utf8;
        DECLARE $salt AS Utf8;
        INSERT INTO 
            users (guid, username, surname, name, lastname, hash, salt) 
        VALUES
            ($id, $username, $surname, $name, $lastname, $hash, $salt);";
        public static string CreateSignInQuery = @"
        DECLARE $id As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $audience AS Utf8;
        INSERT INTO 
            keys (kid, user, audience) 
        VALUES
            ($id, $user, $audience);";

    }
}
