using Org.BouncyCastle.Asn1.X509;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;
using Ydb.Sdk.Table;
using Ydb.Sdk.Value;
using static System.Formats.Asn1.AsnWriter;

namespace NAuthAPI
{
    public class AppContext
    {
        private readonly TableClient _client;
        readonly string _issuer;
        public AppContext(TableClient client, string issuer)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client), "Клиент доступа к БД не может быть null");
            _issuer = issuer;
        }
        #region Account Data
        public async Task<Account?> GetAccountByUsername(string username)
        {
            return await GetAccount(username, Queries.GetIdentityUsername);
        }
        public async Task<Account?> GetAccountById(string id)
        {
            return await GetAccount(id, Queries.GetIdentityId);
        }
        public async Task<Account?> GetAccount(string claim, string query)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(claim) }
            };
            var queryResponse = await ExecuteQuery(query, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];

            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Upn, row["username"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.Surname, row["surname"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.Name, row["name"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.SerialNumber, row["guid"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer),
                new Claim("lastname", row["lastname"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer),
                new Claim(ClaimTypes.MobilePhone, row["phone"].GetOptionalUint64().ToString() ?? "", ClaimValueTypes.UInteger64, _issuer),
                new Claim(ClaimTypes.Email, row["email"].GetOptionalUtf8() ?? "", ClaimValueTypes.Email, _issuer),
                new Claim(ClaimTypes.Gender, row["gender"].GetOptionalUtf8() ?? "", ClaimValueTypes.String, _issuer)
            };
            string hash = row["hash"].GetOptionalUtf8() ?? "";
            string salt = row["salt"].GetOptionalUtf8() ?? "";
            bool blocked = row["blocked"].GetOptional()?.GetBool() ?? true;
            byte attempt = row["attempt"].GetOptionalUint8() ?? 0;

            ClaimsIdentity identity = new(claims, "Bearer");

            Account account = new(identity, hash, salt, blocked, attempt);
            return account;
        }
        public async Task<bool> IsUsernameExists(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUsername, parameters);
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
        #endregion
        #region Account Management
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
                { "$salt", YdbValue.MakeUtf8(account.Salt) },
                { "$gender", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.Gender)?.Value ?? "") },
                { "$email", YdbValue.MakeUtf8(account.Identity.FindFirst(ClaimTypes.Email)?.Value ?? "") },
                { "$phone", YdbValue.MakeUint64(ulong.Parse(account.Identity.FindFirst(ClaimTypes.MobilePhone)?.Value ?? "0")) },
                { "$attempt", YdbValue.MakeUint8(account.Attempts) },
                { "$blocked", YdbValue.MakeUint8(account.IsBlocked ? (byte)1 : (byte)0) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateAccount, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> UpdateAccount(string username, Dictionary<string, string> claims)
        {
            if (claims.Count == 0) return true;
            StringBuilder queryBuilder = new();
            StringBuilder bindings = new();
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(username) }
            };
            queryBuilder.AppendLine($"DECLARE $id AS Utf8;");
            var stringScopes = "surname name lastname email gender".Split(" ");
            var uint64Scopes = "phone".Split(" ");
            foreach (var record in claims)
            {
                if (stringScopes.Contains(record.Key))
                {
                    parameters.Add($"${record.Key}", YdbValue.MakeUtf8(record.Value));
                    queryBuilder.AppendLine($"DECLARE ${record.Key} AS Utf8;");
                }
                else if (uint64Scopes.Contains(record.Key))
                {
                    parameters.Add($"${record.Key}", YdbValue.MakeUint64(ulong.Parse(record.Value)));
                    queryBuilder.AppendLine($"DECLARE ${record.Key} AS Uint64;");
                }
                else
                {
                    continue;
                }
                bindings.Append($"{record.Key} = ${record.Key}, ");
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
            var response = await ExecuteQuery(queryBuilder.ToString(), parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteAccount(string user)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) }
            };
            var response = await ExecuteQuery(Queries.DeleteAccount, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Key Management
        public async Task<bool> CreateAuthKey(string keyId, string audience, string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) },
                { "$user", YdbValue.MakeUtf8(username) },
                { "$audience", YdbValue.MakeUtf8(audience) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateSignIn, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteAuthKey(string keyId)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) }
            };
            var queryResponse = await ExecuteQuery(Queries.DeleteKey, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteUserAuthKeys(string user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$user", YdbValue.MakeUtf8(user) }
            };
            var queryResponse = await ExecuteQuery(Queries.DeleteUserKeys, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> IsKeyValid(string keyId)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetKey, parameters);
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
                { "$user", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUserKeys, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                List<string> keys = new();
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
        #endregion
        #region Client Management
        public async Task<Client?> GetClient(string name)
        {
            var parameters = new Dictionary<string, YdbValue>() 
            {
                { "$id", YdbValue.MakeUtf8(name) }
            };
            var response = await ExecuteQuery(Queries.GetClient, parameters);
            var sets = response.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];
            Client client = new(
                row["name"].GetOptionalUtf8(),
                row["secret"].GetOptionalUtf8(),
                row["valid"].GetOptional()?.GetBool() ?? false,
                row["implement"].GetOptional()?.GetBool() ?? false,
                (row["scopes"].GetOptionalUtf8() ?? "").Split(" ").ToList());

            return client;
        }
        #endregion
        #region User Security
        public async Task<bool> NullAttempt(string user)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) }
            };
            var response = await ExecuteQuery(Queries.NullAttempt, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> AddAttempt(string user)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) }
            };
            var response = await ExecuteQuery(Queries.AddAttempt, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> SetPasswordHash(string id, string hash)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(id) },
                { "$hash", YdbValue.MakeUtf8(hash) }
            };
            var response = await ExecuteQuery(Queries.SetPasswordHash, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Data Accept 
        public async Task<bool> CreateAccept(string user_id, string client, string scope)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user_id", YdbValue.MakeUtf8(user_id) },
                { "$client", YdbValue.MakeUtf8(client) },
                { "$scope", YdbValue.MakeUtf8(scope) },
                { "$datetime", YdbValue.MakeDatetime(DateTime.Now) },
            };
            var response = await ExecuteQuery(Queries.CreateAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<List<string>> GetAccepts(string user_id, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user_id", YdbValue.MakeUtf8(user_id) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(Queries.SelectAccept, parameters);
            var sets = response.Result.ResultSets;
            List<string> result = new List<string>();
            if (sets.Count > 0)
            {
                foreach (var row in sets[0].Rows)
                {
                    result.Add(row["scope"].GetOptionalUtf8() ?? "");
                }
            }
            return result;
        }
        public async Task<bool> DeleteAccept(string user_id, string client, string type)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user_id", YdbValue.MakeUtf8(user_id) },
                { "$client", YdbValue.MakeUtf8(client) },
                { "$type", YdbValue.MakeUtf8(type) }
            };
            var response = await ExecuteQuery(Queries.DeleteAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteAccept(string user_id, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user_id", YdbValue.MakeUtf8(user_id) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(Queries.DeleteAllAccept, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Data Management
        public async Task<List<Claim>> GetClaims(IEnumerable<string> claims, string id)
        {
            List<YdbValue> list = new List<YdbValue>();
            foreach (string claim in claims) list.Add(YdbValue.MakeUtf8(claim));
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(id) },
                { "$list", YdbValue.MakeList(list) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetClaims, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count > 0)
            {
                List<Claim> keys = new();
                foreach (var row in sets[0].Rows)
                {
                    string type = row["type"].GetOptionalUtf8() ?? "";
                    string value = row["value"].GetOptionalUtf8() ?? "";
                    string issuer = row["issuer"].GetOptionalUtf8() ?? "";
                    if (!string.IsNullOrEmpty(type))
                    {
                        keys.Add(new Claim(type, value, ClaimValueTypes.String, issuer));
                    }
                }
                return keys;
            }
            else
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            
        }
        public async Task<bool> SetClaim(string id, string issuer, string type, string value)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(id) },
                { "$issuer", YdbValue.MakeUtf8(issuer) },
                { "$type", YdbValue.MakeUtf8(type) },
                { "$value", YdbValue.MakeUtf8(value) },
            };
            var response = await ExecuteQuery(Queries.SetClaim, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
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
}
