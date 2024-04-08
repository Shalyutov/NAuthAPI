using Org.BouncyCastle.Asn1.X509;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;
using Vault.Api;
using Ydb.Sdk.Services.Table;
using Ydb.Sdk.Value;
using static System.Formats.Asn1.AsnWriter;
using static Yandex.Cloud.Mdb.Clickhouse.V1.Config.ClickhouseConfig.Types.ExternalDictionary.Types.Structure.Types;

namespace NAuthAPI
{
    public class YDBAppContext(TableClient client, string stage, string path) : IAppContext
    {
        private static readonly List<string> validStages = ["Development", "Production", "Test"];
        private readonly string _stage = validStages.Contains(stage) ? stage : throw new Exception("Неопознанная среда выполнения");
        private readonly string _path = path;
        private readonly TableClient _client = client ?? throw new ArgumentNullException(nameof(client), "Клиент доступа к БД не может быть null");
        #region Account Data
        public async Task<Account?> GetAccount(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUser, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;
            
            var row = sets[0].Rows[0];

            string id = row["id"].GetUtf8();
            string hash = row["hash"].GetUtf8();
            string salt = row["salt"].GetUtf8();
            bool blocked = row["blocked"].GetBool();
            byte attempt = row["attempt"].GetUint8();
            string grant = row["grant"].GetUtf8();
            DateTime access = row["access"].GetOptionalTimestamp() ?? DateTime.MaxValue;

            Account account = new(id, username, Convert.FromBase64String(hash), Convert.FromBase64String(salt), blocked, attempt, grant, access);
            return account;
        }
        public async Task<User?> GetUser(string id)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(id) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUser, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];

            string surname = row["surname"].GetUtf8();
            string name = row["name"].GetUtf8();
            string lastname = row["lastname"].GetUtf8();
            string gender = row["gender"].GetUtf8();
            string email = row["email"].GetUtf8();
            ulong phone = row["phone"].GetUint64();

            User user = new(id, surname, name, lastname, email, phone, gender);
            return user;
        }
        public async Task<bool> IsUsernameExists(string username)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(Queries.IsUserExists, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            return sets[0].Rows.Count == 1;
        }
        #endregion
        #region Account Management
        public async Task<bool> CreateIdentity(Account account, User user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id",        YdbValue.MakeUtf8(account.Id) },
                { "$username",  YdbValue.MakeUtf8(account.Username) },
                { "$surname",   YdbValue.MakeOptionalUtf8(user.Surname) },
                { "$name",      YdbValue.MakeOptionalUtf8(user.Name) },
                { "$lastname",  YdbValue.MakeOptionalUtf8(user.LastName) },
                { "$hash",      YdbValue.MakeUtf8(Convert.ToBase64String(account.Hash)) },
                { "$salt",      YdbValue.MakeUtf8(Convert.ToBase64String(account.Salt)) },
                { "$gender",    YdbValue.MakeOptionalUtf8(user.Gender) },
                { "$email",     YdbValue.MakeOptionalUtf8(user.Email) },
                { "$phone",     YdbValue.MakeOptionalUint64(user.Phone) },
                { "$attempt",   YdbValue.MakeUint8(account.Attempts) },
                { "$blocked",   YdbValue.MakeBool(account.IsBlocked) },
                { "$grant",     YdbValue.MakeUtf8(account.Grant) },
                { "$access",    YdbValue.MakeTimestamp(account.Access) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateIdentity, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> UpdateUser(string id, Dictionary<string, string> claims)
        {
            if (claims.Count == 0) return true;
            StringBuilder queryBuilder = new();
            StringBuilder bindings = new();
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(id) }
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
            queryBuilder.AppendLine($"UPDATE users SET {bindings.ToString()} WHERE id = $id");
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
        public async Task<bool> CreateAuthKey(string key, string audience, string user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(key) },
                { "$user", YdbValue.MakeUtf8(user) },
                { "$audience", YdbValue.MakeUtf8(audience) }
            };
            var queryResponse = await ExecuteQuery(Queries.CreateSignIn, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteAuthKey(string key)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(key) }
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
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            return sets[0].Rows.Count > 0;
        }
        public async Task<List<string>> GetUserKeys(string user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$user", YdbValue.MakeUtf8(user) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetUserKeys, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            List<string> keys = [];
            foreach (var row in sets[0].Rows)
            {
                var id = row["id"].GetUtf8();
                if (id != null)
                {
                    keys.Add(id);
                }
            }
            return keys;
        }
        #endregion
        #region Client Management
        public async Task<Client?> GetClient(string name)
        {
            var parameters = new Dictionary<string, YdbValue>() 
            {
                { "$name", YdbValue.MakeUtf8(name) }
            };
            var response = await ExecuteQuery(Queries.GetClient, parameters);
            var sets = response.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];
            Client client = new(
                row["name"].GetUtf8(),
                row["secret"].GetUtf8(),
                row["valid"].GetBool(),
                row["trust"].GetBool(),
                row["scopes"].GetUtf8().Split(" "),
                row["callback"].GetOptionalUtf8() ?? "");

            return client;
        }
        //TODO Create, delete, update clients
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
        public async Task<bool> SetPasswordHash(string id, byte[] hash)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(id) },
                { "$hash", YdbValue.MakeUtf8(Convert.ToBase64String(hash)) }
            };
            var response = await ExecuteQuery(Queries.SetPasswordHash, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Data Accept 
        public async Task<bool> CreateAccept(string user, string client, string scope)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) },
                { "$scope", YdbValue.MakeUtf8(scope) },
                { "$issued", YdbValue.MakeDatetime(DateTime.Now) },
            };
            var response = await ExecuteQuery(Queries.CreateAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<List<string>> GetAccepts(string user, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(Queries.SelectAccept, parameters);
            var sets = response.Result.ResultSets;
            List<string> result = [];
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            foreach (var row in sets[0].Rows)
            {
                result.Add(row["scope"].GetOptionalUtf8() ?? "");
            }
            return result;
        }
        public async Task<bool> DeleteAccept(string user, string client, string type)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) },
                { "$scope", YdbValue.MakeUtf8(type) }
            };
            var response = await ExecuteQuery(Queries.DeleteAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteAccept(string user, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(Queries.DeleteAllAccept, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Data Management
        public async Task<Dictionary<string, string>> GetClaims(IEnumerable<string> claimTypes, string user)
        {
            List<YdbValue> list = [];
            foreach (string claim in claimTypes) list.Add(YdbValue.MakeUtf8(claim));
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$list", YdbValue.MakeList(list) }
            };
            var queryResponse = await ExecuteQuery(Queries.GetClaims, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            Dictionary<string, string> claims = [];
            foreach (var row in sets[0].Rows)
            {
                string type = row["type"].GetUtf8();
                string value = row["value"].GetUtf8();
                if (!string.IsNullOrEmpty(type))
                {
                    claims.Add(type, value);
                }
            }
            return claims;
        }
        public async Task<bool> SetClaim(string user, string issuer, string type, string value)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) },
                { "$issuer", YdbValue.MakeUtf8(issuer) },
                { "$type", YdbValue.MakeUtf8(type) },
                { "$value", YdbValue.MakeUtf8(value) },
            };
            var response = await ExecuteQuery(Queries.SetClaim, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteClaim(string user, string issuer, string type)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) },
                { "$issuer", YdbValue.MakeUtf8(issuer) },
                { "$type", YdbValue.MakeUtf8(type) }
            };
            var response = await ExecuteQuery(Queries.DeleteClaim, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        #region Authorization Management
        public async Task<bool> CreateRequest(Request request)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(request.User) },
                { "$client", YdbValue.MakeUtf8(request.Client) },
                { "$verifier", YdbValue.MakeUtf8(request.Verifier) },
                { "$scope", YdbValue.MakeUtf8(request.Scope) },
                { "$code", YdbValue.MakeUtf8(request.Code) },
                { "$issued", YdbValue.MakeDatetime(DateTime.Now) }
            };
            var response = await ExecuteQuery(Queries.CreateRequest, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<Request?> GetRequest(string client, string code_verifier)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$client", YdbValue.MakeUtf8(client) },
                { "$verifier", YdbValue.MakeUtf8(code_verifier) }
            };
            var response = await ExecuteQuery(Queries.GetRequest, parameters);
            var sets = response.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new Exception("Пустой ответ от базы данных");
            }
            if (sets[0].Rows.Count == 0)
            {
                return null;
            }
            var row = sets[0].Rows[0];
            Request request = new()
            {
                Client = row["client"].GetUtf8(),
                Scope = row["scope"].GetUtf8(),
                Code = row["code"].GetUtf8(),
                Verifier = row["verifier"].GetUtf8(),
                User = row["user"].GetUtf8(),
                Issued = row["issued"].GetOptionalDatetime() ?? DateTime.MinValue,
            };
            return request;

        }
        public async Task<Request?> GetRequestByCode(string code)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$code", YdbValue.MakeUtf8(code) }
            };
            var response = await ExecuteQuery(Queries.GetRequestByCode, parameters);
            var sets = response.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new Exception("Пустой ответ от базы данных");
            }
            if (sets[0].Rows.Count == 0)
            {
                return null;
            }
            var row = sets[0].Rows[0];
            Request request = new()
            {
                Client = row["client"].GetUtf8(),
                Scope = row["scope"].GetUtf8(),
                Code = row["code"].GetUtf8(),
                Verifier = row["verifier"].GetUtf8(),
                User = row["user"].GetUtf8(),
                Issued = row["issued"].GetOptionalDatetime() ?? DateTime.MinValue,
            };
            return request;
        }
        public async Task<bool> DeleteRequest(string code)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$code", YdbValue.MakeUtf8(code) }
            };
            var response = await ExecuteQuery(Queries.DeleteRequest, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        public async Task<ExecuteDataQueryResponse> ExecuteQuery(string query, Dictionary<string, YdbValue> parameters)
        {
            string pathPrefix = $"PRAGMA TablePathPrefix = \"{_path}/nauth/{_stage}\"";
            var response = await _client.SessionExec(async session => 
                await session.ExecuteDataQuery(pathPrefix + query, TxControl.BeginSerializableRW().Commit(), parameters)
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
