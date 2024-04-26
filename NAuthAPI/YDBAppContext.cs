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
        public async Task<bool> CreateTables()
        {
            string pathPrefix = $"PRAGMA TablePathPrefix = \"{_path}/NAuth/{_stage}\";";
            var response = await client.SessionExec(async session =>
            {
                return await session.ExecuteSchemeQuery(pathPrefix + YdbQueries.CreateAllTables);
            });
            return response.Status.IsSuccess;
        }
        public async Task<bool> DropTables()
        {
            string pathPrefix = $"PRAGMA TablePathPrefix = \"{_path}/NAuth/{_stage}\";";
            var response = await client.SessionExec(async session =>
            {
                return await session.ExecuteSchemeQuery(pathPrefix + YdbQueries.DropAllTables);
            });
            return response.Status.IsSuccess;
        }
        #region Account Data
        public async Task<Account?> GetAccount(string username)
        {
            if (string.IsNullOrEmpty(username)) return null;
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.GetAccount, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new Exception("Пустой ответ от базы данных");
            }
            if (sets[0].Rows.Count == 0) return null;
            
            var row = sets[0].Rows[0];

            string id = row["id"].GetUtf8();
            string hash = row["hash"].GetUtf8();
            string salt = row["salt"].GetUtf8();
            bool blocked = row["blocked"].GetBool();
            string grant = row["grant"].GetUtf8();
            DateTime access = row["access"].GetOptionalTimestamp() ?? DateTime.MaxValue;

            Account account = new(id, username, Convert.FromBase64String(hash), Convert.FromBase64String(salt), blocked, grant, access);
            return account;
        }
        public async Task<User?> GetUser(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(id) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.GetUser, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0) return null;
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];

            string? surname = row["surname"].GetOptionalUtf8();
            string? name = row["name"].GetOptionalUtf8();
            string? lastname = row["lastname"].GetOptionalUtf8();
            string? gender = row["gender"].GetOptionalUtf8();
            string? email = row["email"].GetOptionalUtf8();
            ulong? phone = row["phone"].GetOptionalUint64();

            User user = new(id, surname, name, lastname, email, phone, gender);
            return user;
        }
        public async Task<bool> IsUsernameExists(string username)
        {
            if (string.IsNullOrEmpty(username)) return false;
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$username", YdbValue.MakeUtf8(username) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.IsUserExists, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            return sets[0].Rows.Count == 1;
        }
        public async Task<bool> IsIdExists(string id)
        {
            if (string.IsNullOrEmpty(id)) return false;
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(id) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.IsIdExists, parameters);
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
                { "$email",     YdbValue.MakeOptionalUtf8(user.Email) },
                { "$id",        YdbValue.MakeUtf8(account.Id) },
                { "$username",  YdbValue.MakeUtf8(account.Username) },
                { "$surname",   YdbValue.MakeOptionalUtf8(user.Surname) },
                { "$name",      YdbValue.MakeOptionalUtf8(user.Name) },
                { "$lastname",  YdbValue.MakeOptionalUtf8(user.LastName) },
                { "$hash",      YdbValue.MakeUtf8(Convert.ToBase64String(account.Hash)) },
                { "$salt",      YdbValue.MakeUtf8(Convert.ToBase64String(account.Salt)) },
                { "$gender",    YdbValue.MakeOptionalUtf8(user.Gender) },
                { "$phone",     YdbValue.MakeOptionalUint64(user.Phone) },
                { "$blocked",   YdbValue.MakeBool(account.IsBlocked) },
                { "$grant",     YdbValue.MakeUtf8(account.Grant) },
                { "$access",    YdbValue.MakeTimestamp(account.Access) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.CreateIdentity, parameters);
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
        public async Task<bool> DeleteIdentity(string user)
        {
            if (string.IsNullOrEmpty(user)) return false;
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) }
            };
            var response = await ExecuteQuery(YdbQueries.DeleteAccount, parameters);
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
                { "$audience", YdbValue.MakeUtf8(audience) },
                { "$issued", YdbValue.MakeDatetime(DateTime.Now) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.StoreKey, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteAuthKey(string key)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(key) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.DeleteKey, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> DeleteUserAuthKeys(string user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$user", YdbValue.MakeUtf8(user) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.DeleteUserKeys, parameters);
            return queryResponse.Status.IsSuccess;
        }
        public async Task<bool> IsKeyValid(string keyId)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$id", YdbValue.MakeUtf8(keyId) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.GetKey, parameters);
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
            var queryResponse = await ExecuteQuery(YdbQueries.GetUserKeys, parameters);
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
            var response = await ExecuteQuery(YdbQueries.GetClient, parameters);
            var sets = response.Result.ResultSets;
            if (sets.Count == 0) throw new Exception("Пустой ответ от базы данных");
            if (sets[0].Rows.Count == 0) return null;

            var row = sets[0].Rows[0];
            Client client = new(
                name,
                row["secret"].GetUtf8(),
                row["valid"].GetBool(),
                row["trust"].GetBool(),
                row["scope"].GetUtf8().Split(" "),
                row["callback"].GetOptionalUtf8() ?? "");

            return client;
        }
        //TODO Create, delete, update clients
        #endregion
        #region User Security
        public async Task<List<Attempt>> GetAttempts(string user)
        {
            var parameters = new Dictionary<string, YdbValue>
            {
                { "$user", YdbValue.MakeUtf8(user) }
            };
            var queryResponse = await ExecuteQuery(YdbQueries.GetAttempts, parameters);
            var sets = queryResponse.Result.ResultSets;
            if (sets.Count == 0)
            {
                throw new Exception("Пустой ответ от базы данных");
            }

            List<Attempt> attempts = [];
            foreach(var row in sets[0].Rows)
            {
                Attempt attempt = new(row["id"].GetUtf8(), row["issued"].GetTimestamp(), row["success"].GetBool());
                attempts.Add(attempt);
            }
            return attempts;
        }
        public async Task<bool> AddAttempt(string user, bool success)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(Guid.NewGuid().ToString()) },
                { "$issued", YdbValue.MakeTimestamp(DateTime.Now) },
                { "$user", YdbValue.MakeUtf8(user) },
                { "$success", YdbValue.MakeBool(success) }
            };
            var response = await ExecuteQuery(YdbQueries.AddAttempt, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> SetPasswordHash(string id, byte[] hash)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(id) },
                { "$hash", YdbValue.MakeUtf8(Convert.ToBase64String(hash)) }
            };
            var response = await ExecuteQuery(YdbQueries.SetPasswordHash, parameters);
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
            var response = await ExecuteQuery(YdbQueries.CreateAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<List<string>> GetAccepts(string user, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(YdbQueries.SelectAccept, parameters);
            var sets = response.Result.ResultSets;
            List<string> result = [];
            if (sets.Count == 0)
            {
                throw new ApplicationException("Пустой ответ от базы данных");
            }
            foreach (var row in sets[0].Rows)
            {
                result.Add(row["scope"].GetUtf8());
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
            var response = await ExecuteQuery(YdbQueries.DeleteAccept, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteAccept(string user, string client)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$user", YdbValue.MakeUtf8(user) },
                { "$client", YdbValue.MakeUtf8(client) }
            };
            var response = await ExecuteQuery(YdbQueries.DeleteAllAccept, parameters);
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
            var queryResponse = await ExecuteQuery(YdbQueries.GetClaims, parameters);
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
        public async Task<bool> SetClaim(string user, string issuer, string scope, string value)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) },
                { "$issuer", YdbValue.MakeUtf8(issuer) },
                { "$scope", YdbValue.MakeUtf8(scope) },
                { "$value", YdbValue.MakeUtf8(value) },
            };
            var response = await ExecuteQuery(YdbQueries.SetClaim, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<bool> DeleteClaim(string user, string issuer, string scope)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$id", YdbValue.MakeUtf8(user) },
                { "$issuer", YdbValue.MakeUtf8(issuer) },
                { "$scope", YdbValue.MakeUtf8(scope) }
            };
            var response = await ExecuteQuery(YdbQueries.DeleteClaim, parameters);
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
            var response = await ExecuteQuery(YdbQueries.CreateRequest, parameters);
            return response.Status.IsSuccess;
        }
        public async Task<Request?> GetRequest(string client, string code_verifier)
        {
            var parameters = new Dictionary<string, YdbValue>()
            {
                { "$client", YdbValue.MakeUtf8(client) },
                { "$verifier", YdbValue.MakeUtf8(code_verifier) }
            };
            var response = await ExecuteQuery(YdbQueries.GetRequest, parameters);
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
            var response = await ExecuteQuery(YdbQueries.GetRequestByCode, parameters);
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
            var response = await ExecuteQuery(YdbQueries.DeleteRequest, parameters);
            return response.Status.IsSuccess;
        }
        #endregion
        public async Task<ExecuteDataQueryResponse> ExecuteQuery(string query, Dictionary<string, YdbValue> parameters)
        {
            string pathPrefix = $"PRAGMA TablePathPrefix = \"{_path}/NAuth/{_stage}\";";
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
