using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using NAuthAPI;
using Ydb.Sdk.Services.Table;
using Ydb.Sdk.Yc;
using Ydb.Sdk;
using Ydb.Sdk.Auth;
using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf.Collections;
namespace NAuthTest
{
    [TestClass]
    public class AppContextTest()
    {
        static YDBAppContext db;
        static Driver driver;
        static TableClient tableClient;
        static ServiceAccountProvider provider;

        [ClassInitialize]
        public static async Task Initialize(TestContext testContext)
        {
            string endpoint = "grpcs://ydb.serverless.yandexcloud.net:2135";
            string databasePath = "/ru-central1/b1gb8mvbo8og4g8184q8/etn026pjpjqev1v6fneq";
            provider = new("key.json");
            await provider.Initialize();
            var config = new DriverConfig(endpoint, databasePath, provider);
            driver = new Driver(config);
            await driver.Initialize();
            tableClient = new TableClient(driver, new TableClientConfig());
            db = new YDBAppContext(tableClient, "Test", databasePath);

            List<string> tables = ["users", "accounts", "attempts", "scopes", "clients", "verify", "accepts", "claims", "requests", "keys"];
            int count = 0;
            foreach (string tableName in tables)
            {
                var table = await tableClient.DescribeTable($"NAuth/Test/{tableName}");
                Assert.IsNotNull(table);
                if (!table.Status.IsSuccess) count++;
            }
            if (count == 10)
            {
                Assert.IsTrue(await db.CreateTables());
            }
        }
        [TestInitialize]
        public void TestInitialize()
        {
            Assert.IsNotNull(db);
            Assert.IsNotNull(tableClient);
        }
        public static IEnumerable<object[]> IdentityData
        {
            get
            {
                Guid guid = Guid.Parse("302418d9-7b71-46c6-aeb4-0341a65ef2f3");
                byte[] salt = CreateRandBytes(32);
                byte[] hash = HashPassword("Ikvall.635#", guid.ToString(), salt).Result;
                Account account1 = new(guid.ToString(), "shalyutov", hash, salt, false, "user", DateTime.Now.AddYears(1));
                User user1 = new(guid.ToString(), "Шалютов", "Андрей", "Юрьевич", "shalyutov.a@ya.ru", 79226998379u, "male");

                return
                [
                    [account1, user1, true]
                ];
            }
        }
        [TestMethod("Создание учётной записи пользователя")]
        [DynamicData(nameof(IdentityData))]
        public async Task TestCreateIdentity(Account account, User user, bool expected)
        {
            if (await db.IsUsernameExists(account.Username))
            {
                Assert.IsTrue(await db.DeleteIdentity(account.Id));
            }
            Assert.AreEqual(expected, await db.CreateIdentity(account, user));
        }
        [TestMethod("Получение информации учётной записи")]
        [DataRow("shalyutov", true, DisplayName = "Действительное имя пользователя")]
        [DataRow("test", false, DisplayName = "Недействительное имя пользователя")]
        [DataRow("", false, DisplayName = "Пустое имя пользователя")]
        public async Task TestGetAccount(string username, bool exists)
        {
            if (!await db.IsUsernameExists(username) && exists)
            {
                var obj = IdentityData.First();
                Assert.IsTrue(await db.CreateIdentity((Account)obj[0], (User)obj[1]));
            }

            Account? account = await db.GetAccount(username);
            if (exists)
            {
                
                Assert.IsNotNull(account);
                Assert.AreEqual(IdentityData.First()[0] as Account, account);
            }
            else
            {
                Assert.IsNull(account);
            }
        }
        [TestMethod("Получение информации о пользователе по идентификатору")]
        [DataRow("302418d9-7b71-46c6-aeb4-0341a65ef2f3", true, DisplayName = "Существующий идентификатор")]
        [DataRow("00064624250052253", false, DisplayName = "Несуществующий идентификатор")]
        [DataRow("", false, DisplayName = "Пустой идентификатор")]
        public async Task TestGetUser(string id, bool exists)
        {
            if (!await db.IsIdExists(id) && exists)
            {
                var obj = IdentityData.First();
                Assert.IsTrue(await db.CreateIdentity((Account)obj[0], (User)obj[1]));
            }

            User? user = await db.GetUser(id);
            if (exists)
            {
                Assert.IsNotNull(user);
                Assert.AreEqual(IdentityData.First()[1] as User, user);
            }
            else
            {
                Assert.IsNull(user);
            }
        }
        [TestMethod("Удаление учётной записи по идентификатору")]
        [DataRow("302418d9-7b71-46c6-aeb4-0341a65ef2f3", true, DisplayName = "Существующий идентификатор")]
        [DataRow("00064624250052253", false, DisplayName = "Несуществующий идентификатор")]
        [DataRow("", false, DisplayName = "Пустой идентификатор")]
        public async Task TestDeleteUser(string id, bool exists)
        {
            if (!await db.IsIdExists(id) && exists)
            {
                var obj = IdentityData.First();
                Assert.IsTrue(await db.CreateIdentity((Account)obj[0], (User)obj[1]));
            }

            if (exists)
            {
                Assert.IsTrue(await db.DeleteIdentity(id));
                Assert.IsFalse(await db.IsIdExists(id));
            }
            else
            {
                Assert.IsFalse(await db.IsIdExists(id));
            }
        }
        [ClassCleanup]
        public static async Task Cleanup()
        {
            List<string> tables = ["users", "accounts", "attempts", "scopes", "clients", "verify", "accepts", "claims", "requests", "keys"];
            int count = 0;
            foreach (string tableName in tables)
            {
                var table = await tableClient.DescribeTable($"NAuth/Test/{tableName}");
                Assert.IsNotNull(table);
                if (table.Status.IsSuccess) count++;
            }
            if (count == 10)
            {
                Assert.IsTrue(await db.DropTables());

                foreach (string tableName in tables)
                {
                    var table = await tableClient.DescribeTable($"NAuth/Test/{tableName}");
                    Assert.IsNotNull(table);
                    Assert.IsFalse(table.Status.IsSuccess);
                }
            }

            tableClient?.Dispose();
            driver?.Dispose();
        }
        private static byte[] CreateRandBytes(int bytes)
        {
            var buffer = new byte[bytes];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(buffer);
            return buffer;
        }
        private static async Task<byte[]> HashPassword(string password, string id, byte[] salt)
        {
            byte[] _password = Encoding.UTF8.GetBytes(password);
            using var argon2 = new Argon2id(_password)//Recommended parameters by OWASP
            {
                DegreeOfParallelism = 1,
                MemorySize = 19456,
                Iterations = 2,
                Salt = salt,
                AssociatedData = Encoding.UTF8.GetBytes(id),
                KnownSecret = Encoding.UTF8.GetBytes("Ppdofiiennhuvygdfg29598efgj]{hijuhufrg--*+54575(*&^*^%")
            };
            var hash = await argon2.GetBytesAsync(32);

            argon2.Dispose();
            argon2.Reset();
            //argon2 = null;//Correct releasing memmory 
            GC.Collect();

            return hash;
        }
    }
}