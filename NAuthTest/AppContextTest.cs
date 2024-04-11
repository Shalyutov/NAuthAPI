using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using NAuthAPI;
using Ydb.Sdk.Services.Table;
using Ydb.Sdk.Yc;
using Ydb.Sdk;
using Ydb.Sdk.Auth;
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
        }
        [TestInitialize]
        public void TestInitialize()
        {
            Assert.IsNotNull(db);
            Assert.IsNotNull(tableClient);
        }
        [TestMethod("Создание и удаление таблиц")]
        public async Task TestTables()
        {
            Assert.IsTrue(await db.CreateTables());

            List<string> tables = ["users", "accounts", "attempts", "scopes", "clients", "verify", "accepts", "claims", "requests", "keys"];
            foreach(string tableName in tables)
            {
                var table = await tableClient.DescribeTable($"NAuth/Test/{tableName}");
                Assert.IsNotNull( table );
                table.EnsureSuccess();
                Assert.IsTrue(table.Result.Columns.Count > 0);
            }

            Assert.IsTrue(await db.DropTables());
        }
        [ClassCleanup]
        public static void Cleanup()
        {
            tableClient?.Dispose();
            driver?.Dispose();
        }
    }
}