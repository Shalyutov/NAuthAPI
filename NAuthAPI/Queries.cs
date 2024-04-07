namespace NAuthAPI
{
    class Queries
    {
        public static string CreateAllTables = """
            CREATE TABLE accounts 
            (
                username Utf8 NOT NULL,
                id Utf8 NOT NULL,
                hash Utf8 NOT NULL,
                salt Utf8 NOT NULL,
                attempt Uint8 NOT NULL,
                blocked Bool NOT NULL,
                grant Utf8 NOT NULL,
                access Timestamp,
                PRIMARY KEY (username)
            );

            CREATE TABLE requests
            (
                user Utf8 NOT NULL,
                verifier Utf8,
                client Utf8,
                issued Timestamp,
                scope Utf8,
                PRIMARY KEY (client, user, verifier)
            );

            CREATE TABLE `accept`
            (
                `client` Utf8 NOT NULL,
                `scope` Utf8 NOT NULL,
                `issued` Datetime NOT NULL,
                `user` Utf8 NOT NULL,
                PRIMARY KEY (`client`, `scope`, `user`)
            );

            CREATE TABLE `claims`
            (
                `issuer` Utf8 NOT NULL,
                `type` Utf8 NOT NULL,
                `user` Utf8 NOT NULL,
                `value` Utf8 NOT NULL,
                PRIMARY KEY (`issuer`, `type`, `user`)
            );

            CREATE TABLE `clients`
            (
                `name` Utf8 NOT NULL,
                `secret` Utf8 NOT NULL,
                `scopes` Utf8 NOT NULL,
                `trust` Bool NOT NULL,
                `valid` Bool NOT NULL,
                `callback` Utf8,
                PRIMARY KEY (`name`)
            );

            CREATE TABLE `keys`
            (
                `id` Utf8 NOT NULL,
                `audience` Utf8 NOT NULL,
                `issued` Datetime NOT NULL,
                `user` Utf8 NOT NULL,
                PRIMARY KEY (`id`)
            );

            CREATE TABLE `scopes`
            (
                `name` Utf8 NOT NULL,
                `description` Utf8 NOT NULL,
                `issuer` Utf8 NOT NULL,
                PRIMARY KEY (`name`, `issuer`)
            );

            CREATE TABLE `users`
            (
                `id` Utf8 NOT NULL,
                `email` Utf8,
                `phone` Uint64,
                `surname` Utf8,
                `name` Utf8,
                `lastname` Utf8,
                `gender` Utf8,
                PRIMARY KEY (`id`)
            );

            CREATE TABLE `verify`
            (
                `user` Utf8 NOT NULL,
                `claim` Utf8 NOT NULL,
                `verifier` Utf8 NOT NULL,
                `success` Bool,
                PRIMARY KEY (`user`, `claim`)
            );

            COMMIT;
            """;
        public static string DropAllTables = """
            DROP TABLE accept;
            DROP TABLE claims;
            DROP TABLE clients;
            DROP TABLE keys;
            DROP TABLE scopes;
            DROP TABLE users;
            DROP TABLE requests;
            """;
        public static string NullAttempt = """
            DECLARE $id AS Utf8;

            UPDATE
                accounts
            SET
                attempt = CAST(0 as Uint8)
            WHERE
                id = $id;
            """;
        public static string AddAttempt = """
            DECLARE $id AS Utf8;

            UPDATE
                account
            SET
                attempt = attempt + CAST(1 as Uint8)
            WHERE
                id = $id;
            """;
        public static string SetPasswordHash = """
            DECLARE $id AS Utf8;
            DECLARE $hash AS Utf8;

            UPDATE
                accounts
            SET
                hash = $hash
            WHERE
                id = $id;
            """;
        public static string SetClaim = """
            DECLARE $id AS Utf8;
            DECLARE $type AS Utf8;
            DECLARE $value AS Utf8;
            DECLARE $issuer AS Utf8;

            UPSERT INTO
                claims (issuer, type, value, user)
            VALUES
                ($issuer, $type, $value, $id);
            """;
        public static string DeleteClaim = """
            DECLARE $id AS Utf8;
            DECLARE $type AS Utf8;
            DECLARE $issuer AS Utf8;

            DELETE FROM
                claims
            WHERE
                issuer = $issuer AND
                type = $type AND
                user = $id);
            """;
        public static string GetUser = """
            DECLARE $id AS Utf8;

            SELECT
                id, surname, name, lastname, email, phone, gender
            FROM
                users
            WHERE 
                id = $id;
            """;
        public static string GetAccount = """
            DECLARE $username AS Utf8;

            SELECT
                id, salt, blocked, attempt, username, hash, grant, access
            FROM
                accounts
            WHERE 
                username = $username;
            """;
        public static string GetClient = """
            DECLARE $name AS Utf8;

            SELECT
                name, secret, valid, trust, scopes, callback
            FROM
                clients
            WHERE 
                name = $name;
            """;
        public static string CreateClient = """
            DECLARE $name AS Utf8;
            DECLARE $secret AS Utf8;
            DECLARE $valid AS Bool;
            DECLARE $trust AS Bool;
            DECLARE $scopes AS Utf8;
            DECLARE $callback AS Utf8;

            INSERT INTO
                clients (name, secret, valid, trust, scopes, callback)
            VALUES
                ($name, $secret, $valid, $trust, $scopes, $callback);
            """;
        public static string CreateRequest = """
            DECLARE $user AS Utf8;
            DECLARE $verifier AS Utf8;
            DECLARE $client AS Utf8;
            DECLARE $issued AS Timestamp;
            DECLARE $scope AS Utf8;
            DECLARE $code AS Utf8;

            INSERT INTO
                requests (user, verifier, client, issued, scope, code)
            VALUES
                ($user, $verifier, $client, $issued, $scope, $code);
            """;
        public static string GetRequest = """
            DECLARE $client AS Utf8;
            DECLARE $verifier As Utf8;

            SELECT 
                user, verifier, client, issued, scope, code
            FROM
                requests
            WHERE
                client = $client AND
                verifier = $verifier;
            """;
        public static string GetRequestByCode = """
            DECLARE $code AS Utf8;

            SELECT 
                user, verifier, client, issued, scope, code
            FROM
                requests
            WHERE
                code = $code;
            """;
        public static string DeleteRequestByCode = """
            DECLARE $code AS Utf8;

            DELETE 
            FROM
                requests
            WHERE
                code = $code;
            """;
        public static string GetKey = """
            DECLARE $id AS Utf8;

            SELECT
                id, user, audience
            FROM
                keys
            WHERE 
                id = $id;
            """;
        public static string GetClaims = """
            DECLARE $user AS Utf8;
            DECLARE $list AS List<Utf8>;

            SELECT
                issuer, type, value
            FROM
                claims
            WHERE 
                type IN $list AND
                audience = $user;
            """;
        public static string DeleteKey = """
            DECLARE $id AS Utf8;

            DELETE
            FROM
                keys
            WHERE 
                id = $id;
            """;
        public static string DeleteRequest = """
            DECLARE $code AS Utf8;

            DELETE
            FROM
                requests
            WHERE 
                code = $code;
            """;
        public static string DeleteUserKeys = """
            DECLARE $user AS Utf8;
            
            DELETE
            FROM
                keys
            WHERE 
                user = $user;
            """;
        public static string GetUserKeys = """
            DECLARE $user AS Utf8;

            SELECT
                id
            FROM
                keys
            WHERE 
                user = $user;
            """;
        public static string IsUserExists = """
            DECLARE $username AS Utf8;

            SELECT
                id
            FROM
                accounts
            WHERE 
                username = $username;
            """;
        public static string CreateIdentity = """
            DECLARE $id As Utf8;
            DECLARE $username AS Utf8;
            DECLARE $surname AS Utf8;
            DECLARE $name AS Utf8;
            DECLARE $lastname AS Utf8;
            DECLARE $hash AS Utf8;
            DECLARE $salt AS Utf8;
            DECLARE $email AS Utf8;
            DECLARE $phone AS Uint64;
            DECLARE $gender AS Utf8;
            DECLARE $attempt AS Uint8;
            DECLARE $blocked AS Bool;
            DECLARE $grant AS Utf8;
            DECLARE $access AS Timestamp;

            INSERT INTO 
                users (id, surname, name, lastname, email, phone, gender) 
            VALUES
                ($id, $surname, $name, $lastname, $email, $phone, $gender);

            INSERT INTO 
                accounts (id, username, hash, salt, attempt, blocked) 
            VALUES
                ($id, $username, $hash, $salt, $attempt, $blocked);

            COMMIT;
            """;
        public static string CreateSignIn = """
            DECLARE $id As Utf8;
            DECLARE $user AS Utf8;
            DECLARE $audience AS Utf8;

            INSERT INTO 
                keys (id, user, audience) 
            VALUES
                ($id, $user, $audience);
            """;
        public static string DeleteAccount = """
            DECLARE $id As Utf8;

            DELETE FROM
                users
            WHERE
                id = $id;
            """;
        public static string CreateAccept = """
            DECLARE $client As Utf8;
            DECLARE $user AS Utf8;
            DECLARE $scope AS Utf8;
            DECLARE $issued AS Datetime;

            INSERT INTO 
                accept (client, user, scope, issued) 
            VALUES
                ($client, $user, $scope, $issued);
            """;
        public static string DeleteAccept = """
            DECLARE $user As Utf8;
            DECLARE $client As Utf8;
            DECLARE $scope As Utf8;

            DELETE FROM
                accept
            WHERE
                user = $user 
                AND client = $client
                AND scope = $scope;
            """;
        public static string DeleteAllAccept = """
            DECLARE $user As Utf8;
            DECLARE $client As Utf8;

            DELETE FROM
                accept
            WHERE
                user = $user 
                AND client = $client;
            """;
        public static string SelectAccept = """
            DECLARE $user As Utf8;
            DECLARE $client As Utf8;

            SELECT 
                scope
            FROM
                accept
            WHERE
                user = $user
                AND client = $client;
            """;
    }
}
