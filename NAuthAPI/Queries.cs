namespace NAuthAPI
{
    class Queries
    {
        public static string NullAttempt = @"
        DECLARE $id AS Utf8;
        UPDATE
            users
        SET
            attempt = CAST(0 as Uint8)
        WHERE
            guid = $id;
        ";
        public static string AddAttempt = @"
        DECLARE $id AS Utf8;
        UPDATE
            users
        SET
            attempt = attempt + CAST(1 as Uint8)
        WHERE
            guid = $id;
        ";
        public static string GetIdentity = @"
        DECLARE $id AS Utf8;
        SELECT
            hash, name, surname, guid, salt, lastname, email, phone, blocked, attempt
        FROM
            users
        WHERE 
            username = $id;";
        public static string GetClient = @"
        DECLARE $id AS Utf8;
        SELECT
            name, secret, valid, implement, scopes
        FROM
            clients
        WHERE 
            name = $id;";
        public static string CreateClient = @"
        DECLARE $id AS Utf8;
        DECLARE $secret AS Utf8;
        DECLARE $valid AS Bool;
        DECLARE $impl AS Bool;
        DECLARE $scopes AS Utf8;
        INSERT INTO
            clients (name, secret, valid, implement, scopes)
        VALUES
            ($id, $secret, $valid, $impl, $scopes);";
        public static string GetKey = @"
        DECLARE $id AS Utf8;
        SELECT
            kid, user, audience
        FROM
            keys
        WHERE 
            kid = $id;";
        public static string DeleteKey = @"
        DECLARE $id AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            kid = $id;";
        public static string DeleteUserKeys = @"
        DECLARE $user AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            user = $user;";
        public static string GetUserKeys = @"
        DECLARE $user AS Utf8;
        SELECT
            kid
        FROM
            keys
        WHERE 
            user = $user;";
        public static string GetUsername = @"
        DECLARE $id AS Utf8;
        SELECT
            guid
        FROM
            users
        WHERE 
            username = $id;";
        public static string CreateAccount = @"
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
        INSERT INTO 
            users (guid, username, surname, name, lastname, hash, salt, email, phone, gender) 
        VALUES
            ($id, $username, $surname, $name, $lastname, $hash, $salt, $email, $phone, $gender);";
        public static string CreateSignIn = @"
        DECLARE $id As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $audience AS Utf8;
        INSERT INTO 
            keys (kid, user, audience) 
        VALUES
            ($id, $user, $audience);";
        public static string DeleteAccount = @"
        DECLARE $id As Utf8;
        DEELTE FROM
            users
        WHERE
            guid = $id;
        ";
    }
}
