namespace NAuthAPI
{
    class Queries
    {
        public static string GetIdentity = @"
        DECLARE $id AS Utf8;
        SELECT
            hash, name, surname, guid, salt
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
        DECLARE $username AS Utf8;
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
        public static string CreateIdentity = @"
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
        public static string CreateSignIn = @"
        DECLARE $id As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $audience AS Utf8;
        INSERT INTO 
            keys (kid, user, audience) 
        VALUES
            ($id, $user, $audience);";

    }
}
