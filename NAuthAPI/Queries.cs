namespace NAuthAPI
{
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
