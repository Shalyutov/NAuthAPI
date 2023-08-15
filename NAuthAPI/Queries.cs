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
        public static string SetPasswordHash = @"
        DECLARE $id AS Utf8;
        DECLARE $hash AS Utf8;
        UPDATE
            users
        SET
            hash = $hash
        WHERE
            guid = $id;
        ";
        public static string SetClaim = @"
        DECLARE $id AS Utf8;
        DECLARE $type AS Utf8;
        DECLARE $value AS Utf8;
        DECLARE $issuer AS Utf8;
        UPSERT INTO
            claims (issuer, type, value, audience)
        VALUES
            ($issuer, $type, $value, $id);
        ";
        public static string GetIdentityUsername = @"
        DECLARE $id AS Utf8;
        SELECT
            hash, name, surname, guid, salt, lastname, email, phone, blocked, attempt, gender, username
        FROM
            users
        WHERE 
            username = $id;";
        public static string GetIdentityId = @"
        DECLARE $id AS Utf8;
        SELECT
            hash, name, surname, guid, salt, lastname, email, phone, blocked, attempt, gender, username
        FROM
            users
        WHERE 
            guid = $id;";
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
        public static string GetClaims = @"
        DECLARE $id AS Utf8;
        DECLARE $list AS List<Utf8>;
        SELECT
            issuer, type, value
        FROM
            claims
        WHERE 
            type IN $list
            AND audience = $id;
        ";
        public static string DeleteKey = @"
        DECLARE $id AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            kid = $id;";
        //TODO
        public static string DeleteClaim = @"
        DECLARE $id AS Utf8;
        DECLARE $type AS Utf8;
        DELETE
        FROM
            claims
        WHERE 
            audience = $id;";
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
        DECLARE $attempt AS Uint8;
        DECLARE $blocked AS Uint8;
        INSERT INTO 
            users (guid, username, surname, name, lastname, hash, salt, email, phone, gender, attempt, blocked) 
        VALUES
            ($id, $username, $surname, $name, $lastname, $hash, $salt, $email, $phone, $gender, $attempt, CAST($blocked AS Bool));";
        public static string CreateSignIn = @"
        DECLARE $id As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $audience AS Utf8;
        INSERT INTO 
            keys (kid, user, audience) 
        VALUES
            ($id, $user, $audience);
        ";
        public static string DeleteAccount = @"
        DECLARE $id As Utf8;
        DELETE FROM
            users
        WHERE
            guid = $id;
        ";
        public static string CreateAccept = @"
        DECLARE $client As Utf8;
        DECLARE $user_id AS Utf8;
        DECLARE $scope AS Utf8;
        DECLARE $datetime AS Datetime
        INSERT INTO 
            accept (client, user, scope, date) 
        VALUES
            ($client, $user_id, $scope, $datetime);
        ";
        public static string DeleteAccept = @"
        DECLARE $user_id As Utf8;
        DECLARE $client As Utf8;
        DELETE FROM
            accept
        WHERE
            user = $user_id 
            AND client = $client;
        ";
        public static string SelectAccept = @"
        DECLARE $user_id As Utf8;
        DECLARE $client As Utf8;
        SELECT 
            scope
        FROM
            accept
        WHERE
            user = $user_id 
            AND client = $client;
        ";
    }
}
