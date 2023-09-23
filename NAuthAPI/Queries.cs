namespace NAuthAPI
{
    class Queries
    {
        public static string NullAttempt = @"
        DECLARE $guid AS Utf8;
        UPDATE
            users
        SET
            attempt = CAST(0 as Uint8)
        WHERE
            guid = $guid;
        ";
        public static string AddAttempt = @"
        DECLARE $guid AS Utf8;
        UPDATE
            users
        SET
            attempt = attempt + CAST(1 as Uint8)
        WHERE
            guid = $guid;
        ";
        public static string SetPasswordHash = @"
        DECLARE $guid AS Utf8;
        DECLARE $hash AS Utf8;
        UPDATE
            users
        SET
            hash = $hash
        WHERE
            guid = $guid;
        ";
        public static string SetClaim = @"
        DECLARE $guid AS Utf8;
        DECLARE $type AS Utf8;
        DECLARE $value AS Utf8;
        DECLARE $issuer AS Utf8;
        UPSERT INTO
            claims (issuer, type, value, audience)
        VALUES
            ($issuer, $type, $value, $guid);
        ";
        public static string GetIdentityUsername = @"
        DECLARE $username AS Utf8;
        SELECT
            hash, name, surname, guid, salt, lastname, email, phone, blocked, attempt, gender, username
        FROM
            users
        WHERE 
            username = $username;";
        public static string GetIdentityId = @"
        DECLARE $guid AS Utf8;
        SELECT
            hash, name, surname, guid, salt, lastname, email, phone, blocked, attempt, gender, username
        FROM
            users
        WHERE 
            guid = $guid;";
        public static string GetClient = @"
        DECLARE $name AS Utf8;
        SELECT
            name, secret, valid, trust, scopes
        FROM
            clients
        WHERE 
            name = $name;";
        public static string CreateClient = @"
        DECLARE $name AS Utf8;
        DECLARE $secret AS Utf8;
        DECLARE $valid AS Bool;
        DECLARE $trust AS Bool;
        DECLARE $scopes AS Utf8;
        INSERT INTO
            clients (name, secret, valid, trust, scopes)
        VALUES
            ($name, $secret, $valid, $trust, $scopes);";
        public static string CreateRequest = @"
        DECLARE $user AS Utf8;
        DECLARE $verifier AS Utf8;
        DECLARE $client AS Utf8;
        DECLARE $stamp AS Datetime;
        DECLARE $scope AS Utf8;
        INSERT INTO
            requests (user, verifier, client, stamp, scope)
        VALUES
            ($user, $verifier, $client, $stamp, $scope);";
        public static string GetRequest = @"
        DECLARE $client AS Utf8;
        DECLARE $verifier As Utf8;
        SELECT 
            user, verifier, client, stamp, scope
        FROM
            requests
        WHERE
            client = $client
            AND verifier = $verifier;
        ";
        public static string GetRequestByCode = @"
        DECLARE $code AS Utf8;
        SELECT 
            user, verifier, client, stamp, scope
        FROM
            requests
        WHERE
            code = $code;
        ";
        public static string GetKey = @"
        DECLARE $id AS Utf8;
        SELECT
            id, user, audience
        FROM
            keys
        WHERE 
            id = $id;";
        public static string GetClaims = @"
        DECLARE $user AS Utf8;
        DECLARE $list AS List<Utf8>;
        SELECT
            issuer, type, value
        FROM
            claims
        WHERE 
            type IN $list
            AND audience = $user;
        ";
        public static string DeleteKey = @"
        DECLARE $id AS Utf8;
        DELETE
        FROM
            keys
        WHERE 
            id = $id;";
        public static string DeleteRequest = @"
        DECLARE $code AS Utf8;
        DELETE
        FROM
            requests
        WHERE 
            code = $code;";
        public static string DeleteClaim = @"
        DECLARE $user AS Utf8;
        DECLARE $type AS Utf8;
        DELETE
        FROM
            claims
        WHERE 
            audience = $user
            AND type = $type;";
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
            id
        FROM
            keys
        WHERE 
            user = $user;";
        public static string IsUserExists = @"
        DECLARE $username AS Utf8;
        SELECT
            guid
        FROM
            users
        WHERE 
            username = $username;";
        public static string CreateAccount = @"
        DECLARE $guid As Utf8;
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
            ($guid, $username, $surname, $name, $lastname, $hash, $salt, $email, $phone, $gender, $attempt, CAST($blocked AS Bool));";
        public static string CreateSignIn = @"
        DECLARE $id As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $audience AS Utf8;
        INSERT INTO 
            keys (id, user, audience) 
        VALUES
            ($id, $user, $audience);
        ";
        public static string DeleteAccount = @"
        DECLARE $guid As Utf8;
        DELETE FROM
            users
        WHERE
            guid = $guid;
        ";
        public static string CreateAccept = @"
        DECLARE $client As Utf8;
        DECLARE $user AS Utf8;
        DECLARE $scope AS Utf8;
        DECLARE $datetime AS Datetime
        INSERT INTO 
            accept (client, user, scope, date) 
        VALUES
            ($client, $user, $scope, $datetime);
        ";
        public static string DeleteAccept = @"
        DECLARE $user As Utf8;
        DECLARE $client As Utf8;
        DECLARE $type As Utf8;
        DELETE FROM
            accept
        WHERE
            user = $user 
            AND client = $client
            AND type = $type;
        ";
        public static string DeleteAllAccept = @"
        DECLARE $user As Utf8;
        DECLARE $client As Utf8;
        DELETE FROM
            accept
        WHERE
            user = $user 
            AND client = $client;
        ";
        public static string SelectAccept = @"
        DECLARE $user As Utf8;
        DECLARE $client As Utf8;
        SELECT 
            scope
        FROM
            accept
        WHERE
            user = $user
            AND client = $client;
        ";
    }
}
