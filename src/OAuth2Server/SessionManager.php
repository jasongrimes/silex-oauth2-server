<?php

namespace OAuth2Server;

use PDO;
use OAuth2\Storage\SessionInterface;

class SessionManager implements SessionInterface
{
    /** @var PDO */
    protected $conn;

    public function __construct(PDO $conn)
    {
        $this->conn = $conn;
    }

    /**
     * Create a new OAuth session.
     *
     * @param  string $clientId          The client ID
     * @param  string $redirectUri       The redirect URI
     * @param  string $type              The session owner's type (default = "user")
     * @param  string $typeId            The session owner's ID (default = "null")
     * @param  string $authCode          The authorisation code (default = "null")
     * @param  string $accessToken       The access token (default = "null")
     * @param  string $refreshToken      The refresh token (default = "null")
     * @param  int    $accessTokenExpire The expiry time of an access token as a unix timestamp
     * @param  string $stage             The stage of the session (default ="request")
     * @return int                       The session ID
     */
    public function createSession($clientId, $redirectUri, $type = 'user', $typeId = null, $authCode = null, $accessToken = null, $refreshToken = null, $accessTokenExpire = null, $stage = 'requested')
    {
        $stmt = $this->conn->prepare(
            'INSERT INTO oauth_sessions (
                client_id,
                redirect_uri,
                owner_type,
                owner_id,
                auth_code,
                access_token,
                refresh_token,
                access_token_expires,
                stage,
                first_requested,
                last_updated
            ) VALUES (
                :clientId,
                :redirectUri,
                :type,
                :typeId,
                :authCode,
                :accessToken,
                :refreshToken,
                :accessTokenExpire,
                :stage,
                :time,
                :time
            )'
        );

        $stmt->execute(array(
            ':clientId' => $clientId,
            ':redirectUri' => $redirectUri,
            ':type' => $type,
            ':typeId' => $typeId,
            ':authCode' => $authCode,
            ':accessToken' => $accessToken,
            ':refreshToken' => $refreshToken,
            ':accessTokenExpire' => $accessTokenExpire,
            ':stage' => $stage,
            ':time' => time(),
        ));

        return $this->conn->lastInsertId();
    }

    /**
     * Update an OAuth session
     *
     * @param  string $sessionId         The session ID
     * @param  string $authCode          The authorisation code (default = "null")
     * @param  string $accessToken       The access token (default = "null")
     * @param  string $refreshToken      The refresh token (default = "null")
     * @param  int    $accessTokenExpire The expiry time of an access token as a unix timestamp
     * @param  string $stage             The stage of the session (default ="requested")
     * @return  void
     */
    public function updateSession($sessionId, $authCode = null, $accessToken = null, $refreshToken = null, $accessTokenExpire = null, $stage = 'requested')
    {
        $stmt = $this->conn->prepare('
            UPDATE oauth_sessions
            SET auth_code = :authCode
            , access_token = :accessToken
            , refresh_token = :refreshToken
            , access_token_expires = :accessTokenExpire
            , stage = :stage
            , last_updated = :time
            WHERE id = :sessionId
        ');

        $stmt->execute(array(
            ':authCode' => $authCode,
            ':accessToken' => $accessToken,
            ':refreshToken' => $refreshToken,
            ':accessTokenExpire' => $accessTokenExpire,
            ':stage' => $stage,
            ':time' => time(),
            ':sessionId' => $sessionId,
        ));
    }

    /**
     * Delete an OAuth session
     *
     * @param  string $clientId The client ID
     * @param  string $type     The session owner's type
     * @param  string $typeId   The session owner's ID
     * @return  void
     */
    public function deleteSession($clientId, $type, $typeId)
    {
        $stmt = $this->conn->prepare('DELETE FROM oauth_sessions WHERE client_id = :clientId AND owner_type = :type AND owner_id = :typeId');
        $stmt->execute(array(':clientId' => $clientId, ':type' => $type, ':typeId' => $typeId));
    }

    /**
     * Validate that an authorisation code is valid
     *
     * @param  string     $clientId    The client ID
     * @param  string     $redirectUri The redirect URI
     * @param  string     $authCode    The authorisation code
     * @return  int|bool   Returns the session ID if the auth code
     *  is valid otherwise returns false
     */
    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $stmt = $this->conn->prepare('
            SELECT id FROM oauth_sessions
            WHERE client_id = :clientId
            AND redirect_uri = :redirectUri
            AND auth_code = :authCode
        ');

        $stmt->execute(array(
            ':clientId' => $clientId,
            ':redirectUri' => $redirectUri,
            ':authCode' => $authCode,
        ));

        return $stmt->fetchColumn();
    }

    /**
     * Validate an access token.
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [id] => (int) The session ID
     *     [owner_type] => (string) The owner type
     *     [owner_id] => (string) The owner ID
     * )
     * </code>
     *
     * @param  string $accessToken
     * @return array Information about the owner, or an empty array if the access token is not valid.
     */
    public function validateAccessToken($accessToken)
    {
        $stmt = $this->conn->prepare('SELECT id, owner_type, owner_id FROM oauth_sessions WHERE access_token = ?');
        $stmt->execute(array($accessToken));

        return $stmt->fetch(PDO::FETCH_ASSOC) ?: array();
    }

    /**
     * Return the access token for a given session
     *
     * @param  int         $sessionId The OAuth session ID
     * @return string|null            Returns the access token as a string if
     *  found otherwise returns null
     */
    public function getAccessToken($sessionId)
    {
        $stmt = $this->conn->prepare('SELECT access_token FROM oauth_sessions WHERE id = ?');
        $stmt->execute(array($sessionId));
        return $stmt->fetchColumn() ?: null;
    }

    /**
     * Validate a refresh token.
     *
     * @param  string $refreshToken The refresh token
     * @param  string $clientId     The client ID
     * @return int|bool             The session ID if refresh token is valid, otherwise false.
     */
    public function validateRefreshToken($refreshToken, $clientId)
    {
        $stmt = $this->conn->prepare('SELECT id FROM oauth_sessions WHERE refresh_token = :refreshToken AND client_id = :clientId');
        $stmt->execute(array(':refreshToken' => $refreshToken, ':clientId' => $clientId));
        return $stmt->fetchColumn();
    }

    /**
     * Update the refresh token
     *
     * @param  string $sessionId             The session ID
     * @param  string $newAccessToken        The new access token for this session
     * @param  string $newRefreshToken       The new refresh token for the session
     * @param  int    $accessTokenExpires    The UNIX timestamp of when the new token expires
     * @return void
     */
    public function updateRefreshToken($sessionId, $newAccessToken, $newRefreshToken, $accessTokenExpires)
    {
        $stmt = $this->conn->prepare('
            UPDATE oauth_sessions
            SET access_token = :newAccessToken
            , refresh_token = :newRefreshToken
            , access_token_expires = :accessTokenExpires
            WHERE id = :sessionId
        ');

        $stmt->execute(array(
            ':newAccessToken' => $newAccessToken,
            ':newRefreshToken' => $newRefreshToken,
            ':accessTokenExpires' => $accessTokenExpires,
            ':sessionId' => $sessionId,
        ));

    }

    /**
     * Associates a session with a scope
     *
     * @param int    $sessionId The session ID
     * @param string $scopeId   The scope ID
     * @return void
     */
    public function associateScope($sessionId, $scopeId)
    {
        $stmt = $this->conn->prepare('INSERT INTO oauth_session_scopes (session_id, scope_id) VALUES (:sessionId, :scopeId)');
        $stmt->execute(array(':sessionId' => $sessionId, ':scopeId' => $scopeId));
    }

    /**
     * Return the scopes associated with an access token.
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [0] => (string) The scope
     *     [1] => (string) The scope
     *     [2] => (string) The scope
     *     ...
     *     ...
     * )
     * </code>
     *
     * @param  int   $sessionId The session ID
     * @return array
     */
    public function getScopes($sessionId)
    {
        $stmt = $this->conn->prepare('
            SELECT oauth_scopes.scope
            FROM oauth_session_scopes
            JOIN oauth_scopes ON oauth_session_scopes.scope_id = oauth_scopes.id
            WHERE session_id = ?
        ');
        $stmt->execute(array($sessionId));

        return $stmt->fetchAll(PDO::FETCH_COLUMN) ?: array();
    }
}
