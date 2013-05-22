<?php

namespace OAuth2Server\Storage;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Storage\SessionInterface;

class SessionStore implements SessionInterface
{
    /** @var Connection */
    protected $conn;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn;
    }

    /**
     * Create a new session
     *
     * Example SQL query:
     *
     * @param  string $clientId  The client ID
     * @param  string $ownerType The type of the session owner (e.g. "user")
     * @param  string $ownerId   The ID of the session owner (e.g. "123")
     * @return int               The session ID
     */
    public function createSession($clientId, $ownerType, $ownerId)
    {
        $sql = 'INSERT INTO oauth_sessions (client_id, owner_type, owner_id) VALUES (:clientId, :ownerType, :ownerId)';
        $params = array('clientId' => $clientId, 'ownerType' => $ownerType, 'ownerId' => $ownerId);
        $this->conn->executeUpdate($sql, $params);

        return $this->conn->lastInsertId();
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
        $sql = 'DELETE FROM oauth_sessions WHERE client_id = :clientId AND owner_type = :type AND owner_id = :typeId';
        $params = array('clientId' => $clientId, 'type' => $type, 'typeId' => $typeId);
        $this->conn->executeUpdate($sql, $params);
    }

    /**
     * Associate a redirect URI with a session
     *
     * @param  int    $sessionId   The session ID
     * @param  string $redirectUri The redirect URI
     * @return void
     */
    public function associateRedirectUri($sessionId, $redirectUri)
    {
        $sql = 'INSERT INTO oauth_session_redirects (session_id, redirect_uri) VALUES (:sessionId, :redirectUri)';
        $params = array('sessionId' => $sessionId, 'redirectUri' => $redirectUri);
        $this->conn->executeUpdate($sql, $params);
    }

    /**
     * Associate an access token with a session
     *
     * @param  int    $sessionId   The session ID
     * @param  string $accessToken The access token
     * @param  int    $expireTime  Unix timestamp of the access token expiry time
     * @return int                 The access token ID.
     */
    public function associateAccessToken($sessionId, $accessToken, $expireTime)
    {
        $sql = 'INSERT INTO oauth_session_access_tokens (session_id, access_token, access_token_expires)
                VALUES (:sessionId, :accessToken, :accessTokenExpire)';
        $params = array('sessionId' => $sessionId, 'accessToken' => $accessToken, 'accessTokenExpire' => $expireTime);
        $this->conn->executeUpdate($sql, $params);

        return $this->conn->lastInsertId();
    }

    /**
     * Associate a refresh token with a session
     *
     * @param  int    $accessTokenId The access token ID
     * @param  string $refreshToken  The refresh token
     * @param  int    $expireTime    Unix timestamp of the refresh token expiry time
     * @param  string $clientId      The client ID
     * @return void
     */
    public function associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId)
    {
        $sql = 'INSERT INTO oauth_session_refresh_tokens (session_access_token_id, refresh_token, refresh_token_expires, client_id)
                VALUES (:accessTokenId, :refreshToken, :expireTime, :clientId)';
        $params = array(
            'accessTokenId' => $accessTokenId,
            'refreshToken' => $refreshToken,
            'expireTime' => $expireTime,
            'clientId' => $clientId,
        );
        $this->conn->executeUpdate($sql, $params);
    }

    /**
     * Assocate an authorization code with a session
     *
     * @param  int    $sessionId  The session ID
     * @param  string $authCode   The authorization code
     * @param  int    $expireTime Unix timestamp of the access token expiry time
     * @return int                The auth code ID
     */
    public function associateAuthCode($sessionId, $authCode, $expireTime)
    {
        $sql = 'INSERT INTO oauth_session_authcodes (session_id, auth_code, auth_code_expires)
                VALUES (:sessionId, :authCode, :authCodeExpires)';
        $params = array('sessionId' => $sessionId, 'authCode' => $authCode, 'authCodeExpires' => $expireTime);
        $this->conn->executeUpdate($sql, $params);

        return $this->conn->lastInsertId();
    }

    /**
     * Remove an associated authorization token from a session
     *
     * @param  int    $sessionId   The session ID
     * @return void
     */
    public function removeAuthCode($sessionId)
    {
        $this->conn->executeUpdate('DELETE FROM oauth_session_authcodes WHERE session_id = ?', array($sessionId));
    }

    /**
     * Validate an authorization code
     *
     * Expected response:
     *
     * <code>
     * array(
     *     'session_id' =>  (int)
     *     'authcode_id'  =>  (int)
     * )
     * </code>
     *
     * @param  string     $clientId    The client ID
     * @param  string     $redirectUri The redirect URI
     * @param  string     $authCode    The authorization code
     * @return array|bool              False if invalid or array as above
     */
    public function validateAuthCode($clientId, $redirectUri, $authCode)
    {
        $sql = '
            SELECT oauth_sessions.id AS session_id, oauth_session_authcodes.id AS authcode_id
            FROM oauth_sessions
                JOIN oauth_session_authcodes ON oauth_session_authcodes.session_id = oauth_sessions.id
                JOIN oauth_session_redirects ON oauth_session_redirects.session_id = oauth_sessions.id
            WHERE oauth_sessions.client_id = :clientId
                AND oauth_session_authcodes.auth_code = :authCode
                AND oauth_session_authcodes.auth_code_expires >= :time
                AND oauth_session_redirects.redirect_uri = :redirectUri';
        $params = array('clientId' => $clientId, 'authCode' => $authCode, 'redirectUri' => $redirectUri, 'time' => time());

        return $this->conn->fetchAssoc($sql, $params);
    }

    /**
     * Validate an access token
     *
     * Expected response:
     *
     * <code>
     * array(
     *     'session_id' =>  (int),
     *     'client_id'  =>  (string),
     *     'owner_id'   =>  (string),
     *     'owner_type' =>  (string)
     * )
     * </code>
     *
     * @param  string     $accessToken The access token
     * @return array|bool              False if invalid or an array as above
     */
    public function validateAccessToken($accessToken)
    {
        $sql = 'SELECT session_id, oauth_sessions.`client_id`, oauth_sessions.`owner_id`, oauth_sessions.`owner_type`
                FROM `oauth_session_access_tokens` JOIN oauth_sessions ON oauth_sessions.`id` = session_id
                WHERE access_token = :accessToken AND access_token_expires >= :timeNow';
        $params = array('accessToken' => $accessToken, 'timeNow' => time());

        return $this->conn->fetchAssoc($sql, $params);
    }

    /**
     * Removes a refresh token
     *
     * @param  string $refreshToken The refresh token to be removed
     * @return void
     */
    public function removeRefreshToken($refreshToken)
    {
        return $this->conn->executeUpdate('DELETE FROM `oauth_session_refresh_tokens` WHERE refresh_token = ?', array($refreshToken));
    }

    /**
     * Validate a refresh token
     *
     * @param  string   $refreshToken The access token
     * @param  string   $clientId     The client ID
     * @return int|bool               The ID of the access token the refresh token is linked to (or false if invalid)
     */
    public function validateRefreshToken($refreshToken, $clientId)
    {
        $sql = 'SELECT session_access_token_id
          FROM `oauth_session_refresh_tokens`
          WHERE refresh_token = :refreshToken
          AND refresh_token_expires >= :timeNow
          AND client_id = :clientId';
        $params = array('refreshToken' => $refreshToken, 'timeNow' => time(), 'clientId' => $clientId);

        return $this->conn->fetchColumn($sql, $params);
    }

    /**
     * Get an access token by ID
     *
     * Expected response:
     *
     * <code>
     * array(
     *     'id' =>  (int),
     *     'session_id' =>  (int),
     *     'access_token'   =>  (string),
     *     'access_token_expires'   =>  (int)
     * )
     * </code>
     *
     * @param  int    $accessTokenId The access token ID
     * @return array|bool
     */
    public function getAccessToken($accessTokenId)
    {
        return $this->conn->fetchAssoc('SELECT * FROM oauth_session_access_tokens WHERE id = ?', array($accessTokenId));
    }

    /**
     * Associate scopes with an auth code (bound to the session)
     *
     * @param  int $authCodeId The auth code ID
     * @param  int $scopeId    The scope ID
     * @return void
     */
    public function associateAuthCodeScope($authCodeId, $scopeId)
    {
        $sql = 'INSERT INTO `oauth_session_authcode_scopes` (`oauth_session_authcode_id`, `scope_id`)
            VALUES (:authCodeId, :scopeId)';
        $params = array('authCodeId' => $authCodeId, 'scopeId' => $scopeId);
        $this->conn->executeUpdate($sql, $params);
    }

    /**
     * Get the scopes associated with an auth code
     *
     * Expected response:
     *
     * <code>
     * array(
     *     array(
     *         'scope_id' => (int)
     *     ),
     *     array(
     *         'scope_id' => (int)
     *     ),
     *     ...
     * )
     * </code>
     *
     * @param  int   $oauthSessionAuthCodeId The session ID
     * @return array
     */
    public function getAuthCodeScopes($oauthSessionAuthCodeId)
    {
        return $this->conn->fetchAll('SELECT scope_id FROM `oauth_session_authcode_scopes` WHERE oauth_session_authcode_id = ?',
            array($oauthSessionAuthCodeId));
    }

    /**
     * Associate a scope with an access token
     *
     * @param  int    $accessTokenId The ID of the access token
     * @param  int    $scopeId       The ID of the scope
     * @return void
     */
    public function associateScope($accessTokenId, $scopeId)
    {
        $sql = 'INSERT INTO `oauth_session_token_scopes` (`session_access_token_id`, `scope_id`) VALUES (:accessTokenId, :scopeId)';
        $params = array('accessTokenId' => $accessTokenId, 'scopeId' => $scopeId);
        $this->conn->executeUpdate($sql, $params);
    }

    /**
     * Get all associated scopes for an access token
     *
     * Expected response:
     *
     * <code>
     * array (
     *     array(
     *         'key'    =>  (string),
     *         'name'   =>  (string),
     *         'description'    =>  (string)
     *     ),
     *     ...
     *     ...
     * )
     * </code>
     *
     * @param  string $accessToken The access token
     * @return array
     */
    public function getScopes($accessToken)
    {
        $sql = 'SELECT oauth_scopes.*
            FROM oauth_session_token_scopes
              JOIN oauth_session_access_tokens ON oauth_session_access_tokens.`id` = `oauth_session_token_scopes`.`session_access_token_id`
              JOIN oauth_scopes ON oauth_scopes.id = `oauth_session_token_scopes`.`scope_id`
            WHERE access_token = :accessToken';
        $params = array('accessToken' => $accessToken);

        return $this->conn->fetchAll($sql, $params);
    }
}
