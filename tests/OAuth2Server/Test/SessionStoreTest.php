<?php

namespace OAuth2Server\Test;

use OAuth2Server\Storage\SessionStore;
use League\OAuth2\Server\Util\SecureKey;

class SessionStoreTest extends AbstractDbTestCase
{
    /** @var SessionStore */
    protected $store;

    public function setUp()
    {
        $this->store = new SessionStore($this->getDbal());

        parent::setUp();
    }

    /*
    public function getValidSessionData()
    {
        return array(
            array(array(
                'client_id' => 'I6Lh72kTItE6y29Ig607N74M7i21oyTo',
                'redirect_uri' => 'http://example.com/signin/redirect',
                'owner_type' => 'user',
                'owner_id' => '123',
                'auth_code' => null,
                'access_token' => SecureKey::make(),
                'refresh_token' => null,
                'access_token_expires' => time() + 3600,
                'stage' => 'granted',
            )),
        );
    }

    public function getSessionDataFromDb($id)
    {
        $stmt = $this->getPdo()->prepare('SELECT * FROM oauth_sessions WHERE id = :id');
        $stmt->execute(array($id));
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    */

    /**
     * @param int $id
     * @return array|bool
     */
    protected function getOauthSessionData($id)
    {
        return $this->getDbal()->fetchAssoc('SELECT * FROM oauth_sessions WHERE id = ?', array($id));
    }

    public function testCreateSession()
    {
        $clientId = 'I6Lh72kTItE6y29Ig607N74M7i21oyTo';
        $ownerType = 'user';
        $ownerId = '123';

        $sessionId = $this->store->createSession($clientId, $ownerType, $ownerId);

        // Make sure we got back a reasonable primary key.
        $this->assertGreaterThan(0, $sessionId);

        // Pull the data out of the db to compare it.
        $db_data = $this->getOauthSessionData($sessionId);

        $this->assertEquals($clientId, $db_data['client_id']);
        $this->assertEquals($ownerType, $db_data['owner_type']);
        $this->assertEquals($ownerId, $db_data['owner_id']);
    }

    public function testDeleteSession()
    {
        $clientId = SecureKey::make();
        $ownerType = 'user';
        $ownerId = '123';

        $sessionId = $this->store->createSession($clientId, $ownerType, $ownerId);
        $this->assertGreaterThan(0, $sessionId);
        $this->assertNotEmpty($this->getOauthSessionData($sessionId));

        $this->store->deleteSession($clientId, $ownerType, $ownerId);

        $this->assertFalse($this->getOauthSessionData($sessionId));
    }

    public function testAssociateRedirectUri()
    {
        $sessionId = 123;
        $redirectUri = 'http://www.example.com/foo';

        $this->store->associateRedirectUri($sessionId, $redirectUri);

        $this->assertNotEmpty(
            $this->getDbal()->fetchAssoc('SELECT * FROM oauth_session_redirects WHERE session_id = ? AND redirect_uri = ?',
                array($sessionId, $redirectUri))
        );
    }

    public function testAssociateAccessToken()
    {
        $sessionId = 123;
        $accessToken = SecureKey::make();
        $expireTime = time();

        $this->store->associateAccessToken($sessionId, $accessToken, $expireTime);

        $this->assertNotEmpty($this->getDbal()->fetchAssoc(
                'SELECT * FROM oauth_session_access_tokens WHERE session_id = ? AND access_token = ? AND access_token_expires = ?',
                array($sessionId, $accessToken, $expireTime))
        );
    }

    public function testAssociateRefreshToken()
    {
        $sessionId = 123;
        $accessToken = SecureKey::make();
        $expireTime = time();
        $refreshToken = SecureKey::make();
        $clientId = SecureKey::make();

        $accessTokenId = $this->store->associateAccessToken($sessionId, $accessToken, $expireTime);
        $this->store->associateRefreshToken($accessTokenId, $refreshToken, $expireTime, $clientId);

        $this->assertNotEmpty($this->getDbal()->fetchAssoc(
                'SELECT * FROM oauth_session_refresh_tokens
                 WHERE session_access_token_id = ? AND refresh_token = ? AND refresh_token_expires = ? AND client_id = ?',
                array($accessTokenId, $refreshToken, $expireTime, $clientId))
        );
    }

    public function testAssociateAuthCode()
    {
        $sessionId = 123;
        $authCode = SecureKey::make();
        $expireTime = time();

        $authCodeId = $this->store->associateAuthCode($sessionId, $authCode, $expireTime);

        $this->assertGreaterThan(0, $authCodeId);

        $this->assertNotEmpty($this->getDbal()->fetchAssoc(
                'SELECT * FROM oauth_session_authcodes WHERE session_id = ? AND auth_code = ? AND auth_code_expires = ?',
                array($sessionId, $authCode, $expireTime))
        );
    }

    public function testRemoveAuthCode()
    {
        $sessionId = '123';

        $this->store->associateAuthCode($sessionId, 'auth-code', time());
        $this->assertNotEmpty($this->getDbal()->fetchAssoc('SELECT * FROM oauth_session_authcodes WHERE session_id = ?', array($sessionId)));

        $this->store->removeAuthCode($sessionId);
        $this->assertFalse($this->getDbal()->fetchAssoc('SELECT * FROM oauth_session_authcodes WHERE session_id = ?', array($sessionId)));
    }

    public function testValidateAuthCode()
    {
        $clientId = 'xyz';
        $redirectUri = 'http://example.com';
        $authCode = SecureKey::make();

        $sessionId = $this->store->createSession($clientId, 'user', 'xyz');
        $authCodeId = $this->store->associateAuthCode($sessionId, $authCode, time() + 3600);
        $this->store->associateRedirectUri($sessionId, $redirectUri);

        $result = $this->store->validateAuthCode($clientId, $redirectUri, $authCode);
        $this->assertInternalType('array', $result);
        $this->assertEquals($sessionId, $result['session_id']);
        $this->assertEquals($authCodeId, $result['authcode_id']);

        // Test that false is returned if the auth code is not valid.
        $this->assertFalse($this->store->validateAuthCode($clientId, $redirectUri, 'invalid-auth-code'));
    }

    public function testValidateAccessToken()
    {
        $clientId = SecureKey::make();
        $ownerType = 'user';
        $ownerId = '123';
        $accessToken = SecureKey::make();

        $sessionId = $this->store->createSession($clientId, $ownerType, $ownerId);
        $this->store->associateAccessToken($sessionId, $accessToken, time() + 3600);

        // Test that information about the owner is returned if access token is valid.
        $result = $this->store->validateAccessToken($accessToken);
        $this->assertEquals($sessionId, $result['session_id']);
        $this->assertEquals($clientId, $result['client_id']);
        $this->assertEquals($ownerId, $result['owner_id']);
        $this->assertEquals($ownerType, $result['owner_type']);

        // Test that an empty array is returned if access token is invalid.
        $result = $this->store->validateAccessToken('invalid-access-token');
        $this->assertFalse($result);
    }

    public function testRemoveRefreshToken()
    {
        $refreshToken = SecureKey::make();

        $this->store->associateRefreshToken(123, $refreshToken, time() + 3600, 'xyz');

        $this->assertNotEmpty($this->getDbal()->fetchAssoc(
            'SELECT * FROM oauth_session_refresh_tokens WHERE refresh_token = ?',
            array($refreshToken))
        );

        $this->store->removeRefreshToken($refreshToken);

        $this->assertFalse($this->getDbal()->fetchAssoc(
            'SELECT * FROM oauth_session_refresh_tokens WHERE refresh_token = ?',
            array($refreshToken))
        );
    }

    public function testValidateRefreshToken()
    {
        $accessTokenId = 123;
        $refreshToken = SecureKey::make();
        $clientId = 'client-id';

        $this->store->associateRefreshToken($accessTokenId, $refreshToken, time() + 3600, $clientId);
        $this->assertEquals($accessTokenId, $this->store->validateRefreshToken($refreshToken, $clientId));

        $this->assertFalse($this->store->validateRefreshToken('invalid-token', $clientId));
    }

    public function testGetAccessToken()
    {
        $sessionId = 123;
        $accessToken = SecureKey::make();
        $expireTime = time();

        $accessTokenId = $this->store->associateAccessToken($sessionId, $accessToken, $expireTime);

        $result = $this->store->getAccessToken($accessTokenId);
        $this->assertEquals($sessionId, $result['session_id']);
        $this->assertEquals($accessToken, $result['access_token']);
        $this->assertEquals($expireTime, $result['access_token_expires']);
    }

    public function testAssociateAuthCodeScope()
    {
        $authCodeId = 123;
        $scopeId = 321;

        $this->store->associateAuthCodeScope($authCodeId, $scopeId);

        $result = $this->getDbal()->fetchAssoc('SELECT * FROM oauth_session_authcode_scopes WHERE oauth_session_authcode_id = ?', array($authCodeId));
        $this->assertInternalType('array', $result);
        $this->assertEquals($scopeId, $result['scope_id']);
    }

    public function testGetAuthCodeScopes()
    {
        $authCodeId = 123;
        $scopeId = 321;

        $this->store->associateAuthCodeScope($authCodeId, $scopeId);

        $result = $this->store->getAuthCodeScopes($authCodeId);

        $this->assertInternalType('array', $result);
        $this->assertEquals($scopeId, $result[0]['scope_id']);
    }

    public function testAssociateScope()
    {
        $accessTokenId = 123;
        $scopeId = 321;

        $this->store->associateScope($accessTokenId, $scopeId);

        $result = $this->getDbal()->fetchAssoc('SELECT * FROM oauth_session_token_scopes WHERE session_access_token_id = ?',
            array($accessTokenId));
        $this->assertInternalType('array', $result);
        $this->assertEquals($scopeId, $result['scope_id']);
    }

    public function testGetScopes()
    {
        $accessToken = SecureKey::make();
        $clientId = 999;

        $scopeId = 123;
        $scope = 'foo';
        $scopeId2 = 124;
        $scope2 = 'foo2';

        // Set up the test fixture

        // Add scopes
        $stmt = $this->getDbal()->prepare('INSERT INTO oauth_scopes (id, scope) VALUES (:scopeId, :scope)');
        $stmt->execute(array(':scopeId' => $scopeId, ':scope' => $scope));
        $stmt->execute(array(':scopeId' => $scopeId2, ':scope' => $scope2));

        // Add session and access token.
        $sessionId = $this->store->createSession($clientId, 'user', 'xyz');
        $accessTokenId = $this->store->associateAccessToken($sessionId, $accessToken, time() + 3600);

        // Associate scopes with access token.
        $this->store->associateScope($accessTokenId, $scopeId);
        $this->store->associateScope($accessTokenId, $scopeId2);

        // Get scopes and compare them.
        $result = $this->store->getScopes($accessToken);
        $this->assertInternalType('array', $result);
        $this->assertContains($scope, $result[0]);
        $this->assertContains($scope2, $result[1]);

        // Test that an empty array is returned if no scopes are found.
        $result = $this->store->getScopes('invalid-access-token');
        $this->assertInternalType('array', $result);
        $this->assertEmpty($result);
    }
}