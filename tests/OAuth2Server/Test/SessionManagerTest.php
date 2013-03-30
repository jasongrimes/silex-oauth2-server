<?php

namespace OAuth2Server\Test;

use OAuth2Server\SessionManager;
use OAuth2\Util\SecureKey;
use PDO;

class SessionManagerTest extends AbstractDbTestCase
{
    /** @var SessionManager */
    protected $sm;

    public function setUp()
    {
        $this->sm = new SessionManager($this->getPdo());

        parent::setUp();
    }

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

    /**
     * @dataProvider getValidSessionData
     */
    public function testCreateSession($data)
    {
        // Create a new session with the given data. Use call_user_func_array to explode the array into individual method parameters.
        $id = call_user_func_array(array($this->sm, "createSession"), $data);

        // Make sure we got back a reasonable primary key.
        $this->assertGreaterThan(0, $id);

        // Pull the data out of the db to compare it.
        $db_data = $this->getSessionDataFromDb($id);

        // Test that each column has the data we tried to store in it.
        foreach ($data as $key => $val) {
            $this->assertEquals($val, $db_data[$key]);
        }
    }

    /**
     * @dataProvider getValidSessionData
     */
    public function testUpdateSession($data)
    {
        $id = $this->sm->createSession('abc', 'http://example.com');
        $this->assertGreaterThan(0, $id);

        $this->sm->updateSession($id, $data['auth_code'], $data['access_token'], $data['refresh_token'], $data['access_token_expires'], $data['stage']);

        // Test that each column has the data we tried to store in it.
        $db_data = $this->getSessionDataFromDb($id);
        foreach (array('auth_code', 'access_token', 'refresh_token', 'access_token_expires', 'stage') as $key) {
            $this->assertEquals($data[$key], $db_data[$key]);
        }
    }

    public function testDeleteSession()
    {
        $clientId = SecureKey::make();
        $type = 'user';
        $typeId = '123';

        $id = $this->sm->createSession($clientId, 'http://example.com', $type, $typeId);
        $this->assertGreaterThan(0, $id);
        $this->assertNotEmpty($this->getSessionDataFromDb($id));

        $this->sm->deleteSession($clientId, $type, $typeId);

        $db_data = $this->getSessionDataFromDb($id);
        $this->assertFalse($db_data);
    }

    public function testValidateAuthCode()
    {
        $clientId = 'xyz';
        $redirectUri = 'http://example.com';
        $authCode = SecureKey::make();

        $id = $this->sm->createSession($clientId, $redirectUri, 'user', null, $authCode);
        $this->assertGreaterThan(0, $id);

        // Test that the session ID is returned if the auth code is valid.
        $this->assertEquals($id, $this->sm->validateAuthCode($clientId, $redirectUri, $authCode));

        // Test that false is returned if the auth code is not valid.
        $this->assertFalse($this->sm->validateAuthCode($clientId, $redirectUri, 'invalid-auth-code'));
    }

    public function testValidateAccessToken()
    {
        $type = 'user';
        $typeId = '123';
        $accessToken = SecureKey::make();

        $id = $this->sm->createSession('abc', 'http://www.example.com', $type, $typeId, null, $accessToken);
        $this->assertGreaterThan(0, $id);

        // Test that information about the owner is returned if access token is valid.
        $result = $this->sm->validateAccessToken($accessToken);
        $this->assertEquals(array('id' => $id, 'owner_type' => $type, 'owner_id' => $typeId), $result);

        // Test that an empty array is returned if access token is invalid.
        $result = $this->sm->validateAccessToken('invalid-access-token');
        $this->assertInternalType('array', $result);
        $this->assertEmpty($result);
    }

    public function testGetAccessToken()
    {
        $accessToken = SecureKey::make();

        $id = $this->sm->createSession('abc', 'http://example.com', 'user', null, null, $accessToken);
        $this->assertGreaterThan(0, $id);

        // Test that the access token is returned if found.
        $this->assertEquals($accessToken, $this->sm->getAccessToken($id));

        // Test that null is returned otherwise.
        $this->assertNull($this->sm->getAccessToken('invalid-session-id'));

    }

    public function testValidateRefreshToken()
    {
        $clientId = SecureKey::make();
        $refreshToken = SecureKey::make();

        $id = $this->sm->createSession($clientId, 'http://example.com', 'user', null, null, null, $refreshToken);
        $this->assertGreaterThan(0, $id);

        // Test that session ID is returned if refresh token is valid.
        $this->assertEquals($id, $this->sm->validateRefreshToken($refreshToken, $clientId));

        // Test that false is returned if refresh token is not valid.
        $this->assertFalse($this->sm->validateRefreshToken('invalid-refresh-token', $clientId));
    }

    public function testUpdateRefreshToken()
    {
        $accessToken = 'xxx';
        $refreshToken = 'yyy';
        $expires = 999999;

        $id = $this->sm->createSession('aaa', 'http://example.com');
        $this->assertGreaterThan(0, $id);

        $this->sm->updateRefreshToken($id, $accessToken, $refreshToken, $expires);

        $db_data = $this->getSessionDataFromDb($id);
        $this->assertEquals($accessToken, $db_data['access_token']);
        $this->assertEquals($refreshToken, $db_data['refresh_token']);
        $this->assertEquals($expires, $db_data['access_token_expires']);
    }


    public function testAssociateScope()
    {
        $sessionId = 123;
        $scopeId = 321;

        $this->sm->associateScope($sessionId, $scopeId);

        $db_data = $this->getPdo()->query('SELECT * FROM oauth_session_scopes')->fetch(PDO::FETCH_ASSOC);
        $this->assertEquals($sessionId, $db_data['session_id']);
        $this->assertEquals($scopeId, $db_data['scope_id']);
    }

    public function testGetScopes()
    {
        $sessionId = 222;
        $scopeId = 123;
        $scope = 'foo';
        $scopeId2 = 124;
        $scope2 = 'foo2';

        // Set up the test fixture
        $stmt = $this->getPdo()->prepare('INSERT INTO oauth_scopes (id, scope) VALUES (:scopeId, :scope)');
        $stmt->execute(array(':scopeId' => $scopeId, ':scope' => $scope));
        $stmt->execute(array(':scopeId' => $scopeId2, ':scope' => $scope2));
        $this->sm->associateScope($sessionId, $scopeId);
        $this->sm->associateScope($sessionId, $scopeId2);

        $result = $this->sm->getScopes($sessionId);
        $this->assertInternalType('array', $result);
        $this->assertContains($scope, $result);
        $this->assertContains($scope2, $result);

        // Test that an empty array is returned if no scopes are found.
        $result = $this->sm->getScopes('invalid-session-id');
        $this->assertInternalType('array', $result);
        $this->assertEmpty($result);
    }

    /*
    public function testAreTablesGettingTruncated()
    {
        var_dump($this->getPdo()->query('SELECT * FROM oauth_sessions')->fetchAll());
    }
    */

}