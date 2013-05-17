<?php

namespace OAuth2Server\Test;

use OAuth2Server\OAuth2StorageDBAL;
use Doctrine\DBAL\DriverManager;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use OAuth2\Random;
use OAuth2\Model\OAuth2Client;

class OAuth2StorageDBALTest extends AbstractDbTestCase
{
    /** @var \PHPUnit_Framework_MockObject_MockObject */
    protected $userProvider;

    /** @var OAuth2StorageDBAL */
    protected $storage;

    public function setUp()
    {
        $this->userProvider = $this->getMockForAbstractClass('Symfony\Component\Security\Core\User\UserProviderInterface');
        $encoderFactory = new EncoderFactory(array('Symfony\Component\Security\Core\User\UserInterface' => new PlaintextPasswordEncoder()));

        $this->storage = new OAuth2StorageDBAL($this->getDbal(), $this->userProvider, $encoderFactory);
    }

    public function testCreateInstance()
    {
        $this->assertInstanceOf('OAuth2Server\OAuth2StorageDBAL', $this->storage);
    }

    public function testGetClient()
    {
        $client_id = Random::generateToken();
        $secret = Random::generateToken();
        $this->getDbal()->executeUpdate('INSERT INTO oauth2_clients (id, secret) VALUES (:id, :secret)', array(
            'id' => $client_id,
            'secret' => $secret,
        ));

        $sql = 'INSERT INTO oauth2_client_redirect_uris (client_id, redirect_uri) VALUES (:client_id, :redirect_uri)';
        $this->getDbal()->executeUpdate($sql, array('client_id' => $client_id, 'redirect_uri' => 'http://www.example.com/foo'));
        $this->getDbal()->executeUpdate($sql, array('client_id' => $client_id, 'redirect_uri' => 'http://foo.example.com/bar'));

        $client = $this->storage->getClient($client_id);
        $this->assertInstanceOf('OAuth2\Model\OAuth2Client', $client);
    }

    public function testCheckClientCredentials()
    {
        $secret = 'some-secret';
        $client = new OAuth2Client('some-id', $secret);

        $this->AssertTrue($this->storage->checkClientCredentials($client, $secret));
        $this->AssertFalse($this->storage->checkClientCredentials($client, 'incorrect-secret'));

    }

    public function testGetAccessToken()
    {
        $tokenStr = Random::generateToken();
        $clientId = Random::generateToken();
        $userId = 'davidhume';

        $this->getDbal()->executeUpdate('INSERT INTO oauth2_access_tokens (oauth_token, client_id, user_id, expires) VALUES (:oauth_token, :client_id, :user_id, :expires)', array(
            'oauth_token' => $tokenStr,
            'client_id' => $clientId,
            'user_id' => $userId,
            'expires' => (time() + 3600),
        ));

        $token = $this->storage->getAccessToken($tokenStr);
        $this->assertInstanceOf('OAuth2\Model\OAuth2AccessToken', $token);

        $this->assertEquals($clientId, $token->getClientId());
        $this->assertEquals($userId, $token->getData());
        $this->assertFalse($token->hasExpired());

    }

    public function testGetAccessTokenReturnsNullOnInvalidToken() {
        $this->assertNull($this->storage->getAccessToken('invalid-token'));
    }

    public function testCreateAccessToken()
    {
        $tokenStr = Random::generateToken();
        $clientId = Random::generateToken();
        $client = new OAuth2Client($clientId);
        $userId = 'some-user';
        $expires = time() + 3600;
        $scope = 'SOME_SCOPE';

        $token = $this->storage->createAccessToken($tokenStr, $client, $userId, $expires, $scope);

        // Stores the token in the database.
        $this->assertNotEmpty($this->getDbal()->fetchAssoc('SELECT * FROM oauth2_access_tokens WHERE oauth_token = ?',
            array($tokenStr)));

        // Also returns the generated token.
        $this->assertInstanceOf('OAuth2\Model\IOAuth2AccessToken', $token);
        $this->assertEquals($clientId, $token->getClientId());
        $this->assertEquals($userId, $token->getData());
    }

    public function testCheckUserCredentials()
    {
        $clientId = Random::generateToken();
        $client = new OAuth2Client($clientId);
        $username = 'username';
        $password = 'password';

        $user = $this->getMockForAbstractClass('Symfony\Component\Security\Core\User\UserInterface');
        $user->expects($this->any())
            ->method('getPassword')
            ->will($this->returnValue($password));

        $this->userProvider
            ->expects($this->any())
            ->method('loadUserByUsername')
            ->will($this->returnValue($user))
            ;

        // returns array with data => $user if user/pass is valid.
        $result = $this->storage->checkUserCredentials($client, $username, $password);
        $this->assertInternalType('array', $result);
        $this->assertSame($user, $result['data']);

        // returns false if username or password is invalid
        $result = $this->storage->checkUserCredentials($client, $username, 'invalid-password');
        $this->assertFalse($result);
    }

}