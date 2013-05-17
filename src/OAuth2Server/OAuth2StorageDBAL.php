<?php

namespace OAuth2Server;

use Doctrine\DBAL\Connection;
use OAuth2\IOAuth2GrantUser;
use OAuth2\IOAuth2Storage;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\OAuth2Client;
use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\OAuth2AccessToken;
use InvalidArgumentException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class OAuth2StorageDBAL implements IOAuth2Storage, IOAuth2GrantUser
{
    /** @var \Doctrine\DBAL\Connection */
    protected $conn;

    /** @var UserProviderInterface */
    protected $userProvider;

    /** @var EncoderFactoryInterface */
    protected $encoderFactory;

    public function __construct(Connection $conn, UserProviderInterface $userProvider, EncoderFactoryInterface $encoderFactory)
    {
        $this->conn = $conn;
        $this->userProvider = $userProvider;
        $this->encoderFactory = $encoderFactory;
    }

    /**
     * Get a client by its ID.
     *
     * @param string $client_id
     * @return OAuth2Client
     */
    public function getClient($client_id)
    {
        $client_data = $this->conn->fetchAssoc('SELECT * FROM oauth2_clients WHERE id = ?', array($client_id));
        if ($client_data === false) {
            return null;
        }

        $result = $this->conn->fetchAll('SELECT redirect_uri FROM oauth2_client_redirect_uris WHERE client_id = ?', array($client_id));
        $redirect_uris = $result ? array_values($result) : array();

        $client = new OAuth2Client($client_data['id'], $client_data['secret'], $redirect_uris);

        return $client;
    }

    /**
     * Make sure that the client credentials are valid.
     *
     * @param IOAuth2Client $client
     * The client for which to check credentials.
     * @param string $client_secret
     * (optional) If a secret is required, check that they've given the right one.
     *
     * @return boolean
     * TRUE if the client credentials are valid, and MUST return FALSE if they aren't.
     * @endcode
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1
     *
     * @ingroup oauth2_section_3
     * @throws InvalidArgumentException if $client doesn't implement CheckableSecretInterface.
     */
    public function checkClientCredentials(IOAuth2Client $client, $client_secret = NULL)
    {
        return $client->checkSecret($client_secret);
    }

    /**
     * Look up the supplied oauth_token from storage.
     *
     * We need to retrieve access token data as we create and verify tokens.
     *
     * @param string $oauth_token
     * The token string.
     *
     * @return IOAuth2AccessToken
     *
     * @ingroup oauth2_section_7
     */
    public function getAccessToken($oauth_token)
    {
        $data = $this->conn->fetchAssoc('SELECT * FROM oauth2_access_tokens WHERE oauth_token = ?', array($oauth_token));
        if ($data === false) {
            return null;
        }

        return new OAuth2AccessToken($data['client_id'], $data['oauth_token'], $data['expires'], $data['scope'], $data['user_id']);
    }

    /**
     * Store the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param string $oauth_token
     * The access token string to be stored.
     * @param IOAuth2Client $client
     * The client associated with this refresh token.
     * @param mixed $data
     * The user_id
     * @param int $expires
     * The timestamp when the refresh token will expire.
     * @param string $scope
     * (optional) Scopes to be stored in space-separated string.
     * @return OAuth2AccessToken
     *
     * @ingroup oauth2_section_4
     */
    public function createAccessToken($oauth_token, IOAuth2Client $client, $data, $expires, $scope = NULL)
    {
        $sql = 'INSERT INTO oauth2_access_tokens
            (oauth_token, client_id, user_id, expires, scope)
            VALUES (:oauth_token, :client_id, :user_id, :expires, :scope) ';
        $params = array(
            'oauth_token' => $oauth_token,
            'client_id' => $client->getPublicId(),
            'user_id' => $data->getId(),
            'expires' => $expires,
            'scope' => $scope ?: '',
        );

        $this->conn->executeUpdate($sql, $params);

        $token = new OAuth2AccessToken($client->getPublicId(), $oauth_token, $expires, $scope, $data);

        return $token;
    }

    /**
     * Check restricted grant types of corresponding client identifier.
     *
     * If you want to restrict clients to certain grant types, override this
     * function.
     *
     * @param IOAuth2Client $client
     * Client to check.
     * @param string $grant_type
     * Grant type to check. One of the values contained in OAuth2::GRANT_TYPE_REGEXP.
     *
     * @return boolean
     * TRUE if the grant type is supported by this client identifier, and
     * FALSE if it isn't.
     *
     * @ingroup oauth2_section_4
     */
    public function checkRestrictedGrantType(IOAuth2Client $client, $grant_type)
    {
        return true;
    }

    /**
     * Grant access tokens for basic user credentials.
     *
     * Check the supplied username and password for validity.
     *
     * You can also use the $client_id param to do any checks required based
     * on a client, if you need that.
     *
     * Required for OAuth2::GRANT_TYPE_USER_CREDENTIALS.
     *
     * @param IOAuth2Client $client
     * Client to be check with.
     * @param $username
     * Username to be check with.
     * @param $password
     * Password to be check with.
     *
     * @return boolean
     * TRUE if the username and password are valid, and FALSE if it isn't.
     * Moreover, if the username and password are valid, and you want to
     * verify the scope of a user's access, return an associative array
     * with the scope values as below. We'll check the scope you provide
     * against the requested scope before providing an access token:
     * @code
     * return array(
     * 'scope' => <stored scope values (space-separated string)>,
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.3
     *
     * @ingroup oauth2_section_4
     */
    public function checkUserCredentials(IOAuth2Client $client, $username, $password)
    {
        try {
            $user = $this->userProvider->loadUserByUsername($username);
        } catch(AuthenticationException $e) {
            return false;
        }

        if (null !== $user) {
            $encoder = $this->encoderFactory->getEncoder($user);

            if ($encoder->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
                return array(
                    'data' => $user,
                );
            }
        }

        return false;
    }
}