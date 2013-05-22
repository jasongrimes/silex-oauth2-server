<?php

namespace OAuth2Server\Storage;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Storage\ClientInterface;

class ClientStore implements ClientInterface
{
    /** @var Connection */
    protected $conn;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn;
    }

    /**
     * Validate a client
     *
     * Example SQL query:
     *
     * <code>
     * # Client ID + redirect URI
     * SELECT oauth_clients.id, oauth_clients.secret, oauth_client_endpoints.redirect_uri, oauth_clients.name
     *  FROM oauth_clients LEFT JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id
     *  WHERE oauth_clients.id = :clientId AND oauth_client_endpoints.redirect_uri = :redirectUri
     *
     * # Client ID + client secret
     * SELECT oauth_clients.id, oauth_clients.secret, oauth_clients.name FROM oauth_clients WHERE
     *  oauth_clients.id = :clientId AND oauth_clients.secret = :clientSecret
     *
     * # Client ID + client secret + redirect URI
     * SELECT oauth_clients.id, oauth_clients.secret, oauth_client_endpoints.redirect_uri, oauth_clients.name FROM
     *  oauth_clients LEFT JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id
     *  WHERE oauth_clients.id = :clientId AND oauth_clients.secret = :clientSecret AND
     *  oauth_client_endpoints.redirect_uri = :redirectUri
     * </code>
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [client_id] => (string) The client ID
     *     [client secret] => (string) The client secret
     *     [redirect_uri] => (string) The redirect URI used in this request
     *     [name] => (string) The name of the client
     * )
     * </code>
     *
     * @param  string     $clientId     The client's ID
     * @param  string     $clientSecret The client's secret (default = "null")
     * @param  string     $redirectUri  The client's redirect URI (default = "null")
     * @param  string     $grantType    The grant type used in the request (default = "null")
     * @return bool|array               Returns false if the validation fails, array on success
     */
    public function getClient($clientId, $clientSecret = null, $redirectUri = null, $grantType = null)
    {
        $sql = 'SELECT oauth_clients.id AS client_id, secret AS client_secret, name ';
        if ($redirectUri !== null) $sql .= ', redirect_uri ';
        $sql .= 'FROM oauth_clients ';
        if ($redirectUri !== null) $sql .= 'JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id ';


        $sql .= 'WHERE oauth_clients.id = :clientId ';
        $params = array(':clientId' => $clientId);

        if ($clientSecret !== null) {
            $sql .= 'AND secret = :clientSecret ';
            $params[':clientSecret'] = $clientSecret;
        }

        if ($redirectUri !== null) {
            $sql .= 'AND redirect_uri = :redirectUri ';
            $params[':redirectUri'] = $redirectUri;
        }

        return $this->conn->fetchAssoc($sql, $params);
    }
}