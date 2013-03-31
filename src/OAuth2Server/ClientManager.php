<?php

namespace OAuth2Server;

use Doctrine\DBAL\Connection;
use PDO;
use OAuth2\Storage\ClientInterface;

class ClientManager implements ClientInterface
{
    /** @var PDO */
    protected $conn;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn->getWrappedConnection();
    }

    /**
     * Validate a client.
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [client_id] => (string) The client ID
     *     [client secret] => (string) The client secret
     *     [redirect_uri] => (string) The redirect URI used in this request (if any).
     *     [name] => (string) The name of the client
     * )
     * </code>
     *
     * @param  string     $clientId     The client's ID
     * @param  string     $clientSecret The client's secret (default = "null")
     * @param  string     $redirectUri  The client's redirect URI (default = "null")
     * @return bool|array               Returns false if the validation fails, array on success
     */
    public function getClient($clientId = null, $clientSecret = null, $redirectUri = null)
    {
        $sql = 'SELECT oauth_clients.id AS client_id, secret AS client_secret, name ';
        if ($redirectUri) $sql .= ', redirect_uri ';
        $sql .= 'FROM oauth_clients ';
        if ($redirectUri) $sql .= 'JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id ';


        $sql .= 'WHERE oauth_clients.id = :clientId ';
        $params = array(':clientId' => $clientId);

        if ($clientSecret) {
            $sql .= 'AND secret = :clientSecret ';
            $params[':clientSecret'] = $clientSecret;
        }

        if ($redirectUri) {
            $sql .= 'AND redirect_uri = :redirectUri ';
            $params[':redirectUri'] = $redirectUri;
        }

        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}