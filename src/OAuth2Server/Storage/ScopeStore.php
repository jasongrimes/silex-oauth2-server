<?php

namespace OAuth2Server\Storage;

use Doctrine\DBAL\Connection;
use League\OAuth2\Server\Storage\ScopeInterface;

class ScopeStore implements ScopeInterface
{
    /** @var Connection */
    protected $conn;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn;
    }

    /**
     * Return information about a scope
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [id] => (int) The scope's ID
     *     [scope] => (string) The scope itself
     *     [name] => (string) The scope's name
     *     [description] => (string) The scope's description
     * )
     * </code>
     *
     * @param  string     $scope     The scope
     * @param  string     $clientId  The client ID
     * @param  string     $grantType The grant type used in the request
     * @return bool|array If the scope doesn't exist return false
     */
    public function getScope($scope, $clientId = null, $grantType = null)
    {
        return $this->conn->fetchAssoc('SELECT * FROM oauth_scopes WHERE scope = ?', array($scope));
    }
}