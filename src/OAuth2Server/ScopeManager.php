<?php

namespace OAuth2Server;

use Doctrine\DBAL\Connection;
use PDO;
use OAuth2\Storage\ScopeInterface;

class ScopeManager implements ScopeInterface
{
    /** @var PDO */
    protected $conn;

    public function __construct(Connection $conn)
    {
        $this->conn = $conn->getWrappedConnection();
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
     * @param  string     $scope The scope
     * @return bool|array If the scope doesn't exist return false
     */
    public function getScope($scope)
    {
        $stmt = $this->conn->prepare('SELECT * FROM oauth_scopes WHERE scope = ?');
        $stmt->execute(array($scope));
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}