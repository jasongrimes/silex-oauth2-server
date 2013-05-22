<?php

namespace OAuth2Server\Test;

use PDO;
use PHPUnit_Extensions_Database_DataSet_YamlDataSet;
use Doctrine\DBAL\DriverManager;

abstract class AbstractDbTestCase extends \PHPUnit_Extensions_Database_TestCase
{
    // Only instantiate pdo and dbal once for test clean-up/fixture load.
    static private $pdo = null;
    static private $dbal = null;

    // Only instantiate PHPUnit_Extensions_Database_DB_IDatabaseConnection once per test.
    private $conn = null;

    /**
     * @return null|\PHPUnit_Extensions_Database_DB_DefaultDatabaseConnection|\PHPUnit_Extensions_Database_DB_IDatabaseConnection
     */
    final public function getConnection()
    {
        if ($this->conn === null) {
            if (self::$pdo == null) {
                self::$pdo = new PDO('sqlite::memory:');
                $this->createSchema(self::$pdo);
            }
            $this->conn = $this->createDefaultDBConnection(self::$pdo, ':memory:');
        }

        return $this->conn;
    }

    /**
     * @return PDO
     */
    protected function getPdo()
    {
        return $this->getConnection()->getConnection();
    }

    /**
     * @return \Doctrine\DBAL\Connection
     */
    protected function getDbal()
    {
        if (self::$dbal === null) {
            self::$dbal = DriverManager::getConnection(array('pdo' => $this->getPdo()));
        }

        return self::$dbal;
    }

    /**
     * @param PDO $conn
     */
    protected function createSchema(PDO $conn)
    {
        $sql = file_get_contents(__DIR__ . '/../../../sql/sqlite.sql');
        $statements = explode(';', $sql);
        foreach ($statements as $statement) {
            $conn->exec($statement);
        }
    }

    /**
     * Returns the test dataset.
     *
     * @return \PHPUnit_Extensions_Database_DataSet_IDataSet
     */
    protected function getDataSet()
    {
        return new PHPUnit_Extensions_Database_DataSet_YamlDataSet(__DIR__ . '/_files/data.yml');
    }
}