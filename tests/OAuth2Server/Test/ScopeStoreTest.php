<?php

namespace OAuth2Server\Test;

use OAuth2Server\Storage\ScopeStore;

class ScopeStoreTest extends AbstractDbTestCase
{
    /** @var ScopeStore */
    protected $store;

    public function setUp()
    {
        $this->store = new ScopeStore($this->getDbal());

        parent::setUp();
    }

    public function testGetScope()
    {
        $scope = 'testscope';
        $id = 123;
        $name = 'Test name';
        $description = 'Test description';

        $stmt = $this->getPdo()->prepare('INSERT INTO oauth_scopes (id, scope, name, description) VALUES (:id, :scope, :name, :description)');
        $stmt->execute(array(':id' => $id, ':scope' => $scope, ':name' => $name, ':description' => $description));

        $result = $this->store->getScope($scope);
        $this->assertEquals($id, $result['id']);
        $this->assertEquals($scope, $result['scope']);
        $this->assertEquals($name, $result['name']);
        $this->assertEquals($description, $result['description']);

        // Test that false is returned if scope doesn't exist
        $this->assertFalse($this->store->getScope('non-existent-scope'));
    }

}