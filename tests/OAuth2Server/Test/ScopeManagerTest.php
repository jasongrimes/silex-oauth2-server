<?php

namespace OAuth2Server\Test;

use OAuth2Server\ScopeManager;

class ScopeManagerTest extends AbstractDbTestCase
{
    /** @var ScopeManager */
    protected $sm;

    public function setUp()
    {
        $this->sm = new ScopeManager($this->getPdo());

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

        $result = $this->sm->getScope($scope);
        $this->assertEquals($id, $result['id']);
        $this->assertEquals($scope, $result['scope']);
        $this->assertEquals($name, $result['name']);
        $this->assertEquals($description, $result['description']);

        // Test that false is returned if scope doesn't exist
        $this->assertFalse($this->sm->getScope('non-existent-scope'));
    }

}