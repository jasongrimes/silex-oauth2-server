<?php

namespace OAuth2Server;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class OAuth2Token extends AbstractToken
{
    /**
     * @var string
     */
    protected $accessTokenStr;

    public function setAccessTokenStr($accessTokenStr)
    {
        $this->accessTokenStr = $accessTokenStr;
    }

    public function getAccessTokenStr()
    {
        return $this->accessTokenStr;
    }

    public function getCredentials()
    {
        return $this->accessTokenStr;
    }
}
