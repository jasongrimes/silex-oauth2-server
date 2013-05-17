<?php

namespace OAuth2Server;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;

/**
 * OAuthProvider class.
 *
 * @author  Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuth2AuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var \Symfony\Component\Security\Core\User\UserProviderInterface
     */
    protected $userProvider;
    /**
     * @var \OAuth2\OAuth2
     */
    protected $oauthServer;

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $userProvider The user provider.
     * @param \OAuth2\OAuth2 $oauthServer The OAuth2 server service.
     */
    public function __construct(UserProviderInterface $userProvider, OAuth2 $oauthServer)
    {
        $this->userProvider = $userProvider;
        $this->oauthServer = $oauthServer;
    }

    /**
     * @param TokenInterface $token
     * @return OAuth2Token|null
     * @throws AuthenticationException
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        try {
            $tokenString = $token->getAccessTokenStr();

            if ($accessToken = $this->oauthServer->verifyAccessToken($tokenString)) {
                $scope = $accessToken->getScope();
                $user  = $accessToken->getUser();

                $roles = (null !== $user) ? $user->getRoles() : array();

                if (!empty($scope)) {
                    foreach (explode(' ', $scope) as $role) {
                        $roles[] = 'ROLE_' . strtoupper($role);
                    }
                }

                $token = new OAuth2Token($roles);
                $token->setAuthenticated(true);
                $token->setAccessTokenStr($tokenString);

                if (null !== $user) {
                    $token->setUser($user);
                }

                return $token;
            }
        } catch (OAuth2ServerException $e) {
            if (!method_exists('Symfony\Component\Security\Core\Exception\AuthenticationException', 'setToken')) {
                // Symfony 2.1
                throw new AuthenticationException('OAuth2 authentication failed', null, 0, $e);
            }

            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }

        throw new AuthenticationException('OAuth2 authentication failed');
    }

    /**
     * @param TokenInterface $token
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuth2Token;
    }
}