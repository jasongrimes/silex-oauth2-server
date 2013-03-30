<?php

namespace OAuth2Server\Silex;

use OAuth2Server\ScopeManager;
use OAuth2Server\SessionManager;
use OAuth2Server\ClientManager;
use OAuth2\AuthServer;
use OAuth2\ResourceServer;
use Silex\Application;
use Silex\ServiceProviderInterface;

class OAuth2ServerProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given app.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     *
     * @param Application $app An Application instance
     */
    public function register(Application $app)
    {
        $app['oauth2.session_manager'] = $app->share(function() use ($app) {
            return new SessionManager($app['db']);
        });
        $app['oauth2.client_manager'] = $app->share(function() use ($app) {
            return new ClientManager($app['db']);
        });
        $app['oauth2.scope_manager'] = $app->share(function() use ($app) {
            return new ScopeManager($app['db']);
        });
        $app['oauth2.resource_server'] = $app->share(function() use ($app) {
            return new ResourceServer($app['oauth2.session_manager']);
        });
        $app['oauth2.auth_server'] = $app->share(function() use ($app) {
            return new AuthServer($app['oauth2.client_manager'], $app['oauth2.session_manager'], $app['oauth2.scope_manager']);
        });
    }

    /**
     * Bootstraps the application.
     *
     * This method is called after all services are registered
     * and should be used for "dynamic" configuration (whenever
     * a service must be requested).
     */
    public function boot(Application $app)
    {
    }

}