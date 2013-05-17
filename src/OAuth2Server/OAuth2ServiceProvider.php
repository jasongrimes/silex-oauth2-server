<?php

namespace OAuth2Server;

use Silex\Application;
use Silex\ServiceProviderInterface;
use \RuntimeException;
use OAuth2\OAuth2;

class OAuth2ServiceProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given app.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     *
     * @param Application $app An Application instance
     * @throws RuntimeException if options are invalid.
     */
    public function register(Application $app)
    {
        $app['security.authentication_listener.factory.oauth2'] = $app->protect(function ($name, $options) use ($app) {

            $app['oauth2.storage'] = $app->share(function() use ($app, $name) {
                // TODO: the user provider and encoder factory may not be needed for some grant types.
                // TODO: set dependencies based on configured grant types.
                return new OAuth2StorageDBAL($app['db'], $app['security.user_provider.' . $name], $app['security.encoder_factory']);
            });

            $app['oauth2'] = $app->share(function() use ($app, $options) {
                return new OAuth2($app['oauth2.storage'], (array) $options);
            });

            // define the authentication provider object
            $app['security.authentication_provider.'.$name.'.oauth2'] = $app->share(function () use ($app, $name) {
                return new OAuth2AuthenticationProvider($app['security.user_provider.' . $name], $app['oauth2']);
            });

            // define the authentication listener object
            $app['security.authentication_listener.'.$name.'.oauth2'] = $app->share(function () use ($app) {
                return new OAuth2Listener($app['security'], $app['security.authentication_manager'], $app['oauth2']);
            });

            return array(
                // the authentication provider id
                'security.authentication_provider.'.$name.'.oauth2',
                // the authentication listener id
                'security.authentication_listener.'.$name.'.oauth2',
                // the entry point id
                null,
                // the position of the listener in the stack
                'pre_auth'
            );
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
