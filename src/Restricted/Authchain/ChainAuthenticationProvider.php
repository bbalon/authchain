<?php

/**
 * This file is part of authchain, Laravel 4 chain authentication provider
 *
 * @author    Alexey Dementyev <alexey.dementyev@gmail.com>
 * @copyright Alexey Dementyev (c) 2013
 *
 **/

namespace Restricted\Authchain;

use Hash;
use Session;
use Redirect;
use Illuminate\Auth\UserInterface;
use Illuminate\Auth\UserProviderInterface;
use Restricted\Authchain\Config\Loader;
use Restricted\Authchain\Resolver\DelegatingAuthentication;

/**
 * Class ChainAuthenticationProvider
 *
 * @package Restricted\Authchain
 */
class ChainAuthenticationProvider implements UserProviderInterface
{
    /**
     * Delegator service
     *
     * @var DelegatingAuthentication $delegator
     */
    protected $delegator;

    /**
     * Constructor. Sets delegator.
     */
    public function __construct()
    {
        $this->delegator = new DelegatingAuthentication();
    }

    /**
     * @inheritdoc
     */
    public function retrieveByCredentials(array $credentials)
    {

        $identifier = Loader::username();
        $username = $credentials[Loader::username()];
        if ($user = $this->delegator->native()->findBy($identifier, $username)) {
            return $user;
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function validateCredentials(UserInterface $user, array $credentials)
    {
        $plain = $credentials[Loader::password()];

        if(!$user){
          return false;
        }

        if ($this->delegator->provider($credentials)->authenticate()) {
           return true;
        }

        if (Hash::check($plain, $user->getAuthPassword())) {
            return true;
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function retrieveById($identifier)
    {
        if ($user = $this->delegator->native()->find($identifier)) {
            return $user;
        }
        /**
         * Maybe user is removed or blocked in database but session still exists
         */
        Session::flush();

        return Redirect::refresh('302');
    }

    /**
     * Retrieve user by ip address
     *
     * @return bool|UserInterface
     */
    public function retrieveByIpAddress()
    {
        return $this->delegator->resolver()->get('ip')->authenticate();
    }

    /**
    * Needed by Laravel 4.1.26 and above
    */
    public function retrieveByToken($identifier, $token)
    {
        return new \Exception('not implemented');
    }

    /**
    * Needed by Laravel 4.1.26 and above
    */
    public function updateRememberToken(UserInterface $user, $token)
    {
        return new \Exception('not implemented');
    } 
}
