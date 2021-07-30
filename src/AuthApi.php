<?php

namespace ApiSdk;

use RpContracts\RequestProvider;
use RpContracts\Response;

class AuthApi
{
    /**
     * @var RequestProvider
     */
    public RequestProvider $provider;

    /**
     * @var string
     */
    protected string $clientId;

    /**
     * @var string
     */
    protected string $clientSecret;

    /**
     * @var string
     */
    protected string $oauthCallback;

    /**
     * @var string
     */
    public string $env;

    /**
     * @var string
     */
    public string $app;

    /**
     * AuthApi constructor.
     * @param RequestProvider $provider
     * @param string $clientId
     * @param string $clientSecret
     * @param string $oauthCallback
     * @param string $env
     * @param string $app
     */
    public function __construct(RequestProvider $provider, string $clientId, string $clientSecret, string $oauthCallback, string $env, string $app)
    {
        $this->provider = $provider;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->oauthCallback = $oauthCallback;
        $this->env = $env;
        $this->app = $app;
    }

    /**
     * @param $code
     * @return string|null
     */
    public function getClientToken($code) : ?string
    {
        $data = $this->provider->request('oauth/token', 'post',  [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->oauthCallback,
            'code' => $code,
        ])->getContents();


        if($data and isset($data['access_token']) and $data['access_token'])
        {
            return $data['access_token'];
        }

        return null;
    }

    /**
     * @param $email
     * @param $password
     * @return string|null
     */
    public function getClientTokenByAuth($email, $password) : ?string
    {
        $data = $this->provider->request('oauth/token','post',  [
            'grant_type' => 'password',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'username' => $email,
            'password' => $password,
            'scope' => '',
        ])->getContents();

        if($data and isset($data['access_token']) and $data['access_token'])
        {
            return $data['access_token'];
        }

        return null;
    }

    /**
     * @param $token
     * @return array|null
     */
    public function getUserByToken($token) : ?array
    {
        $data = $this->provider->request('api/user?env='.$this->env.'&app='.$this->app, 'get',  [], [
            'Authorization' => 'Bearer ' .$token
        ])->getContents();

        if(is_array($data))
        {
            return $data;
        }

        return null;
    }

    /**
     * @param $token
     * @param null $name
     * @param null $email
     * @param null $password
     * @return array|null
     */
    public function editUserByToken($token, $name = null, $email = null, $password = null) : ?array
    {
        $data = $this->provider->request('api/user', 'post', [
            'name' => $name,
            'email' => $email,
            'password' => $password
        ], [
            'Authorization' => 'Bearer ' .$token
        ])->getContents();

        if(is_array($data))
        {
            return $data;
        }

        return null;
    }

    /**
     * @param $email
     * @param $name
     * @param $password
     * @return array|null
     */
    public function createUser($email, $name, $password) : ?array
    {
        $data = $this->provider->request('api/register', 'post', [
            'email' => $email,
            'name' => $name,
            'password' => $password
        ])->getContents();

        if(is_array($data))
        {
            return $data;
        }

        return null;
    }

    /**
     * @param $email
     * @return array|null
     */
    public function info($email) : ?array
    {
        $data = $this->provider->request('api/info', 'post', ['email' => $email])->getContents();

        if(is_array($data))
        {
            return $data;
        }

        return null;
    }

    /**
     * @param $email
     * @return string|null
     */
    public function getResetPasswordToken($email) : ?string
    {
        $data = $this->provider->request('api/reset_password_token','post', ['email' => $email])->getContents();

        if(is_array($data) and isset($data['token']))
        {
            return $data['token'];
        }

        return null;
    }

    /**
     * @param $email
     * @param $password
     * @param $token
     * @return bool
     */
    public function resetPassword($email, $password, $token) : bool
    {
        $data = $this->provider->request('api/reset_password', 'post', [
            'email' => $email,
            'password' => $password,
            'password_confirmation' => $password,
            'token' => $token,
        ])->getContents();

        if(is_array($data) and isset($data['success']))
        {
            return $data['success'];
        }

        return false;
    }
}
