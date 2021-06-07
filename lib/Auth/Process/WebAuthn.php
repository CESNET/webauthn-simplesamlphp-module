<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Auth\Process;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Easy\Build;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;

/**
 * Authentication Processing filter.
 */
class WebAuthn extends ProcessingFilter
{
    private $redirect_url = '';
    private $api_url = '';
    private $user_id_name = '';
    private $signing_key = '';
    private $skip_redirect_url = '';

    /**
     * Initialize the filter.
     *
     * @param array $config   configuration information about this filter
     * @param mixed $reserved For future use
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);
        $config = Configuration::loadFromArray($config);
        $this->redirect_url = $config->getString('redirect_url', null);
        $this->api_url = $config->getString('api_url', null);
        $this->user_id_name = $config->getString('user_id', null);
        $this->signing_key = $config->getString('signing_key', null);
        $this->skip_redirect_url = $config->getString('skip_redirect_url', null);
    }

    /**
     * Apply filter.
     *
     * @param array $state The current state
     */
    public function process(&$state): void
    {
        if (! is_array($state)) {
            throw new \Exception('State is not an array');
        }
        if (! isset($state['Attributes'])) {
            throw new \Exception('State does not include Attributes');
        }
        $attributes = $state['Attributes'];
        if (! array_key_exists($this->user_id_name, $attributes)) {
            throw new \Exception('User id not found in Attributes');
        }
        $user_id = $attributes[$this->user_id_name][0];
        $actual_time = strval(time());
        $random_string = $actual_time.bin2hex(random_bytes(4));

        $state['random_string'] = $random_string;
        $state['api_user_id'] = $user_id;
        $state['signing_key'] = $this->signing_key;
        $state['api_url'] = $this->api_url;
        $state['skip_redirect_url'] = $this->skip_redirect_url;
        $id = \SimpleSAML\Auth\State::saveState($state, 'webauthn:request', true);
        $request = [
            'user_id' => $user_id,
            'nonce' => $id.';'.$random_string,
            'time' => $actual_time,
        ];

        $jwk = JWKFactory::createFromKeyFile(
            $this->signing_key, // The filename
            null,                   // Secret if the key is encrypted
            [
                'use' => 'sig',
                // Additional parameters
            ]
        );
        $jws = Build::jws() // We build a JWS
            ->alg('RS256') // The signature algorithm. A string or an algorithm class.
            ->payload($request)
            ->sign($jwk) // Compute the token with the given JWK
        ;

        $url = $this->redirect_url.'/'.$jws;
        \SimpleSAML\Utils\HTTP::redirectUntrustedURL($url);
    }
}
