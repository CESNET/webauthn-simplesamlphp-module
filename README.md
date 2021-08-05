# simplesamlphp-module-webauthn

[![CodeFactor](https://www.codefactor.io/repository/github/cesnet/simplesamlphp-module-webauthn/badge/main)](https://www.codefactor.io/repository/github/cesnet/simplesamlphp-module-webauthn/overview/main)

## Installation

```
cd /var/simplesamlphp/modules
git clone https://github.com/CESNET/simplesamlphp-module-webauthn.git webauthn
```

## Example configuration

If the flask module runs at `https://flask.example.com/webauthn/`, use the following auth proc filter:

```
50 => [
    'class' => 'webauthn:WebAuthn',
    'redirect_url' => 'https://flask.example.com/webauthn/authentication_request',
    'api_url' => 'https://flask.example.com/webauthn/request',
    'signing_key' => '/var/webauthn_private.pem',
    'user_id' => 'uid',
    'skip_redirect_url' => 'https://example.com/simplesaml/switchMethods.php',
    'hide_manage_tokens' => 'hide_manage_tokens',
],
```

Then you have to adjust the configuration of the flask module. If your SimpleSAMLphp installation is available at `https://example.com/simplesaml/`, use the following URL as the `callback-url` in the flask module's `config.yaml`:

```
https://example.com/simplesaml/module.php/webauthn/handleResponse.php
```
