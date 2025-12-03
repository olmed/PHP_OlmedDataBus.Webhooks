# Olmed DataBus Webhook Helpers

A PHP library for secure webhook payload encryption, decryption and verification using AES-256-CBC encryption and HMAC-SHA256 signatures.

## Requirements

- PHP >= 7.0
- OpenSSL extension
- JSON extension

## Installation

Install via Composer:

```bash
composer require olmed/databus-webhook-helpers
```

## Usage

### Basic Example

```php
<?php

require_once 'vendor/autoload.php';

use Olmed\DataBus\Webhooks\SecureWebhookHelper;

// Initialize with your encryption and HMAC keys (both must be 32 bytes)
$encryptionKey = 'your-32-byte-encryption-key!!';
$hmacKey = 'your-32-byte-hmac-secret-key!!';

$helper = new SecureWebhookHelper($encryptionKey, $hmacKey);

// Webhook data received from request
$guid = $_POST['guid'];
$webhookType = $_POST['webhookType'];
$encryptedPayload = $_POST['payload']; // Base64 encoded with IV prefix
$signature = $_POST['signature']; // HMAC-SHA256 signature

// Decrypt and verify
$decryptedJson = '';
$isValid = $helper->tryDecryptAndVerifyWithIvPrefix(
    $guid,
    $webhookType,
    $encryptedPayload,
    $signature,
    $decryptedJson
);

if ($isValid) {
    // Successfully decrypted and verified
    $webhookData = json_decode($decryptedJson, true);
    echo "Webhook verified successfully!\n";
    print_r($webhookData);
} else {
    // Failed to decrypt or verify signature
    http_response_code(401);
    echo "Invalid webhook signature or corrupted payload";
}
```

### Complete Webhook Endpoint Example

```php
<?php

require_once 'vendor/autoload.php';

use Olmed\DataBus\Webhooks\SecureWebhookHelper;

// Your secret keys (store these securely, e.g., in environment variables)
$encryptionKey = getenv('WEBHOOK_ENCRYPTION_KEY');
$hmacKey = getenv('WEBHOOK_HMAC_KEY');

try {
    $helper = new SecureWebhookHelper($encryptionKey, $hmacKey);
    
    // Get POST data
    $postData = json_decode(file_get_contents('php://input'), true);
    
    $guid = $postData['guid'] ?? '';
    $webhookType = $postData['webhookType'] ?? '';
    $payload = $postData['payload'] ?? '';
    $signature = $postData['signature'] ?? '';
    
    $decryptedJson = '';
    $isValid = $helper->tryDecryptAndVerifyWithIvPrefix(
        $guid,
        $webhookType,
        $payload,
        $signature,
        $decryptedJson
    );
    
    if ($isValid) {
        $data = json_decode($decryptedJson, true);
        
        // Process your webhook data here
        processWebhook($webhookType, $data);
        
        http_response_code(200);
        echo json_encode(['status' => 'success']);
    } else {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Invalid signature']);
    }
    
} catch (InvalidArgumentException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Configuration error']);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server error']);
}

function processWebhook($type, $data) {
    // Your webhook processing logic here
    error_log("Processing webhook type: {$type}");
}
```

## How It Works

### Encryption Format

The payload is encrypted using AES-256-CBC with the following structure:
1. A random 16-byte Initialization Vector (IV) is generated
2. The data is encrypted using AES-256-CBC
3. The IV is prepended to the encrypted data
4. The combined data (IV + encrypted) is base64-encoded

### Verification Process

1. The base64 payload is decoded
2. The IV (first 16 bytes) is extracted
3. The remaining data is decrypted using AES-256-CBC
4. A JSON structure is reconstructed: `{"guid":"...","webhookType":"...","webhookData":{...}}`
5. An HMAC-SHA256 signature is computed for this JSON
6. The computed signature is compared with the provided signature

### Security Features

- **AES-256-CBC encryption** - Industry-standard encryption
- **HMAC-SHA256 signatures** - Prevents tampering and ensures authenticity
- **Timing-attack safe comparison** - Uses `hash_equals()` for signature verification
- **32-byte keys required** - Enforces strong key lengths

## Key Generation

To generate secure 32-byte keys, you can use:

```php
<?php
// Generate encryption key
$encryptionKey = bin2hex(random_bytes(16)); // 32 characters
echo "Encryption Key: " . $encryptionKey . "\n";

// Generate HMAC key
$hmacKey = bin2hex(random_bytes(16)); // 32 characters
echo "HMAC Key: " . $hmacKey . "\n";
```

Or use OpenSSL from command line:
```bash
openssl rand -hex 16
```

## API Reference

### `SecureWebhookHelper`

#### Constructor

```php
public function __construct(string $encryptionKey, string $hmacKey)
```

**Parameters:**
- `$encryptionKey` - 32-byte encryption key
- `$hmacKey` - 32-byte HMAC key

**Throws:**
- `InvalidArgumentException` - If keys are not exactly 32 bytes

#### `tryDecryptAndVerifyWithIvPrefix`

```php
public function tryDecryptAndVerifyWithIvPrefix(
    string $guid,
    string $webhookType,
    string $base64PayloadWithIv,
    string $signature,
    string &$decryptedJson
): bool
```

**Parameters:**
- `$guid` - Webhook GUID
- `$webhookType` - Type of webhook
- `$base64PayloadWithIv` - Base64-encoded encrypted payload with IV prefix
- `$signature` - HMAC-SHA256 signature (hex string)
- `$decryptedJson` - Output parameter containing decrypted JSON on success

**Returns:**
- `true` if decryption and verification succeeded
- `false` if decryption failed or signature is invalid

### Local Development (Laravel)

If you want to develop and test this package locally in your Laravel project before publishing to Packagist, you can load it directly via autoload.

1. Edit your Laravel project's `composer.json` and add to the `autoload-dev` section:

```json
{
    "autoload-dev": {
        "psr-4": {
            "Olmed\\DataBus\\Webhooks\\": "/absolute/path/to/PHP_OlmedDataBus.Webhooks/src/"
        }
    }
}
```

2. Reload the autoloader:

```bash
composer dump-autoload
```

3. Now you can use the class in your Laravel application:

```php
<?php

use Olmed\DataBus\Webhooks\SecureWebhookHelper;

$helper = new SecureWebhookHelper(
    config('webhooks.encryption_key'),
    config('webhooks.hmac_key')
);
```

Any changes you make to the source files in `/absolute/path/to/PHP_OlmedDataBus.Webhooks/src/` will be immediately available in your Laravel project.

**Note:** Remember to remove this entry from `autoload-dev` and install the package normally via Composer once it's published to Packagist.
