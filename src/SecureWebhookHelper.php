<?php

namespace Olmed\DataBus\Webhooks;

use InvalidArgumentException;
use Exception;

/**
 * SecureWebhookHelper - Helper class for secure webhook encryption and verification
 * 
 * This class provides methods to decrypt and verify webhook payloads that have been
 * encrypted using AES-256-CBC with HMAC-SHA256 signature verification.
 * 
 * @package Olmed\DataBus\Webhooks
 */
class SecureWebhookHelper
{
    /**
     * @var string Encryption key (must be 32 bytes)
     */
    private $encryptionKey;

    /**
     * @var string HMAC key (must be 32 bytes)
     */
    private $hmacKey;

    /**
     * Constructor
     * 
     * @param string $encryptionKey Encryption key (must be 32 bytes)
     * @param string $hmacKey HMAC key (must be 32 bytes)
     * @throws InvalidArgumentException If keys are not 32 bytes
     */
    public function __construct($encryptionKey, $hmacKey)
    {
        $this->encryptionKey = $encryptionKey;
        $this->hmacKey = $hmacKey;

        if (strlen($this->encryptionKey) !== 32) {
            throw new InvalidArgumentException('Encryption key must be 32 bytes.');
        }

        if (strlen($this->hmacKey) !== 32) {
            throw new InvalidArgumentException('HMAC key must be 32 bytes.');
        }
    }

    /**
     * Verify HMAC signature
     * 
     * @param string $payload The payload to verify
     * @param string $expectedSignature The expected HMAC signature (hex string)
     * @return bool True if signature is valid, false otherwise
     */
    private function verifySignature($payload, $expectedSignature)
    {
        $computed = hash_hmac('sha256', $payload, $this->hmacKey, false);
        $computedLower = strtolower($computed);
        $expectedLower = strtolower($expectedSignature);
        
        // Use hash_equals for timing-attack safe comparison (available in PHP 5.6+)
        // For PHP 7.0+ compatibility, we use it directly
        if (function_exists('hash_equals')) {
            return hash_equals($computedLower, $expectedLower);
        }
        
        // Fallback for older PHP versions (though we require 7.0+, hash_equals exists there)
        return $computedLower === $expectedLower;
    }

    /**
     * Encrypt webhook data using AES-256-CBC
     * 
     * This method encrypts the provided data array using AES-256-CBC encryption.
     * The IV (initialization vector) is prepended to the encrypted data.
     * 
     * @param array $webhookData The data to encrypt
     * @return string Base64-encoded encrypted data with IV prefix
     * @throws Exception If encryption fails
     */
    public function encryptWebhookData(array $webhookData)
    {
        // Generate random IV (16 bytes for AES-256-CBC)
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        
        // Encrypt the data
        $encryptedData = openssl_encrypt(
            json_encode($webhookData),
            'aes-256-cbc',
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($encryptedData === false) {
            throw new Exception('Encryption failed');
        }
        
        // Return the IV and encrypted data as a base64 encoded string
        return base64_encode($iv . $encryptedData);
    }

    /**
     * Create HMAC signature for webhook data
     * 
     * This method generates a HMAC (Hash-based Message Authentication Code) 
     * using the SHA-256 algorithm for the provided webhook data.
     * 
     * @param string $guid The webhook GUID
     * @param string $webhookType The webhook type
     * @param array $webhookData The webhook data
     * @return string The HMAC signature (hex string)
     */
    public function createHmac($guid, $webhookType, array $webhookData)
    {
        $data = array(
            'guid' => $guid,
            'webhookType' => $webhookType,
            'webhookData' => $webhookData
        );
        $dataString = json_encode($data);
        return hash_hmac('sha256', $dataString, $this->hmacKey);
    }

    /**
     * Try to decrypt and verify webhook payload with IV prefix
     * 
     * This method decrypts the payload (which has IV prepended) and verifies
     * the HMAC signature against the reconstructed JSON.
     * 
     * @param string $guid The webhook GUID
     * @param string $webhookType The webhook type
     * @param string $base64PayloadWithIv Base64-encoded payload with IV prefix
     * @param string $signature The HMAC signature to verify
     * @param string &$decryptedJson Output parameter for decrypted JSON
     * @return bool True if decryption and verification succeeded, false otherwise
     */
    public function tryDecryptAndVerifyWithIvPrefix($guid, $webhookType, $base64PayloadWithIv, $signature, &$decryptedJson)
    {
        $decryptedJson = '';

        try {
            // Decode base64 payload
            $data = base64_decode($base64PayloadWithIv, true);
            if ($data === false) {
                return false;
            }

            // AES block size for CBC is 128 bits = 16 bytes
            $ivLength = 16;
            
            if (strlen($data) <= $ivLength) {
                return false;
            }

            // Extract IV from the beginning
            $iv = substr($data, 0, $ivLength);
            
            // Extract encrypted data (everything after IV)
            $encryptedData = substr($data, $ivLength);

            // Decrypt using AES-256-CBC
            $decryptedBytes = openssl_decrypt(
                $encryptedData,
                'aes-256-cbc',
                $this->encryptionKey,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($decryptedBytes === false) {
                return false;
            }

            $decryptedJson = $decryptedBytes;

            // Reconstruct JSON exactly as in .NET version for HMAC verification
            $jsonData = json_encode(array(
                'guid' => $guid,
                'webhookType' => $webhookType,
                'webhookData' => json_decode($decryptedJson)
            ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            // Verify HMAC signature
            if (!$this->verifySignature($jsonData, $signature)) {
                return false;
            }

            return true;

        } catch (Exception $e) {
            return false;
        }
    }
}
