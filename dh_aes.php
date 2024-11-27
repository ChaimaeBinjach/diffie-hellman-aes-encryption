<?php
// Secure implementation of Diffie-Hellman Key Exchange and AES Encryption/Decryption in PHP

// Constants for Diffie-Hellman algorithm
const DH_PRIME = 23; // Prime number for the modulus (use a larger prime in production)
const DH_GENERATOR = 5; // Generator (primitive root modulo DH_PRIME)

/**
 * Represents a party in the Diffie-Hellman key exchange.
 */
class Party
{
    private $privateKey; // Private key (kept secret)
    private $publicKey; // Public key (shared with the other party)
    private $sharedSecret; // Shared secret derived from the exchange

    public function __construct()
    {
        // Generate a random private key securely
        $this->privateKey = random_int(1, DH_PRIME - 1);
    }

    /**
     * Calculate and return the public key to share with the other party.
     */
    public function generatePublicKey()
    {
        // Compute public key as (g^privateKey) % p
        $this->publicKey = bcpowmod(DH_GENERATOR, $this->privateKey, DH_PRIME);
        return $this->publicKey;
    }

    /**
     * Compute the shared secret using the other party's public key.
     * @param string $otherPublicKey The public key received from the other party.
     */
    public function computeSharedSecret($otherPublicKey)
    {
        // Shared secret = (otherPublicKey^privateKey) % p
        $this->sharedSecret = bcpowmod($otherPublicKey, $this->privateKey, DH_PRIME);
    }

    /**
     * Derive a 256-bit AES key from the shared secret.
     * @return string AES key derived from the shared secret.
     */
    public function getSharedSecretKey()
    {
        // Convert the shared secret into a fixed-length 256-bit key using SHA-256
        return hash('sha256', $this->sharedSecret, true);
    }
}

/**
 * AES Encryption/Decryption Utility
 */
class AES
{
    /**
     * Encrypt a file using AES-256-CBC.
     */
    public static function encrypt($key, $filePath, $outputPath)
    {
        $iv = random_bytes(16); // Securely generate a random initialization vector (IV)
        $inputHandle = fopen($filePath, 'rb');
        $outputHandle = fopen($outputPath, 'wb');
        fwrite($outputHandle, $iv); // Store IV at the start of the encrypted file

        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192); // Read file in chunks
            $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($ciphertext === false) {
                fclose($inputHandle);
                fclose($outputHandle);
                throw new Exception("Encryption failed.");
            }
            fwrite($outputHandle, $ciphertext);
        }

        fclose($inputHandle);
        fclose($outputHandle);
    }

    /**
     * Decrypt a file encrypted with AES-256-CBC.
     */
    public static function decrypt($key, $filePath, $outputPath)
    {
        $inputHandle = fopen($filePath, 'rb');
        $iv = fread($inputHandle, 16); // Read the IV from the encrypted file
        $outputHandle = fopen($outputPath, 'wb');

        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192); // Read file in chunks
            $plaintext = openssl_decrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            if ($plaintext === false) {
                fclose($inputHandle);
                fclose($outputHandle);
                throw new Exception("Decryption failed.");
            }
            fwrite($outputHandle, $plaintext);
        }

        fclose($inputHandle);
        fclose($outputHandle);
    }
}

/**
 * Secure Server for handling Diffie-Hellman key exchange and file operations.
 */
class SecureServer
{
    private $party;

    public function __construct()
    {
        $this->party = new Party();
    }

    /**
     * Run the server on the specified port.
     */
    public function run($port = 8000)
    {
        $serverSocket = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
        if (!$serverSocket) {
            die("Error starting server: $errstr ($errno)\n");
        }

        echo "Server running on port $port. Waiting for connections...\n";

        while ($client = stream_socket_accept($serverSocket)) {
            echo "Client connected.\n";

            try {
                // Step 1: Perform key exchange
                $publicKey = $this->party->generatePublicKey();
                fwrite($client, "$publicKey\n");
                $clientKey = trim(fgets($client));
                if (!is_numeric($clientKey)) {
                    throw new Exception("Invalid public key received from client.");
                }
                $this->party->computeSharedSecret($clientKey);
                $sharedKey = $this->party->getSharedSecretKey();
                fwrite($client, "Key exchange complete. Ready for commands.\n");

                // Step 2: Handle encryption/decryption commands
                while (($command = trim(fgets($client))) !== 'exit') {
                    if (preg_match('/^(encrypt|decrypt) (\S+) (\S+)$/', $command, $matches)) {
                        $action = $matches[1];
                        $inputPath = $matches[2];
                        $outputPath = $matches[3];

                        if (!file_exists($inputPath)) {
                            fwrite($client, "Error: File $inputPath not found.\n");
                            continue;
                        }

                        if ($action === 'encrypt') {
                            AES::encrypt($sharedKey, $inputPath, $outputPath);
                            fwrite($client, "File encrypted to $outputPath.\n");
                        } elseif ($action === 'decrypt') {
                            AES::decrypt($sharedKey, $inputPath, $outputPath);
                            fwrite($client, "File decrypted to $outputPath.\n");
                        }
                    } else {
                        fwrite($client, "Invalid command. Use: encrypt/decrypt [input file] [output file].\n");
                    }
                }
            } catch (Exception $e) {
                fwrite($client, "Error: " . $e->getMessage() . "\n");
            }

            fclose($client);
        }

        fclose($serverSocket);
    }
}

/**
 * Secure Client for connecting to the server and executing commands.
 */
class SecureClient
{
    private $party;

    public function __construct()
    {
        $this->party = new Party();
    }

    /**
     * Connect to the server and interact.
     */
    public function connect($host = '127.0.0.1', $port = 8000)
    {
        $clientSocket = stream_socket_client("tcp://$host:$port", $errno, $errstr);
        if (!$clientSocket) {
            die("Error connecting to server: $errstr ($errno)\n");
        }

        try {
            // Step 1: Perform key exchange
            $serverKey = trim(fgets($clientSocket));
            if (!is_numeric($serverKey)) {
                throw new Exception("Invalid public key received from server.");
            }
            $publicKey = $this->party->generatePublicKey();
            fwrite($clientSocket, "$publicKey\n");
            $this->party->computeSharedSecret($serverKey);
            $sharedKey = $this->party->getSharedSecretKey();
            echo "Connected to server. Enter commands:\n";

            // Step 2: Send commands
            $handle = fopen("php://stdin", "r");
            while ($command = trim(fgets($handle))) {
                if ($command === 'exit') {
                    fwrite($clientSocket, "exit\n");
                    break;
                }
                fwrite($clientSocket, "$command\n");
                echo fgets($clientSocket);
            }
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage() . "\n";
        }

        fclose($clientSocket);
    }
}

// Main program
if ($argc > 1 && $argv[1] === 'server') {
    $server = new SecureServer();
    $server->run();
} elseif ($argc > 1 && $argv[1] === 'client') {
    $client = new SecureClient();
    $client->connect();
} else {
    echo "Usage: php script.php [server|client]\n";
}
?> 