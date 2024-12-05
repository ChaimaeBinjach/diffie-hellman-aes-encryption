<?php
// Title: Secure File Encryption/Decryption using Diffie-Hellman Key Exchange and AES

// This program is designed to securely encrypt and decrypt both messages and files using advanced cryptographic techniques. 
// The program works in two parts: the Diffie-Hellman Key Exchange and the AES Encryption.
// First, the Diffie-Hellman method is used to establish a shared secret key between two parties without actually transmitting the key itself over the network. 
//This key is then used with AES (Advanced Encryption Standard), a widely used encryption method, to secure messages or files.

// Here’s how it works step-by-step:

// 1. Generating the Secret Key:  
//    Two parties (e.g., Party A and Party B) use the Diffie-Hellman Key Exchange method. 
//They each generate a private key (a random number) and calculate a public key (based on their private key, a predefined prime number, and a generator). 
//They exchange these public keys and use them to compute a shared secret a number known only to the two parties. This shared secret is turned into a fixed-length secret key using the SHA-256 hashing algorithm.

// 2. Encrypting Messages or Files:  
//    Once the shared key is generated, the user can use it to encrypt messages or files using AES in CBC (Cipher Block Chaining) mode. 
// AES is a strong encryption method that ensures the data cannot be understood without the secret key. The encryption process also uses a unique initialization vector (IV) for each operation, making the encryption even more secure.

// 3. Decrypting Messages or Files:  
//    When a user wants to decrypt a message or file, they use the same shared secret key generated earlier. 
//The IV (which is part of the encrypted data) is used to reverse the encryption and retrieve the original message or file.


// How the user will use it:  
// - When the user opens the web interface, they can choose one of the following actions:  
//   1. Encrypt a Message: Enter a message, and the program will encrypt it using the shared secret key. The encrypted output is displayed for you to save or share securely.  
//   2. Decrypt a Message: Enter an encrypted message, and the program will decrypt it back into plain text, provided the correct shared secret key is used.  
//   3. Encrypt a File: Upload a file and specify an output filename. The program encrypts the file using the shared secret key and saves the encrypted version.  
//   4. Decrypt a File: Upload an encrypted file, provide an output filename, and the program decrypts it back to its original content.  

// The user doesn’t need to understand the complex math or algorithms behind it—all they do is interact with a simple form. The program automatically manages key generation, encryption, and decryption behind the scenes.

// Methods Used
// 1. Diffie-Hellman Key Exchange: A secure method to create a shared secret key over an insecure channel. This ensures the key isn’t exposed during transmission.  
// 2. AES (Advanced Encryption Standard): A strong and efficient encryption technique used to protect data. The program uses AES-256-CBC, which is a 256-bit key version of AES with CBC mode for enhanced security.  

// In short, this program ensures that sensitive information stays secure, whether it’s a text message or a file, by leveraging state-of-the-art cryptographic methods. It’s easy for users and extremely difficult for attackers to compromise.

?>

<?php
// Constants for Diffie-Hellman algorithm
const DH_PRIME = '26959946667150639794667015087019630673637144422540572481103610249215' .
                 '86240415972168525968778613979297721632880679741677375922626020202991' .
                 '00899122135964234148830096949773292668040609468928139167643337792914' .
                 '32893441050911660774194075867720991474836581319810300767321046996567' .
                 '45894096775906117876994783423200847665569424640676370666546365917169' .
                 '86636126815380807940256022072559125059334804366032422325864875631266' .
                 '04228254701566090700716245984701338977994718494815488227615651981412' .
                 '00034194003322961484801923976024994946501752483598389004593236842278';
const DH_GENERATOR = 5;

/**
 * Class representing a party in the Diffie-Hellman key exchange
 */
class Party
{
    private $privateKey;
    private $publicKey;
    private $sharedSecret;

    public function __construct()
    {
        // Generate a private key (random integer)
        $this->privateKey = random_int(1, (int)bcsqrt(DH_PRIME, 0));
    }

    /**
     * Generate the public key based on private key and return it
     */
    public function generatePublicKey()
    {
        $this->publicKey = bcpowmod(DH_GENERATOR, $this->privateKey, DH_PRIME);
        return $this->publicKey;
    }

    /**
     * Compute the shared secret using the received public key of another party
     */
    public function computeSharedSecret($otherPublicKey)
    {
        $this->sharedSecret = bcpowmod($otherPublicKey, $this->privateKey, DH_PRIME);
    }

    /**
     * Return the shared secret derived key (SHA-256 hash)
     */
    public function getSharedSecretKey()
    {
        return hash('sha256', $this->sharedSecret, true);
    }

    /**
     * Simulate networked public key exchange (placeholder)
     */
    public static function exchangeKeys($partyA, $partyB)
    {
        $partyAPublic = $partyA->generatePublicKey();
        $partyBPublic = $partyB->generatePublicKey();

        // Simulating sending/receiving public keys
        $partyA->computeSharedSecret($partyBPublic);
        $partyB->computeSharedSecret($partyAPublic);
    }
}

/**
 * AES class for encryption and decryption
 */
class AES
{
    /**
     * Encrypt a plaintext message using AES-256-CBC
     */
    public static function encryptMessage($key, $message)
    {
        $iv = random_bytes(16); // Generate a random Initialization Vector (IV)
        $ciphertext = openssl_encrypt($message, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ciphertext); // Return IV + ciphertext (Base64 encoded)
    }

    /**
     * Decrypt an encrypted message
     */
    public static function decryptMessage($key, $encryptedMessage)
    {
        $data = base64_decode($encryptedMessage);
        $iv = substr($data, 0, 16); // Extract IV
        $ciphertext = substr($data, 16); // Extract ciphertext
        return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Encrypt large binary files in chunks
     */
    public static function encryptFile($key, $filePath, $outputPath)
    {
        $iv = random_bytes(16);
        $inputHandle = fopen($filePath, 'rb');
        $outputHandle = fopen($outputPath, 'wb');
        fwrite($outputHandle, $iv);

        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192);
            $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            fwrite($outputHandle, $ciphertext);
        }

        fclose($inputHandle);
        fclose($outputHandle);
    }

    /**
     * Decrypt large binary files in chunks
     */
    public static function decryptFile($key, $filePath, $outputPath)
    {
        $inputHandle = fopen($filePath, 'rb');
        $iv = fread($inputHandle, 16);
        $outputHandle = fopen($outputPath, 'wb');

        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192);
            $plaintext = openssl_decrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            fwrite($outputHandle, $plaintext);
        }

        fclose($inputHandle);
        fclose($outputHandle);
    }
}

// Usage example: Two-party key exchange
$partyA = new Party();
$partyB = new Party();
Party::exchangeKeys($partyA, $partyB);

$sharedKeyA = $partyA->getSharedSecretKey();
$sharedKeyB = $partyB->getSharedSecretKey();

// Verify keys match
if ($sharedKeyA === $sharedKeyB) {
    echo "Shared keys match!\n";
} else {
    echo "Error: Shared keys do not match.\n";
}


// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $inputMessage = $_POST['inputMessage'] ?? '';
    $inputFile = $_FILES['inputFile']['tmp_name'] ?? '';
    $outputFile = $_POST['outputFile'] ?? '';

    try {
        $party = new Party();
        $party->generatePublicKey(); // Normally exchanged with another party
        $sharedKey = $party->getSharedSecretKey();

        switch ($action) {
            case 'encryptMessage':
                if (empty($inputMessage)) {
                    throw new Exception("Message is required for encryption.");
                }
                $encryptedMessage = AES::encryptMessage($sharedKey, $inputMessage);
                echo "<span class='success'>Encrypted Message: $encryptedMessage</span>";
                break;

            case 'decryptMessage':
                if (empty($inputMessage)) {
                    throw new Exception("Message is required for decryption.");
                }
                $decryptedMessage = AES::decryptMessage($sharedKey, $inputMessage);
                echo "<span class='success'>Decrypted Message: $decryptedMessage</span>";
                break;

            case 'encryptFile':
                if (empty($inputFile) || empty($outputFile)) {
                    throw new Exception("Input file and output file name are required for file encryption.");
                }
                AES::encryptFile($sharedKey, $inputFile, $outputFile);
                echo "<span class='success'>File successfully encrypted to: $outputFile</span>";
                break;

            case 'decryptFile':
                if (empty($inputFile) || empty($outputFile)) {
                    throw new Exception("Input file and output file name are required for file decryption.");
                }
                AES::decryptFile($sharedKey, $inputFile, $outputFile);
                echo "<span class='success'>File successfully decrypted to: $outputFile</span>";
                break;

            default:
                throw new Exception("Invalid action selected.");
        }
    } catch (Exception $e) {
        echo "<span class='error'>Error: " . $e->getMessage() . "</span>";
    }
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Encryption/Decryption</title>
    <style>
       body {
    font-family: Arial, sans-serif;
    background-color: #f4f4f9;
    color: #333;
    margin: 0;
    padding: 0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}

.container {
    background: #fff;
    padding: 20px 30px;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    width: 100%;
    max-width: 450px; /* Slightly larger width for more comfortable spacing */
}

h1 {
    font-size: 1.8rem;
    color: #007BFF;
    text-align: center;
    margin-bottom: 20px;
}

form {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

label {
    font-weight: bold;
    margin-bottom: 5px;
}

input, select, button {
    font-size: 1rem;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 5px;
    width: 100%;
    box-sizing: border-box; /* Ensures padding doesn't affect width */
}

button {
    background-color: #007BFF;
    color: white;
    border: none;
    cursor: pointer;
    transition: background-color 0.3s;
}

button:hover {
    background-color: #0056b3;
}

p {
    font-size: 0.9rem;
    color: #555;
    text-align: center;
    margin-top: 20px;
}

p strong {
    color: #007BFF;
}

.message {
    margin-top: 20px;
    font-size: 1rem;
    text-align: center;
}

.error {
    color: #FF4C4C;
}

.success {
    color: #28A745;
}

    </style>
</head>



<body>
    <div class="container">
        <h1>Advanced File and Message Cryptography</h1>
        <form action="" method="POST" enctype="multipart/form-data">
            <label for="action">Select Action:</label>
            <select name="action" id="action" required>
                <option value="encryptMessage">Encrypt Message</option>
                <option value="decryptMessage">Decrypt Message</option>
                <option value="encryptFile">Encrypt File</option>
                <option value="decryptFile">Decrypt File</option>
            </select>

            <label for="inputMessage">Message (for message encryption/decryption):</label>
            <textarea name="inputMessage" id="inputMessage" placeholder="Enter message here..."></textarea>

            <label for="inputFile">File (for file encryption/decryption):</label>
            <input type="file" name="inputFile" id="inputFile">

            <label for="outputFile">Output File Name (for file encryption/decryption):</label>
            <input type="text" name="outputFile" id="outputFile" placeholder="e.g., output.txt">

            <button type="submit">Submit</button>
        </form>
        <p><strong>Note:</strong> Use larger primes (e.g., 2048-bit) for real-world Diffie-Hellman applications to ensure strong security.</p>
    </div>
</body>
</html>