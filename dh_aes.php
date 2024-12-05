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
// A large prime number (DH_PRIME) used as part of the Diffie-Hellman algorithm.
// This prime ensures secure exchange of keys between parties.
const DH_PRIME = '26959946667150639794667015087019630673637144422540572481103610249215' .
                 '86240415972168525968778613979297721632880679741677375922626020202991' .
                 '00899122135964234148830096949773292668040609468928139167643337792914' .
                 '32893441050911660774194075867720991474836581319810300767321046996567' .
                 '45894096775906117876994783423200847665569424640676370666546365917169' .
                 '86636126815380807940256022072559125059334804366032422325864875631266' .
                 '04228254701566090700716245984701338977994718494815488227615651981412' .
                 '00034194003322961484801923976024994946501752483598389004593236842278';
// Generator value for Diffie-Hellman algorithm
const DH_GENERATOR = 5; // A common generator value used in many DH implementations

/**
 * Class representing a party in the Diffie-Hellman key exchange
 * This class generates private and public keys, computes the shared secret, and derives a shared secret key
 * The shared secret key can be used for encryption/decryption
 * Note: This is a simplified version for demonstration purposes
 */

class Party 
{
    private $privateKey; // Private key for the party (secret)
    private $publicKey; // Public key generated from private key
    private $sharedSecret; // Shared secret computed with another party (result of Diffie-Hellman exchange)

    // Constructor to generate the party's private key (a random number)
    // The private key is a random integer between 1 and the square root of the prime number
    public function __construct()
    {
        // Generate a random private key within the range of 1 to the square root of the prime (DH_PRIME).
        $this->privateKey = random_int(1, (int)bcsqrt(DH_PRIME, 0));
    }

    /**
     * Generate the public key based on the private key and return it
     * The public key is calculated using the formula: 
     * publicKey = (generator^privateKey) % prime
     * It’s safe to share this public key with others.
     * The public key is used by another party to compute the shared secret.
     * The public key is generated only once per party.
     * 
     */
    public function generatePublicKey()
    {
        // Calculate the public key using modular exponentiation (DH_GENERATOR^privateKey % DH_PRIME)
        $this->publicKey = bcpowmod(DH_GENERATOR, $this->privateKey, DH_PRIME);
        return $this->publicKey; // Return the public key for sharing
    }

    /**
      * Compute the shared secret using the public key received from another party
     * This is the core of Diffie-Hellman: both parties use each other's public keys 
     * and their own private key to compute the same shared secret.
     * The shared secret is calculated using modular exponentiation:
     * sharedSecret = (otherPublicKey^privateKey) % prime
     * The shared secret is stored in the object for later use.
     * 
     */
    public function computeSharedSecret($otherPublicKey)
    {
        // Compute the shared secret using the other party's public key and own private key
          // Calculate the shared secret using the formula:
        // sharedSecret = (otherPublicKey^privateKey) % DH_PRIME
        $this->sharedSecret = bcpowmod($otherPublicKey, $this->privateKey, DH_PRIME);
    }

    /**
    * Return the shared secret as a cryptographic key
     * The shared secret is hashed using SHA-256 to derive a secure key for encryption/decryption
     * This key can be used with AES (or other symmetric encryption algorithms) for secure communication.
     * 
     */
    public function getSharedSecretKey()
    {
        // Apply SHA-256 hash to the shared secret to derive a secure encryption key
        // Note: In practice, a key derivation function (KDF) should be used for key derivation.
        // This is a simplified example for demonstration purposes.
        return hash('sha256', $this->sharedSecret, true); // Return the shared secret key
    }

    /**
     * Simulate the exchange of public keys between two parties and compute their shared secrets
     * This simulates a secure communication setup between two parties in Diffie-Hellman
     * The shared secret key can then be used for encryption/decryption.
     * This method is static to demonstrate the key exchange process between two parties.
     */
    public static function exchangeKeys($partyA, $partyB)
    {
        // Each party generates their public key
        // The public keys are exchanged between the parties
        // Each party computes the shared secret using the other party's public key
        $partyAPublic = $partyA->generatePublicKey(); // Generate public key for Party A
        $partyBPublic = $partyB->generatePublicKey(); // Generate public key for Party B

        // Simulate the exchange of public keys: each party computes the shared secret using the other party's public key
        $partyA->computeSharedSecret($partyBPublic); // Party A computes shared secret using Party B's public key
        $partyB->computeSharedSecret($partyAPublic);   // Party B computes shared secret using Party A's public key
    }
}

/**
  * AES class for encryption and decryption
 * AES (Advanced Encryption Standard) is used for encrypting/decrypting messages and files.
 * This class provides methods for encrypting messages, decrypting messages, and encrypting/decrypting files.
 * The encryption mode used is AES-256-CBC, which is a widely used and secure encryption mode.
 * 
 */
class AES
{
    /**
     * Encrypt a plaintext message using AES-256-CBC
     * AES-256-CBC is a secure encryption method, using a 256-bit key and CBC mode for data privacy.
     * An Initialization Vector (IV) is used to add randomness and make encryption more secure.
     */
    public static function encryptMessage($key, $message)
    {
        $iv = random_bytes(16); // Generate a random 16-byte IV (Initialization Vector)
        $ciphertext = openssl_encrypt($message, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv); // Encrypt the message
        return base64_encode($iv . $ciphertext); // Return the encrypted message along with the IV (Base64 encoded)
    }

    /**
      * Decrypt an encrypted message
     * This method reverses the encryption process, using the shared secret key and IV to decrypt the message.
     * The IV is extracted from the encrypted data, and the message is decrypted using AES-256-CBC.
     * The decrypted message is returned as plaintext.
     */
    public static function decryptMessage($key, $encryptedMessage)
    {
        $data = base64_decode($encryptedMessage);// Decode the encrypted message from Base64 format
        $iv = substr($data, 0, 16); // Extract the IV from the beginning of the data
        $ciphertext = substr($data, 16); // Extract the ciphertext (the actual encrypted data)
        // Decrypt the message using the AES-256-CBC method and return the original message
        return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
      * Encrypt a file in chunks using AES-256-CBC
     * This function handles large files, reading and encrypting them in chunks to avoid memory issues.
     * The file is encrypted using AES-256-CBC, and the IV is prepended to the output file.
     * The encrypted file is saved to the specified output path.
     */
    public static function encryptFile($key, $filePath, $outputPath)
    {
        $iv = random_bytes(16);// Generate a random 16-byte IV
        $inputHandle = fopen($filePath, 'rb');// Open the output file for reading
        $outputHandle = fopen($outputPath, 'wb');// Open the input file for writing
        fwrite($outputHandle, $iv); // Write the IV to the beginning of the output file

        // Read and encrypt the file in chunks of 8192 bytes
        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192); // Read 8192 bytes from the input file
            $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv); // Encrypt the data
            fwrite($outputHandle, $ciphertext); // Write the encrypted chunk to the output file
        }

        fclose($inputHandle); // Close the input file
        fclose($outputHandle); // Close the output file
    }

    /**
      * Decrypt a file in chunks using AES-256-CBC
     * This function reverses the encryption process for files.
     * The IV is read from the beginning of the file, and the file is decrypted in chunks.
     * The decrypted file is saved to the specified output path.
     * 
     */
    public static function decryptFile($key, $filePath, $outputPath)
    {
        $inputHandle = fopen($filePath, 'rb'); // Open the input file for reading
        $iv = fread($inputHandle, 16); // Read the IV from the beginning of the file
        $outputHandle = fopen($outputPath, 'wb'); // Open the output file for writing

        // Read and decrypt the file in chunks of 8192 bytes
        while (!feof($inputHandle)) {
            $data = fread($inputHandle, 8192); // Read 8192 bytes from the input file
            $plaintext = openssl_decrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv); // Decrypt the data
            fwrite($outputHandle, $plaintext); // Write the decrypted chunk to the output file
        }

        fclose($inputHandle); // Close the input file
        fclose($outputHandle); // Close the output file
    }
}

// Example usage of the Diffie-Hellman key exchange between two parties
$partyA = new Party(); // Create Party A
$partyB = new Party(); // Create Party B
Party::exchangeKeys($partyA, $partyB); // Exchange public keys between Party A and Party B

$sharedKeyA = $partyA->getSharedSecretKey(); // Get the shared key from Party A
$sharedKeyB = $partyB->getSharedSecretKey(); // Get the shared key from Party B

// Check if the shared keys match between the two parties
if ($sharedKeyA === $sharedKeyB) {
    echo "Shared keys match!\n"; // If they match, encryption/decryption is secure
} else {
    echo "Error: Shared keys do not match.\n"; // This should never happen in a correctly functioning Diffie-Hellman exchange
}



// Handle form submission for encryption/decryption based on user input
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? ''; // Get the selected action from the form
    $inputMessage = $_POST['inputMessage'] ?? ''; // Get the input message from the form
    $inputFile = $_FILES['inputFile']['tmp_name'] ?? ''; // Get the input file from the form
    $outputFile = $_POST['outputFile'] ?? ''; // Get the output file name from the form

    try {
        $party = new Party(); // Create a new party for the user
        $party->generatePublicKey(); // Normally exchanged with another party
        $sharedKey = $party->getSharedSecretKey(); // Generate the shared key from the private/public key exchange

        switch ($action) {
            case 'encryptMessage': // Encrypt a message
                if (empty($inputMessage)) {
                    throw new Exception("Message is required for encryption.");  // Error message if no message is provided
                }
                $encryptedMessage = AES::encryptMessage($sharedKey, $inputMessage); // Encrypt the message
                echo "<span class='success'>Encrypted Message: $encryptedMessage</span>"; // Display the encrypted message
                break; // End the case

            case 'decryptMessage': // Decrypt a message
                if (empty($inputMessage)) {
                    throw new Exception("Message is required for decryption."); // Error message if no message is provided
                }
                $decryptedMessage = AES::decryptMessage($sharedKey, $inputMessage); // Decrypt the message
                echo "<span class='success'>Decrypted Message: $decryptedMessage</span>"; // Display the decrypted message
                break;

            case 'encryptFile': // Encrypt a file
                if (empty($inputFile) || empty($outputFile)) {
                    throw new Exception("Input file and output file name are required for file encryption."); // Error message if no file is provided
                }
                AES::encryptFile($sharedKey, $inputFile, $outputFile); // Encrypt the file
                echo "<span class='success'>File successfully encrypted to: $outputFile</span>"; // Display success message
                break;

            case 'decryptFile': // Decrypt a file
                if (empty($inputFile) || empty($outputFile)) {
                    throw new Exception("Input file and output file name are required for file decryption."); // Error message if no file is provided
                }
                AES::decryptFile($sharedKey, $inputFile, $outputFile); // Decrypt the file
                echo "<span class='success'>File successfully decrypted to: $outputFile</span>"; // Display success message
                break;

            default: // Invalid action selected
                throw new Exception("Invalid action selected."); // Error message for invalid action
        }
    } catch (Exception $e) {
        echo "<span class='error'>Error: " . $e->getMessage() . "</span>"; // Display any errors that occur
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
        /* CSS (Cascading Style Sheets) for styling the webpage's layout and appearance */
       body {
    font-family: Arial, sans-serif; /* Use Arial font for better readability */
    background-color: #f4f4f9; /* Light gray background color */
    color: #333;    /* Dark grey color for text for better readability  */
    margin: 0; /* Remove default margin */
    padding: 0; /* Remove default padding */
    display: flex; /* Use flexbox for centering content */
    justify-content: center; /* Center content horizontally */
    align-items: center; /* Center content vertically */
    height: 100vh; /* Full height of the viewport */
}

.container {
    background: #fff; /* White background for the container */
    padding: 20px 30px; /* Padding around the container */
    border-radius: 8px; /* Rounded corners for the container */
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Drop shadow for a subtle effect */
    width: 100%; /* Full width for the container */
    max-width: 450px; /* Slightly larger width for more comfortable spacing */
}

h1 {
    font-size: 1.8rem; /* Larger font size for the heading */
    color: #007BFF; /* Blue color for the heading */
    text-align: center; /* Center the heading */
    margin-bottom: 20px; /* Space below the heading */
}

form {
    display: flex;  /* Use flexbox for form layout */
    flex-direction: column; /* Arrange form elements in a column */
    gap: 15px; /* Space between form elements */
}

label {
    font-weight: bold; /* Bold text for labels */
    margin-bottom: 5px; /* Space below the label */
}

input, select, button {
    font-size: 1rem; /* Font size for form elements */
    padding: 10px; /* Padding around form elements */
    border: 1px solid #ddd; /* Light gray border for form elements */
    border-radius: 5px; /* Rounded corners for form elements */
    width: 100%; /* Full width for form elements */
    box-sizing: border-box; /* Ensures padding doesn't affect width */
}

button {
    background-color: #007BFF; /* Blue background color for buttons */
    color: white; /* White text color for buttons */
    border: none; /* No border for buttons */
    cursor: pointer; /* Show pointer cursor on hover */
    transition: background-color 0.3s; /* Smooth transition for background color */
}

button:hover {
    background-color: #0056b3; /* Darker blue color on hover */
}

p {
    font-size: 0.9rem;  /* Smaller font size for additional information */
    color: #555; /* Dark gray color for additional information */
    text-align: center; /* Center the text */
    margin-top: 20px; /* Space above the paragraph */
}

p strong {
    color: #007BFF; /* Blue color for strong text */
}

.message {
    margin-top: 20px; /* Space above the message */
    font-size: 1rem; /* Font size for messages */
    text-align: center; /* Center the message */
}

.error {
    color: #FF4C4C; /* Red color for error messages */
}

.success {
    color: #28A745; /* Green color for success messages */
}

    </style>
</head>



<body>
    <div class="container">
        <h1>Advanced File and Message Cryptography</h1>
        <!-- Form for selecting the action and providing input for encryption/decryption -->
        <form action="" method="POST" enctype="multipart/form-data">
            <!-- Select the action to perform -->
            <label for="action">Select Action:</label>
            <!-- Dropdown menu for selecting the action -->
            <select name="action" id="action" required>
                <!-- Options for different actions -->
                <option value="encryptMessage">Encrypt Message</option>
                <!-- Encrypt a message -->
                <option value="decryptMessage">Decrypt Message</option>
                <!-- Decrypt a message -->
                <option value="encryptFile">Encrypt File</option>
                <!-- Encrypt a file -->
                <option value="decryptFile">Decrypt File</option>
                <!-- Decrypt a file -->
            </select>
            <!-- Input field for entering the message -->
            <label for="inputMessage">Message (for message encryption/decryption):</label>
            <!-- Textarea for entering the message -->
            <textarea name="inputMessage" id="inputMessage" placeholder="Enter message here..."></textarea>
            <!-- Input field for selecting a file -->
            <label for="inputFile">File (for file encryption/decryption):</label>
            <!-- File input for selecting a file -->
            <input type="file" name="inputFile" id="inputFile">
            <!-- Input field for entering the output file name -->
            <label for="outputFile">Output File Name (for file encryption/decryption):</label>
            <!-- Text input for entering the output file name -->
            <input type="text" name="outputFile" id="outputFile" placeholder="e.g., output.txt">
            <!-- Submit button for the form -->
            <button type="submit">Submit</button>
            <!-- Display any messages or errors -->
        </form>
        <!-- Additional information for users -->
        <p><strong>Note:</strong> Use larger primes (e.g., 2048-bit) for real-world Diffie-Hellman applications to ensure strong security.</p>
    </div>
</body>
</html>