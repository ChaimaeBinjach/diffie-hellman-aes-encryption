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

// Party class for Diffie-Hellman Key Exchange
class Party
{
    private $privateKey;
    private $publicKey;
    private $sharedSecret;

    public function __construct()
    {
        $this->privateKey = random_int(1, (int)bcsqrt(DH_PRIME, 0));

    }

    public function generatePublicKey()
    {
        $this->publicKey = bcpowmod(DH_GENERATOR, $this->privateKey, DH_PRIME);
        return $this->publicKey;
    }

    public function computeSharedSecret($otherPublicKey)
    {
        $this->sharedSecret = bcpowmod($otherPublicKey, $this->privateKey, DH_PRIME);
    }

    public function getSharedSecretKey()
    {
        return hash('sha256', $this->sharedSecret, true);
    }
}

// AES class for encryption and decryption
class AES
{
    public static function encrypt($key, $filePath, $outputPath)
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

    public static function decrypt($key, $filePath, $outputPath)
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

// Handle form submission or self-request (client-server)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'];
    $inputFile = $_FILES['inputFile']['tmp_name'];
    $outputFile = $_POST['outputFile'];

    try {
        $party = new Party();
        $party->generatePublicKey(); // Normally exchanged with another party
        $sharedKey = $party->getSharedSecretKey();

        if ($action === 'encrypt') {
            AES::encrypt($sharedKey, $inputFile, $outputFile);
            echo "<span class='success'>File successfully encrypted to: $outputFile</span>";
        } elseif ($action === 'decrypt') {
            AES::decrypt($sharedKey, $inputFile, $outputFile);
            echo "<span class='success'>File successfully decrypted to: $outputFile</span>";
        } else {
            throw new Exception("Invalid action selected.");
        }
    } catch (Exception $e) {
        echo "<span class='error'>Error: " . $e->getMessage() . "</span>";
    }
}

// Handle client-server cURL interaction
if (isset($_GET['action']) && $_GET['action'] === 'client') {
    // This part simulates client action (it can call the same file as a "server")
    $url = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];  // Full URL for the current script
    $response = sendRequest($url, $_POST['action'], $_FILES['inputFile']['tmp_name'], $_POST['outputFile']);
    echo $response;
}

function sendRequest($url, $action, $file, $outputFile)
{
    $cfile = new CURLFile($file, 'application/octet-stream', basename($file));
    $data = [
        'action' => $action,
        'inputFile' => $cfile,
        'outputFile' => $outputFile
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    
    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
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
        <h1>Secure File Encryption/Decryption</h1>
        <form action="" method="POST" enctype="multipart/form-data">
            <label for="action">Select Action:</label>
            <select name="action" id="action" required>
                <option value="encrypt">Encrypt</option>
                <option value="decrypt">Decrypt</option>
            </select>

            <label for="inputFile">Select File:</label>
            <input type="file" name="inputFile" id="inputFile" required>

            <label for="outputFile">Output File Name:</label>
            <input type="text" name="outputFile" id="outputFile" placeholder="e.g., output.txt" required>

            <button type="submit">Submit</button>
        </form>
        <p><strong>Note:</strong> Use larger primes (e.g., 2048-bit) for real-world Diffie-Hellman applications to ensure strong security.</p>
        <div class="message">
            <?php
            // Display success or error messages
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $action = $_POST['action'];
                $inputFile = $_FILES['inputFile']['tmp_name'];
                $outputFile = $_POST['outputFile'];

                try {
                    $party = new Party();
                    $party->generatePublicKey(); // Normally exchanged with another party
                    $sharedKey = $party->getSharedSecretKey();

                    if ($action === 'encrypt') {
                        AES::encrypt($sharedKey, $inputFile, $outputFile);
                        echo "<span class='success'>File successfully encrypted to: $outputFile</span>";
                    } elseif ($action === 'decrypt') {
                        AES::decrypt($sharedKey, $inputFile, $outputFile);
                        echo "<span class='success'>File successfully decrypted to: $outputFile</span>";
                    } else {
                        throw new Exception("Invalid action selected.");
                    }
                } catch (Exception $e) {
                    echo "<span class='error'>Error: " . $e->getMessage() . "</span>";
                }
            }
            ?>
        </div>
    </div>
</body>
</html>
