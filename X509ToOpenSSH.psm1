Function ConvertHex-ToBase64 {
<#
.DESCRIPTION
Helper function for converting binary written has hexadecimal to base64

.PARAMETER HexString
Expected format is a string of hexadecimal characters with no spaces or separation between the octets.
#>	
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, Position = 1)]
		[string]$HexString
	)
	$ByteArray = [System.Byte[]]::new($HexString.Length / 2)
	For ($i = 0; $i -lt $ByteArray.Length; $i++) {
		$ByteArray[$i] = [System.Convert]::ToByte($HexString.Substring($i * 2, 2), 16)
	}
	Write-Output ([System.Convert]::ToBase64String($ByteArray))
}
	
Function ConvertX509Cert2-ToOpenSshPubKey {
<#
.SYNOPSIS
Convert a X509Certificate2 object to OpenSSH public key format.

.DESCRIPTION
Accepts a X509Certificate2 object and utilizes the public key to output it in OpenSSH format for use in SSH public key authentication.

.PARAMETER Certificate
A single X509Certificate2 object from .NET.

.EXAMPLE
$Cert = Get-ChildItem Cert:\CurrentUser\My\A4321234CAF8EFACF74A8567D61F04ACA4321234
ConvertX509Cert2-ToOpenSshPubKey -Certificate $Cert
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCurn...ccwdiJ1 CAPI:A4321234CAF8EFACF74A8567D61F04ACA4321234 CN=SMITH.BOB.JONES, OU=PKI, OU=Office, O=Company, C=US
#>
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, Position = 1)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)		
	#RSA Specifics
	If ($Certificate.PublicKey.Oid.FriendlyName -eq 'RSA') {
		$OpenSshPubKey = 'ssh-rsa '
		$Algorithm = '00-00-00-07-73-73-68-2d-72-73-61' #ssh-rsa
		$RSAPubKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
		[xml]$XmlKey = $RSAPubKey.ToXmlString($false)
			
		$ExponentBytes = [System.Convert]::FromBase64String($XmlKey.RSAKeyValue.Exponent)
		$Modulus = [System.BitConverter]::ToString([System.Convert]::FromBase64String($XmlKey.RsaKeyValue.Modulus))
	}
	#DSA Specifics
	ElseIf ($Certificate.PublicKey.Oid.FriendlyName -eq 'DSA') {
		$OpenSshPubKey = 'ssh-dss '
		$Algorithm = '00-00-00-07-73-73-68-2d-64-73-73' #ssh-dss
		$DSAPubKey = [System.Security.Cryptography.X509Certificates.DSACertificateExtensions]::GetDSAPublicKey($Certificate)
		[xml]$XmlKey = $DSAPubKey.ToXmlString($false)
			
		$ExponentBytes = [System.Convert]::FromBase64String($XmlKey.DSAKeyValue.Exponent)
		$Modulus = [System.BitConverter]::ToString([System.Convert]::FromBase64String($XmlKey.DsaKeyValue.Modulus))
	}
	#ECDsa and Ed25519 do not have the proper types or ToXmlString() in the X509Certificate library
	Else {
		Throw 'Unsupported key type.'
	}
		
	#Key
	$ExponentLengthHex = $ExponentBytes.Length.ToString("x8")
	$ExponentHex = [System.BitConverter]::ToString($ExponentBytes)
	$Exponent = $ExponentLengthHex + $ExponentHex
		
	$KeySize = $Certificate.PublicKey.Key.KeySize
	$KeyBytesHex = (($KeySize / 8) + 1).ToString("x8")
	$ModBegin = "$KeyBytesHex-00"
		
	$HexKey = ($Algorithm, $Exponent, $ModBegin, $Modulus -join '') -replace '-', ''
	$Base64Key = ConvertHex-ToBase64 -HexString $HexKey
	$OpenSshPubKey += $Base64Key
		
	#Comment
	$OpenSshPubKey += " CAPI:$($Certificate.Thumbprint.ToLower()) $($Certificate.Subject)"
		
	Write-Output $OpenSshPubKey
}
