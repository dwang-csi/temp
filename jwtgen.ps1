function Generate-JWT (
	[Parameter(Mandatory = $True)]
	[ValidateSet("HS256", "HS384", "HS512")]
	$Algorithm = $null,
	$type = $null,
	[Parameter(Mandatory = $True)]
	[hashtable]$Payload = $null,
	[Parameter(Mandatory = $True)]
	$SecretKey = $null
)
{
	
	$exp = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.
	
	[hashtable]$header = @{ alg = $Algorithm; typ = $type }
	#[hashtable]$payload = @{ iss = $Issuer; exp = $exp }
	
	$headerjson = $header | ConvertTo-Json -Compress
	$payloadjson = $Payload | ConvertTo-Json -Compress
	
	$headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
	$payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
	
	$ToBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64
	
	$SigningAlgorithm = switch ($Algorithm)
	{
		"HS256" { New-Object System.Security.Cryptography.HMACSHA256 }
		"HS384" { New-Object System.Security.Cryptography.HMACSHA384 }
		"HS512" { New-Object System.Security.Cryptography.HMACSHA512 }
	}
	
	$SigningAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
	$Signature = [Convert]::ToBase64String($SigningAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')
	
	$token = "$headerjsonbase64.$payloadjsonbase64.$Signature"
	
	Write-Host $payloadjson
	Write-Host "Secret: $SecretKey"
	Write-Host "Token: $token"
	
	return $token
}

Clear-Host
$api_secret = 'fd655bcf018a4608801e1a0b49f837b3'

$api_bytes = [System.Text.Encoding]::Unicode.GetBytes($api_secret)
$apikey = 'fd655bcf018a4608801e1a0b49f837b3'
$choices = '&Yes', '&No'
$username = Read-Host -Prompt "User Name"
$authQuestion = $Host.UI.PromptForChoice("Authorization", "Is user authorized", $choices, 0)

$auth = "false"
if ($authQuestion -eq 0)
{
	$auth = "true"
}

$timestamp = Get-Date -Format "MM/dd/yyyy HH:mmtt"
[hashtable]$payload = @{ username = $username; authorized = $auth; timestamp = $timestamp }

$token = Generate-JWT -Algorithm 'HS256' -type 'JWT' -Payload $payload -SecretKey $apikey
$url = "http://localhost:8080?token=$token"

Set-Clipboard -Value $url
Write-Host "URL and Token was copied to the Clipboard"
Write-Host
Write-Host $url
Start-Process $url 