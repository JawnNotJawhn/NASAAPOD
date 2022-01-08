<#
.SYNOPSIS
Changes wallpaper registry key for current user.

.DESCRIPTION
Updates HKCU:\Control Panel\Desktop\Wallpaper registry value with an image of filetype: jpeg|jpg|png|tiff

.PARAMETER $Path
String parameter passes through regex formula that allows the following filetype extensions: jpeg|jpg|png|tiff

.EXAMPLE
Set-Wallpaper -Path 'C:\Users\Desktop\Image.png'

#>
function Set-Wallpaper
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidatePattern('^.*\.(jpeg|jpg|png|tiff)$')]
        [string] $Path
    )
    process
    {
        try 
        {
            if (Test-Path -Path $Path)
            {
                $image = Get-ChildItem -Path $Path -ErrorAction Stop

                Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -Value $image.FullName -ErrorAction Stop
            }
            else
            {
                "Path error: $Path is not valid"
            }
        }
        catch 
        {
            "Error with image path: $_"
        }
    }
}

<# 
.SYNOPSIS
Encrypts and decrypts plain text through AES Encryption.

.DESCRIPTION
This function is used to encrypt and decrypt plaintext password utilizing a key.
Encrypting will save a hash of the password onto the $PSScriptRoot filepath.

.EXAMPLE
Invoke-AESEncyption -Encrypt -Key 'textkey' -Credential 'username' -Path 'C:\path'

.EXAMPLE
Invoke-AESEncyption -Decrypt -Key 'textkey' -Path 'C:\Path\DecryptMe.txt'

#>
function Invoke-AESEncryption
{
    [CmdletBinding()]
    param (
        #Encrypts the password using a key.
        [Parameter(Mandatory, ParameterSetName = 'Encrypt')]
        [switch] $Encrypt,
        
        #Decrypts hash value password using a key. 
        [Parameter(Mandatory, ParameterSetName = 'Decrypt')]
        [switch] $Decrypt,
        
        #Key value as a string.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Key,
        
        #Requests credentials. <Username>.txt will be output filename. 
        [Parameter(Mandatory, ParameterSetName = 'Encrypt')]
        [pscredential] $Credential,
        
        #Output filepath of hashed credential. Input txt file of has value.
        [Parameter(Mandatory)]
        [string] $Path
    )
    process
    {
        if (Test-Path -Path $Path)
        {
            #Create hash and AES objects
            $hashObject = New-Object System.Security.Cryptography.SHA256Managed
            $aesObject = New-Object System.Security.Cryptography.AesManaged
            $aesObject.BlockSize = 128
            $aesObject.KeySize = 256
            $aesObject.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesObject.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $keyByteArray = $hashObject.ComputeHash([System.Text.Encoding]::UTF8.GetBytes( $Key ))
            $aesObject.Key = $keyByteArray

            switch ($true) 
            {
                {$Encrypt.IsPresent} {

                    $username = $Credential.UserName
                    $passwordByte = [System.Text.Encoding]::UTF8.GetBytes($Credential.Password)
                    $encryptor = $aesObject.CreateEncryptor()
                    $encryptBlock = $encryptor.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)
                    $encryptBlock = $aesObject.IV + $encryptBlock
                    $encryptedString = [System.Convert]::ToBase64String($encryptBlock)
                    $encryptedString | Out-File -FilePath "$Path\$username.txt"
                }
                {$Decrypt.IsPresent}{

                    $decryptCredential = Get-Content -Path $Path
                    $passwordByte = [System.Convert]::FromBase64String($decryptCredential)
                    $aesObject.IV = $passwordByte[0..15]
                    $decryptor = $aesObject.CreateDecryptor()
                    $decryptBlock = $decryptor.TransformFinalBlock($passwordByte, 16, $passwordByte.Length - 16)
                    $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptBlock)
                    # Decrypted SecureString
                    $userName = [io.path]::GetFileNameWithoutExtension($Path)
                    $pWord = ConvertTo-SecureString -String $decryptedString -AsPlainText -Force
                    $Credential = New-Object -TypeName PSCredential -ArgumentList $userName, $pWord
                    $Credential
                }
            }

            $aesObject.Dispose()
            $hashObject.Dispose()
        }
        else
        {
            "Path $_ is not valid."
        }
    }
}

<#
.SYNOPSIS
NASA APOD api request.

.DESCRIPTION
Builds a URI to make requests to NASA api.

.PARAMETER Credential
Used to enter the API key as password. Enter the username in plaintext when calling. NASA api provides a free key you can use: DEMO_KEY

.PARAMETER Query
User can provide own uri query string. Format: 'Key1+Value1&Key2=Value2'

.PARAMETER RestMethod
Date parameter requires format:  yyyy-MM-dd 

.EXAMPLE
Invoke-NasaApiRequest -RestMethod GET -UriPath /planetary/apod -Credential username -Query ?key1=value1&key2=value2

#>
function Invoke-NasaApiRequest 
{
    [CmdletBinding()]
    param (
        #REST Parameter
        [Parameter(Mandatory, ParameterSetName = 'RestMethod')]
        [ValidateSet('Default', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace')]
        [string] $RestMethod,
        
        #API key
        [Parameter(Mandatory)]
        [PScredential] $Credential,
        
        #URI Path
        [Parameter(Mandatory)]
        [string] $UriPath,
        
        #Query api string
        [Parameter()]
        [string] $Query
    )
    process
    {
        #Sets apikey to separate variable Credential
        $apiKey = $Credential.GetNetworkCredential().Password

        #Build URI
        $nasaUri = 'https://api.nasa.gov'
        $uri = [System.UriBuilder]::new( $nasaUri )
        $uri.Path = $UriPath
        $uri.Query = $Query
        
        switch ($RestMethod) 
        {
            'GET' {
                Invoke-RestMethod -Method Get -URI $uri.Uri.AbsoluteUri
            }
        }
    }
}

<#
.SYNOPSIS
NASA APOD api request.

.DESCRIPTION
Constructs apod api request that is passed through Invoke-NasaApiRequest cmdlet.

.PARAMETER Credential
Used to enter the API key as password. Enter the username in plaintext when calling. NASA api provides a free key you can use: DEMO_KEY

.PARAMETER Query
User can provide own uri query string. Format: 'Key1+Value1&Key2=Value2'

.PARAMETER Date
Date parameter requires format:  yyyy-MM-dd 

.PARAMETER DateRange
DateRange "start_date/end_date" parameter requires format:  yyyy-MM-dd/yyyy-MM-dd

.PARAMETER Count
If this is specified then "count" randomly chosen images will be returned.

.EXAMPLE
Get-NasaApod -Credential 'username' -Path 'c:\filepath\folder' -Date 2022-01-08

NASA Apod uri request gets apod image for input date. Image will output to target path. 
Credential will request for the API key as password. Publically provided api key from NASA: "DEMO_KEY"

.EXAMPLE
Get-NasaApod -Credential 'username' -Path 'c:\filepath\folder' -Query 'Key1+Value1&Key2=Value2' 

Non-mandatory parameters -Path and -Query will allow you to customize and build your own APOD URI.
Credential will request for the API key as password. Publically provided api key from NASA: "DEMO_KEY"

.EXAMPLE
Get-NasaApod -Credential 'username' -Path 'c:\filepath\here' -DateRange 2021-11-01/2021-11-23

NASA Apod uri request for each date in the range. -Path will save all images for each date.
Credential will request for the API key as password. Publically provided api key from NASA: "DEMO_KEY"

.EXAMPLE
Get-NasaApod -Credential 'username' -Count 2

NASA Apod uri request calls two dates at random.
Credential will request for the API key as password. Publically provided api key from NASA: "DEMO_KEY"
#>
function Get-NasaApod
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PScredential] $Credential,
        
        #Path for file output.
        [Parameter()]
        [string] $Path, 
        
        [Parameter(Mandatory, ParameterSetName = 'Query')]
        [string] $Query,

        [Parameter(Mandatory, ParameterSetName = 'Date')]
        [string] $Date,

        [Parameter(Mandatory, ParameterSetName = 'DateRange')]
        [ValidatePattern('^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])\/\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$')]
        [string] $DateRange, 

        [Parameter(Mandatory, ParameterSetName = 'Count')]
        [int32] $Count  
    )
    process 
    {
        #Create query building object that will provide string
        $queryCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        # '?API_KEY=apikey" from Credential parameter will be the first string in every apod 'GET' call.
        $apiKey = $Credential.GetNetworkCredential().Password
        $queryCollection.Add('api_key', $apiKey)
        $uriPath = '/planetary/apod'
        $restMethod = 'GET'

        switch ($PSCmdlet.ParameterSetName)
        {
            {$Count} {
                $queryCollection.Add('count', $Count)
            }
            {$Date} { 
                $dateQuery = $Date | Get-Date -Format 'yyyy-MM-dd'

                $queryCollection.Add('date', $dateQuery)
            }
            {$DateRange} { 
                $dateRangeQuery = $DateRange
                #start_date
                $startDate = [string] $dateRangeQuery | Select-String -Pattern '^.+(?=\/)' | ForEach-Object { $_.matches } | Select-Object value
                $startDate = $startDate.Value
                $queryCollection.Add('start_date', $startDate)
                #end_date 
                $endDate = $dateRangeQuery | Select-String -Pattern '(?<=\/).*$' | ForEach-Object { $_.matches } | Select-Object value
                $endDate = $endDate.Value
                $queryCollection.Add('end_date', $endDate)
            }
        }
        
        #Final step for query builder
        if ($PSBoundParameters.ContainsKey('Query'))  
        { 
            #Checks if user prepended '?' to their query and removes. Else, finalize query
            if ($Query | Select-String -Pattern '^\?')
            {
                $Query = $Query.Substring(1)
                $queryString = $queryCollection.ToString() + '&' + $Query
            }
            else
            {
                $queryString = $queryCollection.ToString() + '&' + $Query
            }
        }
        else
        {
            $queryString = $queryCollection.ToString()
        }

        #Object 
        $invokeNasaApi = Invoke-NasaApiRequest -RestMethod $restMethod -UriPath $uriPath -Credential $Credential -Query $queryString

        #Save api image to target Path
        if ($PSBoundParameters.ContainsKey('Path'))
        {
            if (Test-Path -Path $Path)
            {
                foreach ($_ in $invokeNasaApi) 
                {
                    $imageFile = $_.url | Split-Path -Leaf
                    $outFile = Join-Path -Path $Path -Childpath $imageFile
                    
                    Invoke-WebRequest -Uri $_.url -OutFile $outFile
                }
            }
            else 
            {
                "Path error: $Path is not valid"
            }
        }
        
        $invokeNasaApi
    }
}