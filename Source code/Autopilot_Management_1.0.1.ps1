#GUI - Autopilot Management
#1.0 - 24.05.2023 - First version release
#1.0.1 - 27.06.2023 - Removed unnecessary scope permission causing difficulties manually granting adminconsent

#To-do:
#Add logging window which can be opened with a checkbox
#Permission check read for query, permission check admin for update group tag
#Make all buttons into Powershell runspaces for efficiency
#Save BitLocker info
#Replace global variables with script or local
#Right click header of datatable to filter columns, e.g. add MAC-address
#Double click Autopilot object to list more Intune-information

############################
###   BUILD GUI   ##########
############################ 
#region Build GUI
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
$version = "1.0.1"
$title = "Autopilot Management"
$titleCut = "AutopilotManagement"
$inputXaml = @"
<Window x:Class="GUIAutopilotGroupTag1.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:GUIAutopilotGroupTag1"
        mc:Ignorable="d"
        Title="$($title)" Height="550" Width="1500">
    <Grid>
        <Label x:Name="lblAuthor" Content="Author: Espen Jaegtvik - $($version)" HorizontalAlignment="Left" Margin="683,13,0,0" VerticalAlignment="Top" Opacity="0.5" FontSize="10" RenderTransformOrigin="0.917,0.259"/>
        <Label x:Name="lblSerialnumber" Content="Serialnumber" HorizontalAlignment="Left" Margin="603,35,0,0" VerticalAlignment="Top" FontSize="16" Visibility="Hidden"/>
        <Label x:Name="lblGroupTag" Content="Group Tag" HorizontalAlignment="Left" Margin="10,136,0,0" VerticalAlignment="Top" FontSize="16" Width="104"/>
        <Label x:Name="lblProgress" Content="Progress:" HorizontalAlignment="Left" Margin="101,15,0,0" VerticalAlignment="Top" FontSize="16" Width="85"/>
        <Label x:Name="lblTenantName" Content="Tenant:" HorizontalAlignment="Left" Margin="10,54,0,0" VerticalAlignment="Top" FontSize="12" Width="300"/>
        <Label x:Name="lblCacheSize" Content="Cache size: " HorizontalAlignment="Left" Margin="498,147,0,0" VerticalAlignment="Top" Opacity="0.8" Visibility="Hidden"/>
        <Label x:Name="lblUploading" Content="Upload in progress..." HorizontalAlignment="Left" Margin="858,82,0,0" VerticalAlignment="Top" Width="111" Height="26" FontSize="10" Visibility="Hidden"/>
        <TextBlock x:Name="txtblkImportCsv" HorizontalAlignment="Left" Margin="700,99,0,0" TextWrapping="Wrap" Text="Csv imported and used for query: " VerticalAlignment="Top" Width="315" Height="52" Opacity="0.8" Visibility="Hidden"/>
        <ProgressBar x:Name="progressBar" HorizontalAlignment="Left" Height="20" Margin="176,21,0,0" VerticalAlignment="Top" Width="219"/>
        <TextBox x:Name="txtboxQuery" HorizontalAlignment="Left" Margin="163,94,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="232" Height="28" FontSize="12"/>
        <TextBox x:Name="txtboxGroupTag" HorizontalAlignment="Left" Margin="163,139,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="232" Height="28" FontSize="12"/>
        <Button x:Name="btnLoginAzure" Content="Login Azure" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" Height="36" Width="76" FontSize="13"/>
        <Button x:Name="btnBackupSelection" Content="Backup" HorizontalAlignment="Left" Margin="410,50,0,0" VerticalAlignment="Top" Height="28" Width="76" FontSize="16" IsEnabled="False" RenderTransformOrigin="0.461,0.037"/>
        <Button x:Name="btnQuery" Content="Query" HorizontalAlignment="Left" Margin="410,94,0,0" VerticalAlignment="Top" Height="28" Width="76" FontSize="16" IsEnabled="False"/>
        <Button x:Name="btnUpdateGroupTag" Content="Update" HorizontalAlignment="Left" Margin="410,138,0,0" VerticalAlignment="Top" Height="28" Width="76" FontSize="16" IsEnabled="False" RenderTransformOrigin="0.85,0.548"/>
        <Button x:Name="btnDelete" Content="Delete" HorizontalAlignment="Left" Margin="410,138,0,0" VerticalAlignment="Top" Height="28" Width="76" IsEnabled="False" FontSize="16" Visibility="Hidden"/>
        <Button x:Name="btnUploadHash" Content="Upload Hash" HorizontalAlignment="Left" Margin="858,53,0,0" VerticalAlignment="Top" Height="28" Width="103" FontSize="16" IsEnabled="False" RenderTransformOrigin="0.85,0.548" Visibility="Visible"/>
        <CheckBox x:Name="chkboxLimitUpdate" Content="Disable update limit" HorizontalAlignment="Left" Margin="506,53,0,0" VerticalAlignment="Top" FontSize="14" Height="23" IsEnabled="False" Width="149"/>
        <CheckBox x:Name="chkboxAutopilotprofile" Content="Show Autopilot profile" HorizontalAlignment="Left" Margin="506,76,0,0" VerticalAlignment="Top" IsEnabled="False" IsChecked="True" FontSize="14"/>
        <CheckBox x:Name="chkboxCache" Content="Query with cache" HorizontalAlignment="Left" Margin="506,99,0,0" VerticalAlignment="Top" FontSize="14" IsEnabled="False"/>
        <CheckBox x:Name="chkboxUpdateDelete" Content="Update / Delete" HorizontalAlignment="Left" Margin="506,124,0,0" VerticalAlignment="Top" FontSize="14" IsEnabled="False"/>
        <CheckBox x:Name="chkboxLimitDelete" Content="Disable delete limit" HorizontalAlignment="Left" Margin="700,53,0,0" VerticalAlignment="Top" FontSize="14" IsEnabled="False"/>
        <CheckBox x:Name="chkboxImportCsv" Content="Load / Unload csv" HorizontalAlignment="Left" Margin="700,76,0,0" VerticalAlignment="Top" FontSize="14" IsEnabled="False"/>
        <ComboBox x:Name="comboQuery" HorizontalAlignment="Left" Margin="10,94,0,0" VerticalAlignment="Top" Width="137" Height="28" IsReadOnly="True" FontSize="16">
            <ComboBoxItem Content="Serial number" IsSelected="True"/>
            <ComboBoxItem Content="Device name"/>
            <ComboBoxItem Content="Any"/>
        </ComboBox>
        <DataGrid x:Name="datagridResults" d:ItemsSource="{d:SampleData ItemCount=5}" Margin="10,180,10,58" IsReadOnly="True" AutoGenerateColumns="True">
            <DataGrid.Columns>
                <!-- Autopilot -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Serial number" Binding="{Binding serialNumber}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Group Tag" Binding="{Binding groupTag}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Manufacturer" Binding="{Binding manufacturer}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Model" Binding="{Binding model}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Enrollmentstate" Binding="{Binding enrollmentState}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Last Contact" Binding="{Binding lastContactedDateTime}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Profile assignmentstate" Binding="{Binding deploymentProfileAssignmentStatus}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="id" Binding="{Binding id}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="deploymentProfileAssignmentDetailedStatus" Binding="{Binding deploymentProfileAssignmentDetailedStatus}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="deploymentProfileAssignedDateTime" Binding="{Binding deploymentProfileAssignedDateTime}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="purchaseOrderIdentifier" Binding="{Binding purchaseOrderIdentifier}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="productKey" Binding="{Binding productKey}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="addressableUserName" Binding="{Binding addressableUserName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="userPrincipalName" Binding="{Binding userPrincipalName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="resourceName" Binding="{Binding resourceName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="skuNumber" Binding="{Binding skuNumber}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="systemFamily" Binding="{Binding systemFamily}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="azureActiveDirectoryDeviceId" Binding="{Binding azureActiveDirectoryDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="azureAdDeviceId" Binding="{Binding azureAdDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="managedDeviceId" Binding="{Binding managedDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="displayName" Binding="{Binding displayName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="deviceAccountUpn" Binding="{Binding deviceAccountUpn}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="deviceAccountPassword" Binding="{Binding deviceAccountPassword}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="deviceFriendlyName" Binding="{Binding deviceFriendlyName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="remediationState" Binding="{Binding remediationState}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="remediationStateLastModifiedDateTime" Binding="{Binding remediationStateLastModifiedDateTime}" Visibility="Hidden"/>
                <!-- Intune -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Device name" Binding="{Binding intuneDeviceName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="User display name" Binding="{Binding intuneUserDisplayName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="User principal name" Binding="{Binding intuneUserPrincipalName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune id" Binding="{Binding intuneId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Autopilot profile" Binding="{Binding intuneEnrollmentProfileName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneManagedDeviceOwnerType" Binding="{Binding intuneManagedDeviceOwnerType}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneEnrolledDateTime" Binding="{Binding intuneEnrolledDateTime}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneOsVersion" Binding="{Binding intuneOsVersion}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneDeviceEnrollmentType" Binding="{Binding intuneDeviceEnrollmentType}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneEmailAddress" Binding="{Binding intuneEmailAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneWifiMacAddress" Binding="{Binding intuneWifiMacAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneEthernetMacAddress" Binding="{Binding intuneEthernetMacAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="intuneFreeStorageSpaceInBytes" Binding="{Binding intuneFreeStorageSpaceInBytes}" Visibility="Hidden"/>
                <!-- Autopilot profile -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Autopilot profile" Binding="{Binding autopilotDeploymentProfile}"/>
            </DataGrid.Columns>
            <DataGrid.Resources>
                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#0064FF"/>
                <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}" Color="#CCDAFF"/>
            </DataGrid.Resources>
        </DataGrid>
    </Grid>
</Window>
"@

#Cleanup XAML
$xaml = $inputXaml -Replace 'mc:Ignorable="d"', '' -Replace "x:N", 'N' -Replace '^<Win.*', '<Window' `
                   -Replace 'd:ItemsSource="{d:SampleData ItemCount=5}"', '' -Replace "x:Class=`"GUIAutopilotGroupTag1.MainWindow`"", ""
[XML]$xaml = $xaml

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$global:syncHash = [Hashtable]::Synchronized(@{})

try {
    $syncHash.Window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Warning $_.Exception
    throw
}

#Create variables
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try {
        Write-Host "Variable: var_$($_.Name)"
        $syncHash.Add("var_$($_.Name)",$syncHash.Window.FindName($_.Name))
    } catch {
        throw
    }
}
$global:syncHash.token = $null
$global:syncHash.tokenAcquired = $null
$global:syncHash.headers = $null
$global:syncHash.cache = $null
$global:syncHash.csvDevices = $null
$global:syncHash.hashUploading = [System.Collections.ArrayList]::New()
$global:syncHash.apImportStatus = [System.Collections.ArrayList]::New()

#endregion Build GUI

############################
###   FUNCTIONS   ##########
############################ 
#region Functions

#region Token
#v0.1 - 18.03.2022
#v0.2 - 21.03.2022 - bugfix PKCE
#v1.0 - 12.06.2022 - bugfix login window
#v1.1 - 17.01.2023 - added support for refresh token
#v1.2 - 24.01.2023 - bugfix refresh token

Function Get-HTMLFriendly {
    #Function will replace "/", ":", " " with HTLM-accepted code
    [Cmdletbinding()]
    Param (
    [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()][array]$Replace
    )
    $result = $Replace.Replace("/","%2F").Replace(":","%3A").Replace(" ","%20")
    return $result
}

Function Get-PKCE {
    #Function will create code challenge to get a code, which again can get us a token using code with code verifier
    #Valid input to function is length of code verifier
    [Cmdletbinding()]
    Param (
    [Parameter(Mandatory=$false, 
               HelpMessage="Enter a number between 43 and 128")]
               [ValidateNotNullOrEmpty()][int]$Length = 128
    )

    if ($Length -lt 43 -or $Length -gt 128) {
        Write-Warning "Please enter a number between 43 and 128"
        break
    }
    $codeChallenge = $null
    $codeVerifier = $null
    [int]$count = 0

    #Create random string
    do {
        [int]$numberOrLetter = 1..3 | Get-Random
        Switch ($numberOrLetter) {
            1 {[byte]$random = 48..57 | Get-Random} #Number
            2 {[byte]$random = 65..90 | Get-Random} #Uppercase letter
            3 {[byte]$random = 97..122 | Get-Random} #Lowercase letter
            default {Write-Warning "Unknown error, exit"; break}
        }
        [string]$codeVerifier += [char]$random
        $count++
    } while ($count -lt $length)

    #Create code challenge with S256-hash and base64url
    $sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("sha256")
    $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
    $base64 = ([System.Convert]::ToBase64String($hash)).SubString(0,43)
    $codeChallenge = ($base64.Split("=")[0]).Replace("+","-").Replace("/","_").Replace("=","")
    
    #Return PKCE
    $result = New-Object psobject -Property @{
        CodeVerifier = $codeVerifier
        CodeChallenge = $codeChallenge
    }

    return $result
}

Function Get-CodeFlowAuthToken {
    #This function is dependent of functions Get-PKCE and Get-HTMLFriendly
    [CmdletBinding(DefaultParameterSetName = "New")]
    param(
        [Parameter(Mandatory = $true,
                   ParameterSetName = "New",
                   HelpMessage='The site the Enterprise App will authenticate to')]
                   [ValidateNotNullOrEmpty()][string]$RedirectUri,
        [Parameter(Mandatory = $true,
                   ParameterSetName = "New",
                   HelpMessage='Input as array like @("value1", "value2") etc.')]
                   [ValidateNotNullOrEmpty()][array]$Scope,
        [Parameter(Mandatory = $true,
                   HelpMessage='Id to Enterprise App')]
                   [ValidateNotNullOrEmpty()][string]$ClientId,
        [Parameter(Mandatory = $false,
                   HelpMessage='Name of your tenant, Ex. "customer.com"')]
                   [ValidateNotNullOrEmpty()][string]$TenantName = "common",
        [Parameter(Mandatory = $false,
                   ParameterSetName = "New",
                   HelpMessage='This is part of the header in last query to get token. Ex. input "https://admin.hp.com"')]
                   [ValidateNotNullOrEmpty()][string]$Origin,
        [Parameter(Mandatory = $true,
                   ParameterSetName = "Refresh",
                   HelpMessage='Used to refresh the token. Pass your current token which has the "access_token", "id_token" and "refresh_token".')]
                   [ValidateNotNullOrEmpty()][object]$CurrentToken
    )
    #Variables to create uri
    if ($tenantName -ne "common") { $tenantName = ((Invoke-RestMethod -uri "https://login.microsoftonline.com/$tenantName/.well-known/openid-configuration").token_endpoint).Replace("https://login.microsoftonline.com/","").Replace("/oauth2/token","") }
    if ($PSCmdlet.ParameterSetName -eq "New") {
        $convertedScope, $convertedRedirectUri = $null
        $convertedScope = (Get-HTMLFriendly -Replace $scope) -join "%20"
        $convertedRedirectUri = Get-HTMLFriendly -Replace $redirectUri
        $PKCE = Get-PKCE
        $codeChallenge = $PKCE.codeChallenge
        $codeVerifier = $PKCE.codeVerifier
        $state = $codeChallenge.Substring(0, 27)
        $prompt = "prompt=select_account"
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Web
    if ($PSCmdlet.ParameterSetName -eq "New") {
        $uri = "https://login.microsoftonline.com/$($tenantName)/oauth2/v2.0/authorize?client_id=$($clientId)&scope=$($convertedScope)&redirect_uri=$($convertedRedirectUri)&response_mode=query&response_type=code&code_challenge=$($codeChallenge)&code_challenge_method=S256&$($prompt)" #&$($authority)
    } else {
        #Refresh token
        Write-Host $CurrentToken.refresh_token
        if ($CurrentToken.refresh_token) {
            Write-Host "Refresh..."
            try {
                $uri = "https://login.microsoftonline.com/$($tenantName)/oauth2/v2.0/token"
                $body = @{
                    grant_type = "refresh_token"
                    client_id = $clientId
                    refresh_token = $CurrentToken.refresh_token
                }
                $header = @{"Content-Type" = "application/x-www-form-urlencoded"}
                $token = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Post -ErrorAction Stop
                return $token
            } catch {
                Write-Host "Invalid refresh token."
                return
            }
        } else {
            Write-Host "Can't continue because we're missing `"refresh_token.`""
            return
        }
    }

    #Prompt Azure logon and save code after successful authentication
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
    $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600;Url = $uri}
    $DocComp = {
        $uri = $web.Url.AbsoluteUri
        if ($uri -match "error=[^&]*|code=[^&]*") { $form.Close() }
    }
    $DocNav = {
        if ($web.DocumentText -like "*document.location.replace*$($redirectUri)?code=*") { $form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $web.Add_Navigated($DocNav)
    $form.Controls.Add($web)
    $form.Add_Shown( { $form.Activate() } )
    $form.ShowDialog() | Out-Null
    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    #First attempt to get code
    $code = @{}
    foreach ($key in $queryOutput.Keys) {
        $code["$key"] = $queryOutput[$key]
    }
    #Second attempt to get code
    if ($code.code -eq $null) {
        try {
            $ErrorActionPreference = "Stop"
            $tempCode = ([string]($web.DocumentText.Split("`n") | `
            Select-String -Pattern "document.location.replace")).Replace("document.location.replace(`"urn:ietf:wg:oauth:2.0:oob?","")
            $tempCode = ($tempCode.Split("\") | Where-Object {$_ -match "code="}).Replace(" ","").Replace("code=","")
            $code.code = $tempCode
            $ErrorActionPreference = "Continue"
        } catch {
            $ErrorActionPreference = "Continue"
            Write-Host "Failed to get code. Can not retrieve token. Reason: User might have cancelled web form."
            return
        }
    }
    #Get token using code and code verifier
    $uri = "https://login.microsoftonline.com/$($tenantName)/oauth2/v2.0/token"
    $scope = $scope -join " "
    $body = @{
        grant_type = "authorization_code"
        client_id = $clientId
        scope = $scope -join ""
        code = $code.code
        code_verifier = $codeVerifier
        redirect_uri = $redirectUri
    }

    if ($Origin) {
        $header = @{
            Origin = $Origin
        }
        $token = Invoke-RestMethod -Uri $uri -Headers $header -Body $body -Method Post
    } else {
        $token = Invoke-RestMethod -Uri $uri -Body $body -Method Post
    }
    return $token
}
#endregion token

Function Get-TenantName {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true,
                   HelpMessage='Token for authentication. Provide full token information which include property "access_token".')]
                   [ValidateNotNullOrEmpty()]$Token
    )
    $headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $($Token.access_token)"
    }
    $uri = "https://graph.microsoft.com/v1.0/organization"
    try {
        $query = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    } catch {
        Write-Host "Failed to get tenant name. Maybe permission issue."
    }
    if ($query.value.verifiedDomains.Count -gt 1) {
        $tenantName = ($query.value.verifiedDomains | Where-Object {$_.Name -notlike "*onmicrosoft.com"} | Select-Object -First 1).Name
    } else {
        $tenantName = $query.value.verifiedDomains.Name
    }
    return $tenantName
}

Function Remove-Runspace {
    [CmdletBinding()]
    Param(
    [Parameter(
        Mandatory=$false,
        HelpMessage="Runspace id to terminate.")]
        [int]$id,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Force remove, even if runspace is open.")]
        [switch]$Force = $false,
    [Parameter(
        Mandatory=$false,
        HelpMessage='Custom attribute to search for in runspace. Name must be "Custom". Input value to search for here. Tips: can be added to runspace object with "Add-Member".')]
        [string]$Custom
    )
    #Remove all available runspaces
    if (-not $id -and -not $Force -and -not $Custom) {
        Get-Runspace | Where-Object {$_.RunspaceAvailability -eq "Available"} | ForEach-Object {$_.Dispose()}
        $removed = $true
        Write-Host "Available runspaces were removed."
    }
    #Remove id
    if ($id) {
        Get-Runspace -id $id | `
            ForEach-Object {
            if ($Force) {
                $_.Dispose()
                Write-Host "Runspace id: `"$id`" was removed."
                $removed = $true
                return
            } else {
                if ($_.RunspaceAvailability -ne "Available") {
                    Write-Host "Can not remove runspace because it's not completed. Use parameter -Force to force removal." -ForegroundColor Yellow
                    $removed = $true
                    return
                } else {
                    $_.Dispose()
                    Write-Host "Runspace id: `"$id`" was removed."
                    $removed = $true
                    return
                }
            }
        }
    }
    #Remove custom (added by Add-Member to runspace)
    if ($Custom) {
        Get-Runspace | Where-Object {$_.Custom -eq $Custom} | `
            ForEach-Object {
            if ($Force) {
                $_.Dispose()
                Write-Host "Runspace with custom: `"$Custom`" was removed."
                $removed = $true
                return
            } else {
                if ($_.RunspaceAvailability -ne "Available") {
                    Write-Host "Can not remove runspace because it's not completed. Use parameter -Force to force removal." -ForegroundColor Yellow
                    $removed = $true
                    return
                } else {
                    $_.Dispose()
                    Write-Host "Runspace with custom: `"$Custom`" was removed."
                    $removed = $true
                    return
                }
            }
        }
    }
    if ($removed -ne $true) {
        Write-Host "No runspaces were removed."
    }
}

Function Confirm-TokenValidity {
    Param(
    [Parameter(
        Mandatory=$true,
        HelpMessage="Get-Date from the moment token was acquired")]
        [DateTime]$TokenAcquired,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Token lifetime (in seconds)")]
        [int]$TokenLifetime
    )
    Write-Host "Checking if token has expired..."
    #Buffer of 5 minutes
    $TokenLifeTime = $TokenLifeTime - 180
    #Calculate
    if (($TokenAcquired).AddSeconds($TokenLifetime) -gt (Get-Date)) {
        Write-Host "Token still valid."
        $tokenValid = $true
    } else {
        Write-Host "Token has expired. Disable UI."
        $tokenValid = $false
    }
    return $tokenValid
}

Function Refresh-Token {
    #Run in a runspace to continuously refresh token when needed. Requires global variables to be able to update token
    do {
        Switch ($syncHash.token.ext_expires_in) {
            {$_ -ge 5000} {$refreshTimer = 1200}
            {$_ -ge 4000 -and $_ -lt 5000} {$refreshTimer = 1000}
            {$_ -ge 3000 -and $_ -lt 4000} {$refreshTimer = 800}
            {$_ -ge 2000 -and $_ -lt 3000} {$refreshTimer = 600}
            {$_ -ge 1000 -and $_ -lt 2000} {$refreshTimer = 400}
            default {$refreshTimer = 200}
        }
        if (($syncHash.tokenAcquired).AddSeconds($syncHash.token.ext_expires_in - $refreshTimer) -gt (Get-Date)) {
            Write-Host "No need to refresh"
        } else {
            Write-Host "Refresh"
            try {
                #Refresh token
                $ErrorActionPreference = "Stop"
                $tempToken = Get-CodeFlowAuthToken -CurrentToken $syncHash.token -ClientId $syncHash.clientId
                $syncHash.tokenAcquired = Get-Date
                $syncHash.token = $tempToken
            } catch {
            } finally {
                $ErrorActionPreference = "Continue"
            }

        }
        Start-Sleep 120
    } while ($syncHash.token -ne $null)
}

Function Disable-UI {
    $syncHash.var_btnUpdateGroupTag.IsEnabled = $false
    $syncHash.var_btnQuery.IsEnabled = $false
    $syncHash.var_btnBackupSelection.IsEnabled = $false
    $syncHash.var_btnDelete.IsEnabled = $false
    $syncHash.var_btnUploadHash.IsEnabled = $false
    $syncHash.var_chkboxLimitUpdate.IsChecked = $false
    $syncHash.var_chkboxLimitUpdate.IsEnabled = $false
    $syncHash.var_chkboxAutopilotprofile.IsEnabled = $false
    $syncHash.var_chkboxUpdateDelete.IsEnabled = $false
    $syncHash.var_chkboxLimitDelete.IsChecked = $false
    $syncHash.var_chkboxLimitDelete.IsEnabled = $false
    $syncHash.var_lblTenantName.Content = "Tenant name:"
    $syncHash.var_lblUploading.Visibility = "Hidden"
    $syncHash.var_chkboxCache.IsEnabled = $false
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 0
    Update-Cache -Object $syncHash.var_lblCacheSize
    Remove-Runspace -Custom "RefreshToken" -Force #Force stop refreshing token
    Write-Host "UI access disabled."
    return
}

Function Update-Progressbar {
    Param(
        [Parameter(
            Mandatory=$true,
            HelpMessage="Variable/object to update.")]
            $Object,       
        [Parameter(
            Mandatory=$true,
            HelpMessage="Percentage complete to show.")]
            [int]$Percent,
        [Parameter(
            Mandatory=$false,
            HelpMessage="Specify if running inside runspace. True or false.")]
            [switch]$Runspace = $false   
    )
    if ($Runspace) {
        $Object.Dispatcher.Invoke([action]{ $Object.value = "$($Percent)" })
    } else {
        $Object.value = "$($Percent)"
    }

}

Function Update-Cache {
    [CmdletBinding()]
    Param(
    [Parameter(
        Mandatory=$true,
        HelpMessage='Object or label to update. Ex. "$chkbox".')]
        $Object,
    [Parameter(
        Mandatory=$false,
        HelpMessage="Force remove, even if runspace is open.")]
        [string]$Text = "Cache size: ",
    [Parameter(
        Mandatory=$false,
        HelpMessage='Number to update cache with.')]
        [switch]$Enabled
    )
    Switch ($Enabled) {
        "True"  { 
                    $Object.Content = "$($Text)"
                    $Object.Visibility = "Visible"
                }
        "False" {
                    $Object.Content = "Cache size: "; 
                    $Object.Visibility = "Hidden"
                    Write-Host "Hiding current cache."
                }
    }
}

Function Import-CsvDevices {
    $filePicker = New-Object Microsoft.Win32.OpenFileDialog -Property @{
        Filter = "Csv files (*.csv)|*.csv|Text documents (*.txt)|*.txt"
    }
    $filePicker.ShowDialog() | Out-Null
    try {
        $csvDevices = Import-Csv $filePicker.FileName
    } catch {
        Write-Host "User cancelled or failed to import csv file `"$($csv)`""
        return
    }
    #Verify header
    $verifyCsvHeader = ($csvDevices | Get-Member | Where-Object {$_.Name -eq "Device Serial Number"}).Name
    if ($verifyCsvHeader -ne "Device Serial Number") {
        [System.Windows.Forms.MessageBox]::Show("Csv is in an unreadable format, please use header `"Device Serial Number`".","Invalid format","OK","Warning") | Out-Null
        return
    }
    try {
        $syncHash.var_txtblkImportCsv.Text = "Csv imported and used for query:`n$($filePicker.FileName)"
    } catch {}
    return $csvDevices #.'Device Serial Number'
}

Function Search-AutopilotDevice {
    #Check token status
    if ((Confirm-TokenValidity -TokenAcquired $syncHash.tokenAcquired -TokenLifetime $syncHash.token.expires_in) -ne $true) {
        Write-Host "Invalid or expired token."
        Disable-UI
        [System.Windows.Forms.MessageBox]::Show("Expired or invalid authentication.`nPlease reauthenticate by using `"Login Azure`".","Invalid/expired token","OK","Information") | Out-Null
        return
    }

    #Reset values
    $syncHash.var_datagridResults.Items.Clear()
    $syncHash.var_btnUpdateGroupTag.IsEnabled = $false
    $syncHash.var_btnDelete.IsEnabled = $false
    $syncHash.var_txtboxQuery.Text = $syncHash.var_txtboxQuery.Text.TrimStart(" ").TrimEnd(" ")
    $syncHash.txtboxQuery = $syncHash.var_txtboxQuery.Text
    Update-Cache -Object $syncHash.var_lblCacheSize
    $serialnumber = $false
    $devicename = $false
    $any = $false
    $userInput = $false
    $serialnumber = $false
    $useCache = $syncHash.var_chkboxCache.IsChecked
    $intune = $true
    $result = $null

    #Identify input
    Switch ($syncHash.var_comboQuery.Text) {
        "Serial number" {$serialnumber = $true; Write-Host "Query for serial number."}
        "Device name" {$devicename = $true; Write-Host "Query for device name."}
        "Any" {$any = $true; Write-Host "Query all object properties with input."}
        default {Write-Host "Invalid query input."; return}
    }
    if ($syncHash.txtboxQuery -ne "") {
        $userInput = $true
        Write-Host "Search specified value."
    }
    Switch ($syncHash.var_chkboxAutopilotprofile.IsChecked) {
        "True" {$autopilotProfile = $true}
        "False" {$autopilotProfile = $false}
    }
    Switch ($syncHash.cache) {
        $null   {$hasCache = $false}
        default {$hasCache = $true}
    }

    if ($useCache -eq $false) {
        Write-Host "Instructed to not use cache. Wipe existing cache."
        $syncHash.cache = $null
        #Query Autopilot devices
        $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
        try {
            $query = Invoke-RestMethod -Headers $syncHash.headers -Uri $uri -Method Get
        } catch {
            Write-Host "Access denied."
            [System.Windows.Forms.MessageBox]::Show("Failed to update device(s).`nMake sure you have one of the following roles:`n- Intune Administrator`n- Global Admin`n`nEnterprise application:`n- `"Microsoft Intune Powershell`" must be admin consented.`n- You must be granted permission to login to the Enterprise app.","Insufficient permissions","OK","Error") | Out-Null
            return
        }
        $nextLink = $query.'@odata.nextLink'
        $result = $query.value
        #If more than 1000 loop
        while ($nextLink -ne $null) {
            $query = Invoke-RestMethod -Headers $syncHash.headers -Uri $nextLink
            $nextLink = $query.'@odata.nextLink'
            $result = $result + $query.value
        }

        #Process result
        if ($userInput) {
            if ($serialnumber) {
                Write-Host "Serial number defined, look for matches."
                [array]$filteredResult = $null
                foreach ($device in $result) {
                    if ($device.serialNumber -like "*$($syncHash.txtboxQuery)*") {
                        $filteredResult += $device
                    }
                }
                $result = $filteredResult
            } elseif ($devicename) {
                Write-Host "Device name defined, will search when temporary datagrid has been built."
            } elseif ($any) {
                Write-Host "Any defined, will search when temporary datagrid has been built."
            } else {
                Write-Host "No input value defined, show all Autopilot devices."
            }
        }
        if ($result) {
            #Enable buttons
            $syncHash.var_btnUpdateGroupTag.IsEnabled = $true
            $syncHash.var_btnDelete.IsEnabled = $true
            $syncHash.var_btnBackupSelection.IsEnabled = $true
            $syncHash.var_chkboxCache.IsEnabled = $true
            Update-Cache -Object $syncHash.var_lblCacheSize -Text "Cache size: $($result.Count) devices" -Enabled
        } else {
            if ($serialnumber) {
                Write-Host "No device found with serial number `"$($syncHash.txtboxQuery)`"."
                [System.Windows.Forms.MessageBox]::Show("Search did not return any devices.`nSearch something else, or do an empty search.","No devices found","OK","Information") | Out-Null
            } else {
                Write-Host "No device found."
            }
            return
        }
        
        #Ask to turn off Autopilot profile for large environment
        if ($autopilotProfile -and $result.Count -gt 200) {
            Write-Host "Found many devices. Ask if user want to continue."
            if ($serialnumber) {
                $largeEnvironment = [System.Windows.Forms.MessageBox]::Show("Found $($result.count) devices in query.`nProcess will take a long time with 200+ devices if `"Show Autopilot profile`" is checked.`n`nContinue with Autopilot profile information?","Many devices","YesNoCancel","Information")
            } else {
                $largeEnvironment = [System.Windows.Forms.MessageBox]::Show("Query needs to process $($result.count)`nTo speed up the process it's recommended to turn off `"Show Autopilot profile`".`n`nContinue with Autopilot profile information?","Many devices","YesNoCancel","Information")
            }
            Switch ($largeEnvironment) {
                "No" {Write-Host "Disable Autopilot profile query."; $autopilotProfile = $false; $syncHash.var_chkboxAutopilotprofile.IsChecked = $false}
                "Yes" {Write-Host "User chose to continue as is."}
                "Cancel" {Write-Host "User cancelled, exit."; return}
                default {Write-Host "Unknown, exit."; return}
            }
        }

        #region datagrid
        #Build datagrid
        if ($userInput -eq $false -or $serialnumber) {
            [array]$syncHash.tempDatagrid = @()
            foreach ($device in $result) {
                #Actual datagrid
                $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                    serialNumber="$($device.serialNumber)";
                    groupTag="$($device.groupTag)";
                    manufacturer="$($device.manufacturer)";
                    model="$($device.model)";
                    enrollmentState="$($device.enrollmentState)";
                    lastContactedDateTime="$($device.lastContactedDateTime)";
                    deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                    id="$($device.id)";
                    deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                    deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                    purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                    productKey="$($device.productKey)";
                    addressableUserName="$($device.addressableUserName)";
                    userPrincipalName="$($device.userPrincipalName)";
                    resourceName="$($device.resourceName)";
                    skuNumber="$($device.skuNumber)";
                    systemFamily="$($device.systemFamily)";
                    azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                    azureAdDeviceId="$($device.azureAdDeviceId)";
                    managedDeviceId="$($device.managedDeviceId)";
                    displayName="$($device.displayName)";
                    deviceAccountUpn="$($device.deviceAccountUpn)";
                    deviceAccountPassword="$($device.deviceAccountPassword)";
                    deviceFriendlyName="$($device.deviceFriendlyName)";
                    remediationState="$($device.remediationState)";
                    remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                    intuneId=$null;
                    intuneDeviceName=$null;
                    intuneManagedDeviceOwnerType=$null;
                    intuneEnrolledDateTime=$null;
                    intuneOsVersion=$null;
                    intuneDeviceEnrollmentType=$null;
                    intuneEmailAddress=$null;
                    intuneUserPrincipalName=$null;
                    intuneUserDisplayName=$null;
                    intuneWifiMacAddress=$null;
                    intuneEthernetMacAddress=$null;
                    intuneFreeStorageSpaceInBytes=$null;
                    intuneEnrollmentProfileName=$null;
                    autopilotDeploymentProfile=$null;
                })
                #Temporary datagrid
                [psobject]$tempObject = @{
                    serialNumber="$($device.serialNumber)";
                    groupTag="$($device.groupTag)";
                    manufacturer="$($device.manufacturer)";
                    model="$($device.model)";
                    enrollmentState="$($device.enrollmentState)";
                    lastContactedDateTime="$($device.lastContactedDateTime)";
                    deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                    id="$($device.id)";
                    deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                    deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                    purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                    productKey="$($device.productKey)";
                    addressableUserName="$($device.addressableUserName)";
                    userPrincipalName="$($device.userPrincipalName)";
                    resourceName="$($device.resourceName)";
                    skuNumber="$($device.skuNumber)";
                    systemFamily="$($device.systemFamily)";
                    azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                    azureAdDeviceId="$($device.azureAdDeviceId)";
                    managedDeviceId="$($device.managedDeviceId)";
                    displayName="$($device.displayName)";
                    deviceAccountUpn="$($device.deviceAccountUpn)";
                    deviceAccountPassword="$($device.deviceAccountPassword)";
                    deviceFriendlyName="$($device.deviceFriendlyName)";
                    remediationState="$($device.remediationState)";
                    remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                    intuneId=$null;
                    intuneDeviceName=$null;
                    intuneManagedDeviceOwnerType=$null;
                    intuneEnrolledDateTime=$null;
                    intuneOsVersion=$null;
                    intuneDeviceEnrollmentType=$null;
                    intuneEmailAddress=$null;
                    intuneUserPrincipalName=$null;
                    intuneUserDisplayName=$null;
                    intuneWifiMacAddress=$null;
                    intuneEthernetMacAddress=$null;
                    intuneFreeStorageSpaceInBytes=$null;
                    intuneEnrollmentProfileName=$null;
                    autopilotDeploymentProfile=$null;
                }
                #New object
                $syncHash.tempDatagrid += $tempObject
            }
        } else {
            #Temporary datagrid
            [array]$syncHash.tempDatagrid = @()
            foreach ($device in $result) {
                [psobject]$tempObject = @{
                    serialNumber="$($device.serialNumber)";
                    groupTag="$($device.groupTag)";
                    manufacturer="$($device.manufacturer)";
                    model="$($device.model)";
                    enrollmentState="$($device.enrollmentState)";
                    lastContactedDateTime="$($device.lastContactedDateTime)";
                    deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                    id="$($device.id)";
                    deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                    deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                    purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                    productKey="$($device.productKey)";
                    addressableUserName="$($device.addressableUserName)";
                    userPrincipalName="$($device.userPrincipalName)";
                    resourceName="$($device.resourceName)";
                    skuNumber="$($device.skuNumber)";
                    systemFamily="$($device.systemFamily)";
                    azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                    azureAdDeviceId="$($device.azureAdDeviceId)";
                    managedDeviceId="$($device.managedDeviceId)";
                    displayName="$($device.displayName)";
                    deviceAccountUpn="$($device.deviceAccountUpn)";
                    deviceAccountPassword="$($device.deviceAccountPassword)";
                    deviceFriendlyName="$($device.deviceFriendlyName)";
                    remediationState="$($device.remediationState)";
                    remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                    intuneId=$null;
                    intuneDeviceName=$null;
                    intuneManagedDeviceOwnerType=$null;
                    intuneEnrolledDateTime=$null;
                    intuneOsVersion=$null;
                    intuneDeviceEnrollmentType=$null;
                    intuneEmailAddress=$null;
                    intuneUserPrincipalName=$null;
                    intuneUserDisplayName=$null;
                    intuneWifiMacAddress=$null;
                    intuneEthernetMacAddress=$null;
                    intuneFreeStorageSpaceInBytes=$null;
                    intuneEnrollmentProfileName=$null;
                    autopilotDeploymentProfile=$null;
                }
                #New object
                $syncHash.tempDatagrid += $tempObject
            }
        }
        
        #Update datagrid with Intune and Autopilotprofile info
        #Create batch query and split into 20 per query, which is the limit
        #region intunebatch
        if ($intune) {
            $objectsFinalBatch = $result.Count % 20
            $objectTracker = 0
            $objectPointer = 0
            $batchCounter = 1
            $countFullBatches = [math]::Ceiling($result.Count / 20)
            do {
                $batches = '
                    {
                        "requests": [
                    '
                #Determine how many objects to put in batch, limit is always 20, but we might have less objects left
                if (($result.Count - ($objectTracker + 1) -lt 20)) {
                    #Less than 20 objects remaining
                    $x = $objectsFinalBatch
                } else {
                    #20 or more objects remaining
                    $x = 20
                }
                #Create json for batch, also last object cannot end with ","
                for ($i=1;$i -le $x;$i++) {
                    if ($i -lt $x) {
                        $batch = @("
                                {
                                    `"id`": `"$i`",
                                    `"method`": `"GET`",
                                    `"url`": `"deviceManagement/managedDevices/$($result[$objectTracker].managedDeviceId)`"
                                },`n
                        ")
                    } else {
                        $batch = @("
                                {
                                    `"id`": `"$i`",
                                    `"method`": `"GET`",
                                    `"url`": `"deviceManagement/managedDevices/$($result[$objectTracker].managedDeviceId)`"
                                }
                        ")
                    }
                    #Add object to json, save id toward object and prepare for next object
                    $batches += $batch
                    $objectTracker++
                }
                #Finalize json with all objects and send batch to graph
                $batches += '
                    ]
                }
                '
                #Query Graph and sort result
                $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                $responseResponses = $response.responses | Sort-Object {[int]$_.Id}
                $objectPointer = $objectTracker - $x
                #Update datagrid with Intune info
                if ($userInput -eq $false -or $serialnumber) {
                    foreach ($responseResponse in $responseResponses) {
                        #Actual datagrid
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneId=$responseResponse.body.id
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneDeviceName=$responseResponse.body.deviceName
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneManagedDeviceOwnerType=$responseResponse.body.managedDeviceOwnerType
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneEnrolledDateTime=$responseResponse.body.enrolledDateTime
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneOsVersion=$responseResponse.body.osVersion
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneDeviceEnrollmentType=$responseResponse.body.deviceEnrollmentType
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneEmailAddress=$responseResponse.body.emailAddress
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneUserPrincipalName=$responseResponse.body.userPrincipalName
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneUserDisplayName=$responseResponse.body.userDisplayName
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneWifiMacAddress=$responseResponse.body.wifiMacAddress
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneEthernetMacAddress=$responseResponse.body.ethernetMacAddress
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneFreeStorageSpaceInBytes=$responseResponse.body.freeStorageSpaceInBytes
                        $syncHash.var_datagridResults.Items[$objectPointer].intuneEnrollmentProfileName=$responseResponse.body.enrollmentProfileName
                        #Temporary datagrid
                        $syncHash.tempDatagrid[$objectPointer].intuneId=$responseResponse.body.id
                        $syncHash.tempDatagrid[$objectPointer].intuneDeviceName=$responseResponse.body.deviceName
                        $syncHash.tempDatagrid[$objectPointer].intuneManagedDeviceOwnerType=$responseResponse.body.managedDeviceOwnerType
                        $syncHash.tempDatagrid[$objectPointer].intuneEnrolledDateTime=$responseResponse.body.enrolledDateTime
                        $syncHash.tempDatagrid[$objectPointer].intuneOsVersion=$responseResponse.body.osVersion
                        $syncHash.tempDatagrid[$objectPointer].intuneDeviceEnrollmentType=$responseResponse.body.deviceEnrollmentType
                        $syncHash.tempDatagrid[$objectPointer].intuneEmailAddress=$responseResponse.body.emailAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneUserPrincipalName=$responseResponse.body.userPrincipalName
                        $syncHash.tempDatagrid[$objectPointer].intuneUserDisplayName=$responseResponse.body.userDisplayName
                        $syncHash.tempDatagrid[$objectPointer].intuneWifiMacAddress=$responseResponse.body.wifiMacAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneEthernetMacAddress=$responseResponse.body.ethernetMacAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneFreeStorageSpaceInBytes=$responseResponse.body.freeStorageSpaceInBytes
                        $syncHash.tempDatagrid[$objectPointer].intuneEnrollmentProfileName=$responseResponse.body.enrollmentProfileName
                        #New object
                        $objectPointer++
                    }
                } else {
                    foreach ($responseResponse in $responseResponses) {
                        #Temporary datagrid
                        $syncHash.tempDatagrid[$objectPointer].intuneId=$responseResponse.body.id
                        $syncHash.tempDatagrid[$objectPointer].intuneDeviceName=$responseResponse.body.deviceName
                        $syncHash.tempDatagrid[$objectPointer].intuneManagedDeviceOwnerType=$responseResponse.body.managedDeviceOwnerType
                        $syncHash.tempDatagrid[$objectPointer].intuneEnrolledDateTime=$responseResponse.body.enrolledDateTime
                        $syncHash.tempDatagrid[$objectPointer].intuneOsVersion=$responseResponse.body.osVersion
                        $syncHash.tempDatagrid[$objectPointer].intuneDeviceEnrollmentType=$responseResponse.body.deviceEnrollmentType
                        $syncHash.tempDatagrid[$objectPointer].intuneEmailAddress=$responseResponse.body.emailAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneUserPrincipalName=$responseResponse.body.userPrincipalName
                        $syncHash.tempDatagrid[$objectPointer].intuneUserDisplayName=$responseResponse.body.userDisplayName
                        $syncHash.tempDatagrid[$objectPointer].intuneWifiMacAddress=$responseResponse.body.wifiMacAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneEthernetMacAddress=$responseResponse.body.ethernetMacAddress
                        $syncHash.tempDatagrid[$objectPointer].intuneFreeStorageSpaceInBytes=$responseResponse.body.freeStorageSpaceInBytes
                        $syncHash.tempDatagrid[$objectPointer].intuneEnrollmentProfileName=$responseResponse.body.enrollmentProfileName
                        #New object
                        $objectPointer++
                    }
                }
                #Progress
                Write-Host "Intune: Processed batch: " $batchCounter " / " $countFullBatches
                if ($autopilotProfile) {
                    [int]$progress = [math]::Truncate((($batchCounter / $countFullBatches) * 100) / 2)
                } else {
                    [int]$progress = [math]::Truncate(($batchCounter / $countFullBatches) * 100)
                }
                Write-Progress -Activity "Processing Autopilot devices" -Status "$progress %" -PercentComplete $progress
                Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
                $batchCounter++
                #Loop until out of batches
            } while($batchCounter -le $countFullBatches)
        }
        #endregion intunebatch
        #region Autopilotprofile
        if ($autopilotProfile) {
            $objectsFinalBatch = $result.Count % 20
            $objectTracker = 0
            $objectPointer = 0
            $batchCounter = 1
            $countFullBatches = [math]::Ceiling($result.Count / 20)
            if ($countFullBatches -gt 10) {
                Write-Host "This will take a long time..."
            }
            do {
                $batches = '
                    {
                        "requests": [
                    '
                #Determine how many objects to put in batch, limit is always 20, but we might have less objects left
                if (($result.Count - ($objectTracker + 1) -lt 20)) {
                    #Less than 20 objects remaining
                    $x = $objectsFinalBatch
                } else {
                    #20 or more objects remaining
                    $x = 20
                }
                #Create json for batch, also last object cannot end with ","
                for ($i=1;$i -le $x;$i++) {
                    if ($i -lt $x) {
                        $batch = @("
                                {
                                    `"id`": `"$i`",
                                    `"method`": `"GET`",
                                    `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($result[$objectTracker].id)?`$expand=deploymentProfile,intendedDeploymentProfile`"
                                },`n
                        ")
                    } else {
                        $batch = @("
                                {
                                    `"id`": `"$i`",
                                    `"method`": `"GET`",
                                    `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($result[$objectTracker].id)?`$expand=deploymentProfile,intendedDeploymentProfile`"
                                }
                        ")
                    }
                    #Add object to json, save id toward object and prepare for next object
                    $batches += $batch
                    $objectTracker++
                }
                #Finalize json with all objects and send batch to graph
                $batches += '
                    ]
                }
                '
                #Query Graph and sort result
                $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                $responseResponses = $response.responses | Sort-Object {[int]$_.Id}
                $objectPointer = $objectTracker - $x
                #Update datagrid with Autopilotprofile info
                if ($userInput -eq $false -or $serialnumber) {
                    foreach ($responseResponse in $responseResponses) {
                        $syncHash.var_datagridResults.Items[$objectPointer].autopilotDeploymentProfile=$responseResponse.body.deploymentProfile.displayName;
                        $syncHash.tempDatagrid[$objectPointer].autopilotDeploymentProfile=$responseResponse.body.deploymentProfile.displayName;
                        $objectPointer++
                    }
                    $syncHash.var_datagridResults.Items.Refresh()
                } else {
                    foreach ($responseResponse in $responseResponses) {
                        $syncHash.tempDatagrid[$objectPointer].autopilotDeploymentProfile=$responseResponse.body.deploymentProfile.displayName;
                        $objectPointer++
                    }
                }
                #Progress
                Write-Host "Autopilotprofile: Processed batch: " $batchCounter " / " $countFullBatches
                [int]$progress = [math]::Truncate(((($batchCounter / $countFullBatches) * 100) / 2) + 50) #Add 50% as this is cycle number two on same batches
                Write-Progress -Activity "Processing Autopilot devices" -Status "$progress %" -PercentComplete $progress
                Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
                $batchCounter++
                #Loop until out of batches
            } while($batchCounter -le $countFullBatches)
        }
        #endregion Autopilotprofile

        #Only run if searching for anything other than serial number
        if ($userInput -and -not $serialnumber) {
            if ($devicename) {
                foreach ($device in $syncHash.tempDatagrid) {
                    if ($device.intuneDeviceName -like "*$($syncHash.txtboxQuery)*") {
                        $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                            serialNumber="$($device.serialNumber)";
                            groupTag="$($device.groupTag)";
                            manufacturer="$($device.manufacturer)";
                            model="$($device.model)";
                            enrollmentState="$($device.enrollmentState)";
                            lastContactedDateTime="$($device.lastContactedDateTime)";
                            deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                            id="$($device.id)";
                            deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                            deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                            purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                            productKey="$($device.productKey)";
                            addressableUserName="$($device.addressableUserName)";
                            userPrincipalName="$($device.userPrincipalName)";
                            resourceName="$($device.resourceName)";
                            skuNumber="$($device.skuNumber)";
                            systemFamily="$($device.systemFamily)";
                            azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                            azureAdDeviceId="$($device.azureAdDeviceId)";
                            managedDeviceId="$($device.managedDeviceId)";
                            displayName="$($device.displayName)";
                            deviceAccountUpn="$($device.deviceAccountUpn)";
                            deviceAccountPassword="$($device.deviceAccountPassword)";
                            deviceFriendlyName="$($device.deviceFriendlyName)";
                            remediationState="$($device.remediationState)";
                            remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                            intuneId="$($device.intuneId)";
                            intuneDeviceName="$($device.intuneDeviceName)";
                            intuneManagedDeviceOwnerType="$($device.intuneManagedDeviceOwnerType)";
                            intuneEnrolledDateTime="$($device.intuneEnrolledDateTime)";
                            intuneOsVersion="$($device.intuneOsVersion)";
                            intuneDeviceEnrollmentType="$($device.intuneDeviceEnrollmentType)";
                            intuneEmailAddress="$($device.intuneEmailAddress)";
                            intuneUserPrincipalName="$($device.intuneUserPrincipalName)";
                            intuneUserDisplayName="$($device.intuneUserDisplayName)";
                            intuneWifiMacAddress="$($device.intuneWifiMacAddress)";
                            intuneEthernetMacAddress="$($device.intuneEthernetMacAddress)";
                            intuneFreeStorageSpaceInBytes="$($device.intuneFreeStorageSpaceInBytes)";
                            intuneEnrollmentProfileName="$($device.intuneEnrollmentProfileName)";
                            autopilotDeploymentProfile="$($device.autopilotDeploymentProfile)";
                        })
                    }
                }  
            }
            if ($any) {
                Write-Host "Searching all objects properties with input."
                foreach ($device in $syncHash.tempDatagrid) {
                    if ($device.values -like "*$($syncHash.txtboxQuery)*") {
                        $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                            serialNumber="$($device.serialNumber)";
                            groupTag="$($device.groupTag)";
                            manufacturer="$($device.manufacturer)";
                            model="$($device.model)";
                            enrollmentState="$($device.enrollmentState)";
                            lastContactedDateTime="$($device.lastContactedDateTime)";
                            deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                            id="$($device.id)";
                            deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                            deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                            purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                            productKey="$($device.productKey)";
                            addressableUserName="$($device.addressableUserName)";
                            userPrincipalName="$($device.userPrincipalName)";
                            resourceName="$($device.resourceName)";
                            skuNumber="$($device.skuNumber)";
                            systemFamily="$($device.systemFamily)";
                            azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                            azureAdDeviceId="$($device.azureAdDeviceId)";
                            managedDeviceId="$($device.managedDeviceId)";
                            displayName="$($device.displayName)";
                            deviceAccountUpn="$($device.deviceAccountUpn)";
                            deviceAccountPassword="$($device.deviceAccountPassword)";
                            deviceFriendlyName="$($device.deviceFriendlyName)";
                            remediationState="$($device.remediationState)";
                            remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                            intuneId="$($device.intuneId)";
                            intuneDeviceName="$($device.intuneDeviceName)";
                            intuneManagedDeviceOwnerType="$($device.intuneManagedDeviceOwnerType)";
                            intuneEnrolledDateTime="$($device.intuneEnrolledDateTime)";
                            intuneOsVersion="$($device.intuneOsVersion)";
                            intuneDeviceEnrollmentType="$($device.intuneDeviceEnrollmentType)";
                            intuneEmailAddress="$($device.intuneEmailAddress)";
                            intuneUserPrincipalName="$($device.intuneUserPrincipalName)";
                            intuneUserDisplayName="$($device.intuneUserDisplayName)";
                            intuneWifiMacAddress="$($device.intuneWifiMacAddress)";
                            intuneEthernetMacAddress="$($device.intuneEthernetMacAddress)";
                            intuneFreeStorageSpaceInBytes="$($device.intuneFreeStorageSpaceInBytes)";
                            intuneEnrollmentProfileName="$($device.intuneEnrollmentProfileName)";
                            autopilotDeploymentProfile="$($device.autopilotDeploymentProfile)";
                        })
                    }
                } 
            }
            if ($syncHash.var_datagridResults.Items.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Search did not return any devices.`nSearch something else, or do an empty search.","No devices found","OK","Information") | Out-Null
            }
        }
        #Save datagrid to cache
        $syncHash.cache = $syncHash.tempDatagrid

        #endregion datagrid
        Write-Progress -Activity "Processing Autopilot devices" -Status "Ready" -Completed
    #region useCache
    } else {
        Write-Host "Instructed to use cache."
        Update-Cache -Object $syncHash.var_lblCacheSize -Text "Cache size: $($syncHash.cache.Count) devices" -Enabled
        #Enable buttons
        $syncHash.var_btnUpdateGroupTag.IsEnabled = $true
        $syncHash.var_btnDelete.IsEnabled = $true
        $syncHash.var_btnBackupSelection.IsEnabled = $true
        $syncHash.var_chkboxCache.IsEnabled = $true
        #Check if user input
        if ($userInput) {
            if ($serialnumber) {
                Write-Host "Serial number defined, look for matches."
                [array]$filteredResult = $null
                foreach ($device in $syncHash.cache) {
                    if ($device.serialNumber -like "*$($syncHash.txtboxQuery)*") {
                        $filteredResult += $device
                    }
                }
                $result = $filteredResult
            } elseif ($devicename) {
                Write-Host "device name defined, look for matches."
                [array]$filteredResult = $null
                foreach ($device in $syncHash.cache) {
                    if ($device.intuneDeviceName -like "*$($syncHash.txtboxQuery)*") {
                        $filteredResult += $device
                    }
                }
                $result = $filteredResult
            } elseif ($any) {
                Write-Host "Any defined, will search when temporary datagrid has been built."
                [array]$filteredResult = $null
                foreach ($device in $syncHash.cache) {
                    if ($device.values -like "*$($syncHash.txtboxQuery)*") {
                        $filteredResult += $device
                    }
                }
                $result = $filteredResult
            } else {
                Write-Host "No input value defined, show all Autopilot devices."
            }
            #Build datagrid if match from textbox
            if ($result) {
                Write-Host "Found device(s) with query `"$($syncHash.txtboxQuery)`""
                foreach ($device in $result) {
                    $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                        serialNumber="$($device.serialNumber)";
                        groupTag="$($device.groupTag)";
                        manufacturer="$($device.manufacturer)";
                        model="$($device.model)";
                        enrollmentState="$($device.enrollmentState)";
                        lastContactedDateTime="$($device.lastContactedDateTime)";
                        deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                        id="$($device.id)";
                        deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                        deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                        purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                        productKey="$($device.productKey)";
                        addressableUserName="$($device.addressableUserName)";
                        userPrincipalName="$($device.userPrincipalName)";
                        resourceName="$($device.resourceName)";
                        skuNumber="$($device.skuNumber)";
                        systemFamily="$($device.systemFamily)";
                        azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                        azureAdDeviceId="$($device.azureAdDeviceId)";
                        managedDeviceId="$($device.managedDeviceId)";
                        displayName="$($device.displayName)";
                        deviceAccountUpn="$($device.deviceAccountUpn)";
                        deviceAccountPassword="$($device.deviceAccountPassword)";
                        deviceFriendlyName="$($device.deviceFriendlyName)";
                        remediationState="$($device.remediationState)";
                        remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                        intuneId="$($device.intuneId)";
                        intuneDeviceName="$($device.intuneDeviceName)";
                        intuneManagedDeviceOwnerType="$($device.intuneManagedDeviceOwnerType)";
                        intuneEnrolledDateTime="$($device.intuneEnrolledDateTime)";
                        intuneOsVersion="$($device.intuneOsVersion)";
                        intuneDeviceEnrollmentType="$($device.intuneDeviceEnrollmentType)";
                        intuneEmailAddress="$($device.intuneEmailAddress)";
                        intuneUserPrincipalName="$($device.intuneUserPrincipalName)";
                        intuneUserDisplayName="$($device.intuneUserDisplayName)";
                        intuneWifiMacAddress="$($device.intuneWifiMacAddress)";
                        intuneEthernetMacAddress="$($device.intuneEthernetMacAddress)";
                        intuneFreeStorageSpaceInBytes="$($device.intuneFreeStorageSpaceInBytes)";
                        intuneEnrollmentProfileName="$($device.intuneEnrollmentProfileName)";
                        autopilotDeploymentProfile="$($device.autopilotDeploymentProfile)";
                    })
                } 
            } else {
                Write-Host "Query for `"$($syncHash.txtboxQuery)`" did not return any device(s)."
                [System.Windows.Forms.MessageBox]::Show("Search did not return any devices.`nSearch something else, or do an empty search.","No devices found","OK","Information") | Out-Null
            }
        #Show all data
        } else {
            Write-Host "No input value defined, show all Autopilot devices."
            foreach ($device in $syncHash.cache) {
                $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                    serialNumber="$($device.serialNumber)";
                    groupTag="$($device.groupTag)";
                    manufacturer="$($device.manufacturer)";
                    model="$($device.model)";
                    enrollmentState="$($device.enrollmentState)";
                    lastContactedDateTime="$($device.lastContactedDateTime)";
                    deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                    id="$($device.id)";
                    deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                    deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                    purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                    productKey="$($device.productKey)";
                    addressableUserName="$($device.addressableUserName)";
                    userPrincipalName="$($device.userPrincipalName)";
                    resourceName="$($device.resourceName)";
                    skuNumber="$($device.skuNumber)";
                    systemFamily="$($device.systemFamily)";
                    azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                    azureAdDeviceId="$($device.azureAdDeviceId)";
                    managedDeviceId="$($device.managedDeviceId)";
                    displayName="$($device.displayName)";
                    deviceAccountUpn="$($device.deviceAccountUpn)";
                    deviceAccountPassword="$($device.deviceAccountPassword)";
                    deviceFriendlyName="$($device.deviceFriendlyName)";
                    remediationState="$($device.remediationState)";
                    remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                    intuneId="$($device.intuneId)";
                    intuneDeviceName="$($device.intuneDeviceName)";
                    intuneManagedDeviceOwnerType="$($device.intuneManagedDeviceOwnerType)";
                    intuneEnrolledDateTime="$($device.intuneEnrolledDateTime)";
                    intuneOsVersion="$($device.intuneOsVersion)";
                    intuneDeviceEnrollmentType="$($device.intuneDeviceEnrollmentType)";
                    intuneEmailAddress="$($device.intuneEmailAddress)";
                    intuneUserPrincipalName="$($device.intuneUserPrincipalName)";
                    intuneUserDisplayName="$($device.intuneUserDisplayName)";
                    intuneWifiMacAddress="$($device.intuneWifiMacAddress)";
                    intuneEthernetMacAddress="$($device.intuneEthernetMacAddress)";
                    intuneFreeStorageSpaceInBytes="$($device.intuneFreeStorageSpaceInBytes)";
                    intuneEnrollmentProfileName="$($device.intuneEnrollmentProfileName)";
                    autopilotDeploymentProfile="$($device.autopilotDeploymentProfile)";
                })
            }
        }
    }
}

Function Remove-AutopilotDevice {
    #Check token status
    if ((Confirm-TokenValidity -TokenAcquired $syncHash.tokenAcquired -TokenLifetime $syncHash.token.expires_in) -ne $true) {
        Write-Host "Invalid or expired token."
        Disable-UI
        [System.Windows.Forms.MessageBox]::Show("Expired or invalid authentication.`nPlease reauthenticate by using `"Login Azure`".","Invalid/expired token","OK","Information") | Out-Null
        return
    }

    #Reset values
    $delete = $false
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 0

    #If limit is not checked:
    if ($syncHash.var_chkboxLimitDelete.IsChecked -eq $false) {
        Switch ($syncHash.var_datagridResults.SelectedItems.Count) {
            "0" {[System.Windows.Forms.MessageBox]::Show("Make a selection to delete a device from Autopilot.`n","Make a selection","OK","Information") | Out-Null; $delete = $false; return}
            {$_ -ge "2"} {[System.Windows.Forms.MessageBox]::Show("Deletion is limited to one device at a time.","Too many selections","OK","Information") | Out-Null; $delete = $false; return}
            "1" {$delete = $true}
            default {Write-Host "Not sure what happened, will exit."; $delete = $false; return}
        }
    } else {
        Write-Host "Set to override delete limit of 1."
        $delete = $true
    }

    #Continue deletion
    if ($delete) {
        [array]$devices = $syncHash.var_datagridResults.SelectedItems
        Write-Host "Array devices built."
        #Write-Host $($devices.intuneId)
        $choiceAutopilot = [System.Windows.Forms.MessageBox]::Show("$(($devices | Measure-Object).Count) device(s) marked for deletion.`n`nAfter deleting you need hardware hash from a .csv-file to recover device.`n`nAre you sure you want to continue deletion?","Confirm delete","YesNo","Information","Button2")
        if ($choiceAutopilot -eq "No") {return}
    }
    #Check if exist in Intune
    $intuneDevice = $false
    foreach ($device in $devices) {
        if ($device.intuneId -ne $null -and -not ($device.intuneId -match '^\s*$')) {
            Write-Host "Prompt for Intune deletion."
            $intuneDevice = $true
        }
    }

    if ($intuneDevice) {
        Write-Host "Intune device(s) exist"
        Switch ($devices.Count) {
            1 {$choiceIntune = [System.Windows.Forms.MessageBox]::Show("To delete this Autopilot device you must also delete the Intune device.`n`nWarning: `n- Device cannot be recovered.`n- All Intune settings will remain on device (stuck).`n- Azure AD Joined only devices need local accounts to log on.`n- BitLocker key will be lost.`n`nDelete Intune device aswell?","Intune device found","YesNo","Warning","Button2")}
            {$_ -gt 1} {
                $choiceIntune = [System.Windows.Forms.MessageBox]::Show("To delete these Autopilot devices you must also delete the Intune device associated with each device.`n`nWarning: `n- Device cannot be recovered.`n- All Intune settings will remain on device (stuck).`n- Azure AD Joined only devices need local accounts to log on.`n- BitLocker keys will be lost.`n`nDelete Intune devices aswell?","Intune devices found","YesNo","Warning","Button2")
                if ($choiceIntune -eq "Yes") {$choiceIntune = [System.Windows.Forms.MessageBox]::Show("Are you completely sure?`n`nWarning: `n- INTUNE DEVICES CANNOT BE RECOVERED!!","Intune devices found","YesNo","Warning","Button2")} 
            }
            default {Write-Host "Intune: Unknown scenario, exit..."; return}
        }
        Switch ($choiceIntune) {
            "Yes" {Write-Host "Intune: Continue deletion."}
            "No" {
                Write-Host "Intune: User cancelled deletion."
                [System.Windows.Forms.MessageBox]::Show("No devices were deleted.","User cancelled","OK","Information") | Out-Null
                return
            }
            default {Write-Host "Intune: Unknown choice, exit..."; return}
        }

        #Delete Intune device, batches
        $intuneDevices = $devices | Where-Object {$null -ne $_.intuneId}
        $objectsFinalBatch = ($intuneDevices | Measure-Object).Count % 20
        $objectTracker = 0
        $objectPointer = 0
        $batchCounter = 1
        $i = $null
        $batches = $null
        $syncHash.allIntuneBatches = $null
        $countFullBatches = [math]::Ceiling(($intuneDevices | Measure-Object).Count / 20)

        do {
            $batches = '
                {
                    "requests": [
            '
            #Determine how many objects to put in batch, limit is always 20, but we might have less objects remaining
            if ((($intuneDevices | Measure-Object).Count - ($objectTracker + 1) -lt 20)) {
                #Less than 20 objects remaining
                $x = $objectsFinalBatch
            } else {
                #20 or more objects remaining
                $x = 20
            }
            #Create json for batch, also last object cannot end with ","
            for ($i=1;$i -le $x;$i++) {
                if ($i -lt $x) {
                    $batch = @("
                        {
                            `"id`": `"$($intuneDevices[$objectTracker].id)`",
                            `"method`": `"DELETE`",
                            `"url`": `"deviceManagement/managedDevices/$($intuneDevices[$objectTracker].intuneId)`"
                        },`n
                    ")
                } else {
                    $batch = @("
                        {
                            `"id`": `"$($intuneDevices[$objectTracker].id)`",
                            `"method`": `"DELETE`",
                            `"url`": `"deviceManagement/managedDevices/$($intuneDevices[$objectTracker].intuneId)`"
                        }
                    ")
                }
                #Add object to json then go for next object
                $batches += $batch
                $objectTracker++
            }
            #Finalize json with all objects and send batch to graph
            $batches += '
                    ]
                }
            '

            #Query Graph
            $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
            Write-Host "Intune delete initiated."
            $responseResponses = $response.responses #| Sort-Object {[int]$_.Id}
            foreach ($response in $responseResponses) {
                Write-Host "Status: $($response)"
            }
            $objectPointer = $objectTracker - $x
            $syncHash.allIntuneBatches += $batches
            #Progress
            Write-Host "Intune: Processed batch: " $batchCounter " / " $countFullBatches
            [int]$progress = [math]::Truncate(((($batchCounter / $countFullBatches) * 90) / 2)) #Max 45% progress
            Write-Progress -Activity "Deleting Intune devices" -Status "$progress %" -PercentComplete $progress
            Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
            $batchCounter++
        } while($batchCounter -le $countFullBatches)
    }

    #Progress is halfways, set to 45%
    Write-Progress -Activity "Deleting Autopilot devices" -Status "45 %" -PercentComplete 45
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 45
    
    #Delete Autopilot devices
    $objectsFinalBatch = ($devices | Measure-Object).Count % 20
    $objectTracker = 0
    $objectPointer = 0
    $batchCounter = 1
    $i = $null
    $batches = $null
    $syncHash.allAutopilotBatches = $null
    $countFullBatches = [math]::Ceiling(($devices | Measure-Object).Count / 20)
    [array]$statusAutopilotDeletion = $null

    do {
        $batches = '
            {
                "requests": [
        '
        #Determine how many objects to put in batch, limit is always 20, but we might have less objects remaining
        if ((($devices | Measure-Object).Count - ($objectTracker + 1) -lt 20)) {
            #Less than 20 objects remaining
            $x = $objectsFinalBatch
        } else {
            #20 or more objects remaining
            $x = 20
        }
        #Create json for batch, also last object cannot end with ","
        for ($i=1;$i -le $x;$i++) {
            if ($i -lt $x) {
                $batch = @("
                    {
                        `"id`": `"$($devices[$objectTracker].id)`",
                        `"method`": `"DELETE`",
                        `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($devices[$objectTracker].id)`"
                    },`n
                ")
            } else {
                $batch = @("
                    {
                        `"id`": `"$($devices[$objectTracker].id)`",
                        `"method`": `"DELETE`",
                        `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($devices[$objectTracker].id)`"
                    }
                ")
            }
            #Add object to json then go for next object
            $batches += $batch
            $objectTracker++
        }

        #Finalize json with all objects and send batch to graph
        $batches += '
                ]
            }
        '
        #Query Graph
        $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
        $responseResponses = $response.responses
        Write-Host "Autopilot delete initiated."
        $responseResponses = $response.responses
        foreach ($response in $responseResponses) {
            Write-Host "Status: $($response)"
            $statusAutopilotDeletion += $response
        }
        $objectPointer = $objectTracker - $x
        $syncHash.allAutopilotBatches += $batches
        #Progress
        Write-Host "Autopilot: Processed batch: " $batchCounter " / " $countFullBatches
        [int]$progress = [math]::Truncate(((($batchCounter / $countFullBatches) * 90) / 2) + 45) #Max 90% progress
        Write-Progress -Activity "Processing Autopilot devices" -Status "$progress %" -PercentComplete $progress
        Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
        $batchCounter++
    } while($batchCounter -le $countFullBatches)

    
    #Delete AAD device
    if ($choiceIntune -eq "Yes") {
        $objectsFinalBatch = ($intuneDevices | Measure-Object).Count % 20
        $objectTracker = 0
        $objectPointer = 0
        $batchCounter = 1
        $i = $null
        $batches = $null
        $syncHash.allAadBatchesGet = $null
        $countFullBatches = [math]::Ceiling(($intuneDevices | Measure-Object).Count / 20)
        
        do {
            $batches = '
                {
                    "requests": [
            '
            #Determine how many objects to put in batch, limit is always 20, but we might have less objects remaining
            if ((($intuneDevices | Measure-Object).Count - ($objectTracker + 1) -lt 20)) {
                #Less than 20 objects remaining
                $x = $objectsFinalBatch
            } else {
                #20 or more objects remaining
                $x = 20
            }
            
            #Create json for batch, also last object cannot end with ","
            for ($i=1;$i -le $x;$i++) {
                if ($i -lt $x) {
                    $batch = @("
                        {
                            `"id`": `"$($intuneDevices[$objectTracker].azureActiveDirectoryDeviceId)`",
                            `"method`": `"GET`",
                            `"url`": `"devices?`$filter=deviceId+eq+`'$($intuneDevices[$objectTracker].azureActiveDirectoryDeviceId)`'`"
                        },`n
                    ")
                } else {
                    $batch = @("
                        {
                            `"id`": `"$($intuneDevices[$objectTracker].azureActiveDirectoryDeviceId)`",
                            `"method`": `"GET`",
                            `"url`": `"devices?`$filter=deviceId+eq+`'$($intuneDevices[$objectTracker].azureActiveDirectoryDeviceId)`'`"
                        }
                    ")
                }
                
                #Add object to json then go for next object
                $batches += $batch
                $objectTracker++
            }
            
            #Finalize json with all objects and send batch to graph
            $batches += '
                    ]
                }
            '

            #Query graph and collect data
            $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
            $responseResponses = $response.responses
            $aadDevices = $responseResponses.body.value
            $objectPointer = $objectTracker - $x
            $syncHash.allAadBatchesGet += $batches
            $batchCounter++
        } while($batchCounter -le $countFullBatches)
        

        if ($aadDevices.id) {
            #DELETE
            Write-Host "Deleting $(($aadDevices | Measure-Object).Count) AAD devices."
            $objectsFinalBatch = ($aadDevices | Measure-Object).Count % 20
            $objectTracker = 0
            $objectPointer = 0
            $batchCounter = 1
            $i = $null
            $batches = $null
            $syncHash.allAadBatchesDel = $null
            $countFullBatches = [math]::Ceiling(($aadDevices | Measure-Object).Count / 20)

            #Run only if 1 or more AAD devices
            if (($aadDevices | Measure-Object).Count -gt 0) {
                do {
                    $batches = '
                        {
                            "requests": [
                    '
                    #Determine how many objects to put in batch, limit is always 20, but we might have less objects remaining
                    if ((($aadDevices | Measure-Object).Count - ($objectTracker + 1) -lt 20)) {
                        #Less than 20 objects remaining
                        $x = $objectsFinalBatch
                    } else {
                        #20 or more objects remaining
                        $x = 20
                    }
                    
                    #Create json for batch, also last object cannot end with ","
                    for ($i=1;$i -le $x;$i++) {
                        if ($i -lt $x) {
                            $batch = @("
                                {
                                    `"id`": `"$($aadDevices[$objectTracker].id)`",
                                    `"method`": `"DELETE`",
                                    `"url`": `"devices/$($aadDevices[$objectTracker].id)`'`"
                                },`n
                            ")
                        } else {
                            $batch = @("
                                {
                                    `"id`": `"$($aadDevices[$objectTracker].id)`",
                                    `"method`": `"DELETE`",
                                    `"url`": `"devices/$($aadDevices[$objectTracker].id)`'`"
                                }
                            ")
                        }
                                
                        #Add object to json then go for next object
                        $batches += $batch
                        $objectTracker++
                    }
                    
                    #Finalize json with all objects and send batch to graph
                    $batches += '
                            ]
                        }
                    '
                    $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                    $responseResponses = $response.responses
                    Write-Host "Azure AD delete initiated."
                    $responseResponses = $response.responses #| Sort-Object {[int]$_.Id}
                    foreach ($response in $responseResponses) {
                        Write-Host "Status: $($response)"
                    }
                    $objectPointer = $objectTracker - $x
                    $syncHash.allAADBatchesDel += $batches
                    #Progress
                    Write-Host "AAD: Processed batch: " $batchCounter " / " $countFullBatches
                    [int]$progress = [math]::Truncate(((($batchCounter / $countFullBatches) * 10) + 90)) #Start at 90% progress
                    Write-Progress -Activity "Processing AAD devices" -Status "$progress %" -PercentComplete $progress
                    Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
                    $batchCounter++
                } while($batchCounter -le $countFullBatches)
            }
        }
    }

    #Set progress to 100%
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 100
    Write-Progress -Activity "Deleting Autopilot devices" -Status "100 %" -PercentComplete 100
    Write-Progress -Activity "Deleting Autopilot devices" -Status "Ready" -Completed

    #For troubleshooting purposes
    $syncHash.allIntuneBatches
    $syncHash.allAadBatchesGet
    $syncHash.allAadBatchesDel
    $syncHash.allAutopilotBatches

    #In case some devices failed to delete we log the information to LocalAppData
    if ($statusAutopilotDeletion.status -ne 200) {
        [array]$errorArray = $null
        Write-Host "Some devices failed to delete. Writing failed devices to logfile."
        foreach ($status in $statusAutopilotDeletion | Where-Object {$_.status -ne 200}) {
            $messageConverted = ConvertFrom-Json $status.body.error.message
            $errorObject = New-Object PSObject -Property ([ordered]@{
                "AutopilotId" = $status.id
                "HttpError" = $status.status
                "ErrorCode" = $status.body.error.code
                "Version" = $messageConverted._version
                "Message" = $messageConverted.Message
                "CustomApiErrorPhrase" = $messageConverted.CustomApiErrorPhrase
                "RetryAfter" = $messageConverted.RetryAfter
                "ErrorSourceService" = $messageConverted.ErrorSourceService
                "HttpHeaders" = $messageConverted.HttpHeaders
                "---" = "---"
            })
            $errorArray += $errorObject
        }
        try {
            $date = Get-Date -format "yyyy.MM.dd-HH.mm.ss"
            $filename = "$($titleCut)-AutopilotDeletionFailed-$($date).log"
            if (-not (Test-Path "$env:LOCALAPPDATA\$titleCut")) {
                New-Item -Path "$env:LOCALAPPDATA\$titleCut" -ItemType Directory -Force | Out-Null
            }
            $errorArray | Out-File "$env:LOCALAPPDATA\$titleCut\$filename" -Append
            [System.Windows.Forms.MessageBox]::Show("Some devices failed to delete from Autopilot. Please review log written under:`n`n`"$env:LOCALAPPDATA\$titleCut`"","Autopilot device(s) failed to delete","OK","Warning") | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Some devices failed to delete from Autopilot.","Autopilot device(s) failed to delete","OK","Warning") | Out-Null
        }
        Write-Host "Deletion completed."
    }
}

Function Import-APDevices {
    #Use already imported csv $syncHash.csvDevices
    #Verify headers and keep those necessary
    if ( (($syncHash.csvDevices | Get-Member | Where-Object {$_.Name -eq "Device Serial Number"}).Name) -and (($syncHash.csvDevices | Get-Member | Where-Object {$_.Name -eq "Windows Product ID"}).Name) -and (($syncHash.csvDevices | Get-Member | Where-Object {$_.Name -eq "Hardware Hash"}).Name) ) {
        Write-Host "Csv has valid Autopilot hash headers."
        if ( (($syncHash.csvDevices | Get-Member | Where-Object {$_.Name -eq "Windows Product ID"}).Name) ) {
            $csvVerified = $syncHash.csvDevices | Select-Object 'Device Serial Number','Windows Product ID','Hardware Hash','Group Tag'
        } else {
            $csvVerified = $syncHash.csvDevices | Select-Object 'Device Serial Number','Windows Product ID','Hardware Hash'
        }
    } else {
        Write-Host "Invalid headers in Autopilot hash csv-file."
        [System.Windows.Forms.MessageBox]::Show("Invalid headers in csv-file.`nMake sure this is a valid Autopilot hash file","Invalid Autopilot csv","OK","Warning") | Out-Null
        return
    }
    #Split into batches of 50
    $csvCount = ($csvVerified | Measure-Object).Count
    $objectsFinalBatch = $csvCount % 50
    $objectTracker = 0
    $batchCounter = 1
    $countFullBatches = [math]::Ceiling($csvCount / 50)
    [array]$batches = $null
    [array]$batch = $null
    #$json = $null
    do {
        #Start batch
        $batch = @("
        {
            `"importedWindowsAutopilotDeviceIdentities`": [")
        #Determine how many objects to put in batch, batch is limited to 50, but we might have less objects left
        if (($csvCount - ($objectTracker + 1) -lt 50)) {
            #Less than 50 objects remaining
            $x = $objectsFinalBatch
        } else {
            #50 or more objects remaining
            $x = 50
        }
        #Create json for batch, also last object cannot end with ","
        for ($i=1;$i -le $x;$i++) {
            #Add object to batch
            if ($csvVerified[$objectTracker].'Group Tag') {
                $groupTag = $csvVerified[$objectTracker].'Group Tag'.TrimEnd(" ")
            }
            if ($i -lt $x) {
                $batch += @("
                {
                    `"serialNumber`": `"$($csvVerified[$objectTracker].'Device Serial Number'.TrimEnd(" "))`",
                    `"productKey`": `"$($csvVerified[$objectTracker].'Windows Product Id'.TrimEnd(" "))`",
                    `"hardwareIdentifier`": `"$($csvVerified[$objectTracker].'Hardware Hash'.TrimEnd(" "))`",
                    `"groupTag`": `"$($groupTag)`"
                },")
            } else {
                $batch += @("
                {
                    `"serialNumber`": `"$($csvVerified[$objectTracker].'Device Serial Number'.TrimEnd(" "))`",
                    `"productKey`": `"$($csvVerified[$objectTracker].'Windows Product Id'.TrimEnd(" "))`",
                    `"hardwareIdentifier`": `"$($csvVerified[$objectTracker].'Hardware Hash'.TrimEnd(" "))`",
                    `"groupTag`": `"$($groupTag)`"
                }")
            }
            $objectTracker++
        }
        
        #Finish batch
        $batch += @("
            ]
        }
        ")
        $batch = $batch -join " "
        $batches += $batch
        $batchCounter++
    } while($batchCounter -le $countFullBatches)

    #Upload all Autopilot hashes
    $uri = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities/import"
    [array]$responses = $null
    foreach ($query in $batches) {
        try {
            $response = Invoke-RestMethod -Headers $syncHash.headers -Uri $uri -Method POST -Body $query -ErrorAction Stop
            $responses += $response
        } catch {
            Write-Host "Something went wrong. No devices were uploaded: " $_.Exception
            [System.Windows.Forms.MessageBox]::Show("Something went wrong. No devices were uploaded.","Import failed","OK","Error") | Out-Null
            return
        }
    }

    #Gather all importIds
    [array]$importIds = $null
    if ($responses.Count -gt 1) {
        for ($i=0;$i -lt $responses.Count;$i++) {
            $importIds += $responses[$i].value.importId[0]
        }
    } else {
        $importIds = $responses[0].value.importId[0]
    }

    
    #Create an async runspace for each importId
    foreach ($importId in $importIds) {
        $runspace = [runspacefactory]::CreateRunspace($InitialSessionState) #Import functions to runspace
        $runspace.ApartmentState = "STA" #Required for WPF
        $runspace.ThreadOptions = "ReuseThread" #Prevent memory leak
        $powershell = [Powershell]::Create()
        $powershell.Runspace = $runspace
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable("syncHash",$syncHash) #Add variables
        $runspace.SessionStateProxy.SetVariable("importId",$importId) #Add variables
        #$runspace.SessionStateProxy.SetVariable("titleCut",$titleCut) #Add variables
        $runspace | Add-Member -MemberType NoteProperty -Name "Custom" -Value "ImportAPDevices"
        $runspace | Add-Member -MemberType NoteProperty -Name "importId" -Value $importId
        $powershell.AddScript( { Trace-APDeviceImport -ImportId $importId } ) #Code to run
        $asyncObject = $powershell.BeginInvoke() | Out-Null #Start runspace
    }
    #Create async runspace to watch each importId runspace
    $runspace = [runspacefactory]::CreateRunspace($InitialSessionState) #Import functions to runspace
    $runspace.ApartmentState = "STA" #Required for WPF
    $runspace.ThreadOptions = "ReuseThread" #Prevent memory leak
    $powershell = [Powershell]::Create()
    $powershell.Runspace = $runspace
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable("syncHash",$syncHash) #Add variables
    $runspace.SessionStateProxy.SetVariable("importIds",$importIds) #Add variables
    $runspace.SessionStateProxy.SetVariable("titleCut",$titleCut) #Add variables
    $runspace | Add-Member -MemberType NoteProperty -Name "Custom" -Value "WatchAPImportRunspace"
    $powershell.AddScript( { Watch-APImportRunspace -ImportIds $importIds } ) #Code to run
    $asyncObject = $powershell.BeginInvoke() | Out-Null #Start runspace
}

Function Trace-APDeviceImport {
    #Function that will check Autopilot import status for up to 30 minutes until it times out
    param(
        [parameter(Mandatory=$true,
            HelpMessage="Provide Autopilot import id to trace status of Autopilot device import.")]
        [ValidateNotNullorEmpty()][string]$ImportId
    )
    #Run for a maximum of 1800 seconds (30 minutes)
    $seconds = 0
    Write-Host "Upload: Started."
    if ($synchash.windowIsLoaded) {
        $syncHash.var_lblUploading.Dispatcher.Invoke( [action]{$syncHash.var_lblUploading.Visibility = "Visible"} )
    }
    [void]$syncHash.hashUploading.Add($importId)
    do {
        $uriImportStatus = "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities?`$filter=ImportId eq '$($ImportId)'&`$select=id,groupTag,serialNumber,importId,assignedUserPrincipalName,state"
        Start-Sleep 30
        $seconds += 30
        Write-Host "Upload: Have waited $($seconds) seconds for status."
        try {
            $responseStatus = Invoke-RestMethod -Headers $syncHash.headers -Uri $uriImportStatus -Method Get -ErrorAction Stop
        } catch {
            Write-Host "Upload: Error, Failed to query Graph for status."
        }
        $wait = $false
        #Wait if any of the statuses are unknown or pending
        foreach ($status in $responseStatus.value.state.deviceImportStatus) {
            if ($status -eq "unknown" -or $status -eq "pending") {
                $wait = $true
            }
        }
    } while ($wait -eq $true -and $seconds -le 1799)
    
    #Collect result if it exist
    if ($responseStatus.value.state) {
        #Put each upload status into an array and print all to file
        [array]$fullStatus = $null
        $i = 1
        foreach ($status in $responseStatus.value) {
            $singleStatus = New-Object PSObject -Property ([ordered]@{
                "Number" = $i
                "ImportId" = $status.importId
                "AutopilotId" = $status.id
                "SerialNumber" = $status.serialNumber
                "AssignedUserPrincipalName" = $status.assignedUserPrincipalName
                "GroupTag" = $status.groupTag
                "ImportStatus" = $status.state.deviceImportStatus
                "RegistrationId" = $status.state.deviceRegistrationId
                "ErrorCode" = $status.state.deviceErrorCode
                "ErrorName" = $status.state.deviceErrorName
            })
            $fullStatus += $singleStatus
            $i++
        }
    } else {
        $report = Write-Outfile -Type "AutopilotImportReport" -Message "Something went wrong. Autopilot upload result was lost. Does not mean upload failed, but we cannot know for certain."
        Open-Report -Reportname $report
        return
    }
    #Store result in global array for another runspace to create report
    foreach ($status in $fullStatus) {
        $syncHash.apImportStatus.Add($status) | Out-Null
    }
    #Open report
    Write-Host "Upload: Completed. Pass message to runspace."
    #Cleanup
    if ($synchash.windowIsLoaded) {
        [void]$syncHash.hashUploading.Remove($importId)
        if (-not $syncHash.hashUploading) {
            $syncHash.var_lblUploading.Dispatcher.Invoke( [action]{$syncHash.var_lblUploading.Visibility = "Hidden"} )
        }
    }
}

Function Watch-APImportRunspace {
    param(
    [parameter(Mandatory=$true,
        HelpMessage="Provide Autopilot import id to trace status of Autopilot device import.")]
    [ValidateNotNullorEmpty()][array]$ImportIds
    )
    $seconds = 0
    [array]$importMessage = $null
    do {
        Write-Host "Sleep 30 seconds."
        Start-Sleep 30
        $seconds += 30
        $wait = $true
        #See if any runspace is still in progress, wait if still in progress
        foreach ($importId in $importIds) {
            if (-not (Get-Runspace | Where-Object {$_.importId -eq $importId -and $_.RunspaceAvailability -ne "Available"}) ) {
                $wait = $false
                Write-Host "No runspace, no need to wait, can end loop."
            } else {
                $wait = $true
            }
        }
    } while ($wait -eq $true -and $seconds -le 1859)
    
    #Gather result from runspace and cleanup
    foreach ($importId in $importIds) {
        $runspace = Get-Runspace | Where-Object {$_.importId -eq $importId -and $_.RunspaceAvailability -eq "Available"}
        if ($runspace) {
            foreach ($status in $syncHash.apImportStatus | Where-Object {$_.importId -eq $importId}) {
                Write-Host "Found completed runspace. Gather result and cleanup."
                $importMessage += $status
                $syncHash.apImportStatus.Remove($status)
            }
            #Remove runspace here using id
            Remove-Runspace -id $runspace.id
        }
    }
    #Create and open report
    if ($importMessage) {
        $importMessage = $importMessage | Format-Table -Property * -AutoSize | Out-String -Width 4096
        $report = Write-Outfile -Type "AutopilotImportReport" -Message $importMessage
        Open-Report -Reportname $report
    }
}


Function Write-Outfile {
    #Function that will create a log file for you.
    param(
        [parameter(Mandatory=$false,
            HelpMessage="Root folder path of log file.")]
            [ValidateNotNullorEmpty()][string]$Path = "$env:LOCALAPPDATA\$titleCut",
        [parameter(Mandatory=$true,
            HelpMessage="Type of log, e.g. 'AutopilotDeletionFailed'. This will be part of the filename consisting of <programname>-<type>-<date>.")]
            [ValidateNotNullorEmpty()][string]$Type,
        [parameter(Mandatory=$true,
            HelpMessage="Message to write, can be a PSObject. Will append each object to outfile.")]
            [ValidateNotNullorEmpty()][object]$Message
    )
    $date = Get-Date -format "yyyy.MM.dd-HH.mm.ss"
    $filename = "$($titleCut)-$($Type)-$($date).log"
    if (-not (Test-Path "$Path")) {
        New-Item -Path "$Path" -ItemType Directory -Force | Out-Null
    }
    $fullPath = "$($Path)\$($filename)"
    $Message | Out-File $fullPath -Append
    return $fullPath
}

Function Open-Report {
    #Function that tries to open input filename (full path) using cmtrace and fallback to notepad.
    param(
        [parameter(Mandatory=$true,
            HelpMessage="Full path to filename to open in cmtrace / notepad.")]
        [ValidateNotNullorEmpty()][string]$Reportname
    )
    #Open report
    try {
        Start-Process cmtrace.exe $Reportname -ErrorAction Stop
        $reportOpened = $true
    } catch {$reportOpened = $false}
    if (-not $reportOpened) {
        try {Start-Process "$env:windir\System32\notepad.exe" $Reportname -ErrorAction Stop}
        catch {[System.Windows.Forms.MessageBox]::Show("Tried to open created report, but failed. You can find it here:`n`"$Reportname`"","Report created","OK","Information") | Out-Null}
    }
}

Function Compare-PSObjectIdentity {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSObject]$ReferenceObject,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSObject]$DifferenceObject
    )

    $equal = $true
    $properties = ($ReferenceObject | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)
    foreach ($property in $properties) {
        $result = Compare-Object $ReferenceObject $DifferenceObject -Property "$property"
    }

    if ($result) {
        $equal = $false
    }
    return $equal
}

#endregion Functions

############################
###   LOAD FUNCTIONS   #####
############################

#region Load Functions
$InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
Get-ChildItem Function:/ | Where-Object Source -like "" | ForEach-Object {
    $functionDefinition = Get-Content "Function:\$($_.Name)"
    $sessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $functionDefinition
    $InitialSessionState.Commands.Add($sessionStateFunction)
}

#endregion Load Functions

############################
###   UI    ################
############################ 

#region UI
$syncHash.var_btnLoginAzure.Add_Click( {
    Disable-UI
    $syncHash.token = $null
    $syncHash.clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" #Microsoft Intune Powershell
    $scope = @(
        "openid"
        "offline_access"
        "DeviceManagementManagedDevices.PrivilegedOperations.All"
        "DeviceManagementManagedDevices.ReadWrite.All"
        "DeviceManagementRBAC.ReadWrite.All"
        "DeviceManagementApps.ReadWrite.All"
        "DeviceManagementConfiguration.ReadWrite.All"
        "DeviceManagementServiceConfig.ReadWrite.All"
        "Group.ReadWrite.All"
        "Directory.Read.All"
        "User.Read"
        "Group.Read.All"
        #"Directory.AccessAsUser.All" #Extra: for deleting Azure AD devices #27.06.2023 handled by MS backend
    )
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $syncHash.token = Get-CodeFlowAuthToken -RedirectUri $redirectUri -Scope $scope -ClientId $syncHash.clientId
    $syncHash.tokenAcquired = Get-Date
    if ($syncHash.token) {
        Write-Host "Token retrieved."
        $syncHash.headers = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $($syncHash.token.access_token)"
        }
        #As runspace: Refresh token in background
        $runspace = [runspacefactory]::CreateRunspace($InitialSessionState) #Import functions to runspace
        $runspace.ApartmentState = "STA" #Required for WPF
        $runspace.ThreadOptions = "ReuseThread" #Prevent memory leak
        $powershell = [Powershell]::Create()
        $powershell.Runspace = $runspace
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable("syncHash",$syncHash) #Add variables
        $runspace.SessionStateProxy.SetVariable("titleCut",$titleCut) #Add variables
        $powershell.AddScript( { Refresh-Token } ) #Code to run
        $runspace | Add-Member -MemberType NoteProperty -Name "Custom" -Value "RefreshToken" #Information about runspace
        $asyncObject = $powershell.BeginInvoke() #Start runspace
        
        #Enable UI
        $syncHash.var_btnQuery.IsEnabled = $true
        $syncHash.var_chkboxLimitUpdate.IsEnabled = $true
        $syncHash.var_chkboxAutopilotprofile.IsEnabled = $true
        $syncHash.var_chkboxUpdateDelete.IsEnabled = $true
        $syncHash.var_chkboxImportCsv.IsEnabled = $true
    } else {
        Write-Host "Failed to authenticate Azure, please retry."
        return
    }
    #Populate tenantname
    $syncHash.var_lblTenantName.Content = "Tenant name: $(Get-TenantName -Token $syncHash.token)"
} )

$syncHash.var_btnQuery.Add_Click( {
    #Populate datagrid
    Search-AutopilotDevice
    #If using csv: cleanup datagrid and query csv
    if ($syncHash.csvDevices) {
        [array]$syncHash.tempDatagrid = $syncHash.var_datagridResults.Items
        [array]$csvDevicesNotFound = $null
        $syncHash.var_datagridResults.Items.Clear()
        foreach ($csvDevice in $syncHash.csvDevices) { #.'Device Serial Number') {
            $found = $false
            foreach ($device in $syncHash.tempDatagrid) {
                #Check for duplicates and ignore if found
                $ignore = $false
                if ($device.serialNumber -eq $csvDevice.'Device Serial Number') {
                    foreach ($possibleDuplicate in $syncHash.var_datagridResults.Items) {
                        if ($possibleDuplicate.serialNumber -eq $device.serialNumber -and $possibleDuplicate.id -eq $device.id) {
                            #Write-Host "Duplicate found. Don't add this one to the datagrid."
                            $ignore = $true
                        }
                    }
                    if (-not $ignore) {
                        $syncHash.var_datagridResults.AddChild([pscustomobject]@{
                            serialNumber="$($device.serialNumber)";
                            groupTag="$($device.groupTag)";
                            manufacturer="$($device.manufacturer)";
                            model="$($device.model)";
                            enrollmentState="$($device.enrollmentState)";
                            lastContactedDateTime="$($device.lastContactedDateTime)";
                            deploymentProfileAssignmentStatus="$($device.deploymentProfileAssignmentStatus)";
                            id="$($device.id)";
                            deploymentProfileAssignmentDetailedStatus="$($device.deploymentProfileAssignmentDetailedStatus)";
                            deploymentProfileAssignedDateTime="$($device.deploymentProfileAssignedDateTime)";
                            purchaseOrderIdentifier="$($device.purchaseOrderIdentifier)";
                            productKey="$($device.productKey)";
                            addressableUserName="$($device.addressableUserName)";
                            userPrincipalName="$($device.userPrincipalName)";
                            resourceName="$($device.resourceName)";
                            skuNumber="$($device.skuNumber)";
                            systemFamily="$($device.systemFamily)";
                            azureActiveDirectoryDeviceId="$($device.azureActiveDirectoryDeviceId)";
                            azureAdDeviceId="$($device.azureAdDeviceId)";
                            managedDeviceId="$($device.managedDeviceId)";
                            displayName="$($device.displayName)";
                            deviceAccountUpn="$($device.deviceAccountUpn)";
                            deviceAccountPassword="$($device.deviceAccountPassword)";
                            deviceFriendlyName="$($device.deviceFriendlyName)";
                            remediationState="$($device.remediationState)";
                            remediationStateLastModifiedDateTime="$($device.remediationStateLastModifiedDateTime)";
                            intuneId="$($device.intuneId)";
                            intuneDeviceName="$($device.intuneDeviceName)";
                            intuneManagedDeviceOwnerType="$($device.intuneManagedDeviceOwnerType)";
                            intuneEnrolledDateTime="$($device.intuneEnrolledDateTime)";
                            intuneOsVersion="$($device.intuneOsVersion)";
                            intuneDeviceEnrollmentType="$($device.intuneDeviceEnrollmentType)";
                            intuneEmailAddress="$($device.intuneEmailAddress)";
                            intuneUserPrincipalName="$($device.intuneUserPrincipalName)";
                            intuneUserDisplayName="$($device.intuneUserDisplayName)";
                            intuneWifiMacAddress="$($device.intuneWifiMacAddress)";
                            intuneEthernetMacAddress="$($device.intuneEthernetMacAddress)";
                            intuneFreeStorageSpaceInBytes="$($device.intuneFreeStorageSpaceInBytes)";
                            intuneEnrollmentProfileName="$($device.intuneEnrollmentProfileName)";
                            autopilotDeploymentProfile="$($device.autopilotDeploymentProfile)";
                        })
                    }
                    $found = $true
                }
            }
            if (-not $found) {
                if ($csvDevicesNotFound -eq $null) {
                    $csvDevicesNotFound += "Csv query did not find all device(s). Make sure you're not limited by cache.`nThese device(s) were not found when querying using csv:`n"
                }
                $csvDevicesNotFound += $csvDevice
            }
        }
        if ($csvDevicesNotFound) {
            $reportName = Write-Outfile -Type "CsvDevicesNotFound" -Message $csvDevicesNotFound
            $openReport = [System.Windows.Forms.MessageBox]::Show("Csv query did not find all devices. Report was created showing devices not found. Report is located here:`n`n$($reportName)`n`nDo you want to open the report?","Csv devices not found","YesNo","Information")
            if ($openReport -eq "Yes") {
                Open-Report -Reportname $reportName
            }
        }
    }

} )

$syncHash.var_btnUpdateGroupTag.Add_Click( {
    #Check token status
    if ((Confirm-TokenValidity -TokenAcquired $syncHash.tokenAcquired -TokenLifetime $syncHash.token.expires_in) -ne $true) {
        Write-Host "Invalid or expired token."
        Disable-UI
        [System.Windows.Forms.MessageBox]::Show("Expired or invalid authentication.`nPlease reauthenticate by using `"Login Azure`".","Invalid/expired token","OK","Information") | Out-Null
        return
    }

    Update-Progressbar -Object $syncHash.var_progressBar -Percent 0
    $syncHash.var_txtboxGroupTag.Text = $syncHash.var_txtboxGroupTag.Text.TrimStart(" ").TrimEnd(" ")
    $syncHash.txtboxGroupTag = $syncHash.var_txtboxGroupTag.Text
    #Check if multiple selections are made and if we are to override
    if ($syncHash.var_datagridResults.SelectedItems.Count -ge 5 -and $syncHash.var_chkboxLimitUpdate.IsChecked -eq $false) {
        [System.Windows.Forms.MessageBox]::Show("Too many selections.`nNo changes were made.`nUse checkbox to override.","Too many selections","OK","Information") | Out-Null
    } elseif ($syncHash.var_datagridResults.SelectedItems.Count -lt 1) {
        [System.Windows.Forms.MessageBox]::Show("No selections.`nNo changes were made.`nQuery, then click item in list to change.","No selections","OK","Information") | Out-Null
    } else {
        $objectsFinalBatch = $syncHash.var_dataGridResults.SelectedItems.Count % 20
        $objectTracker = 0
        $batchCounter = 1
        $countFullBatches = [math]::Ceiling($syncHash.var_dataGridResults.SelectedItems.Count / 20)
        do {
            $batches = '
                {
                    "requests": [
                '
            #Determine how many objects to put in batch, limit is always 20, but we might have less objects left
            if (($syncHash.var_dataGridResults.SelectedItems.Count - ($objectTracker + 1) -lt 20)) {
                #Less than 20 objects remaining
                $x = $objectsFinalBatch
            } else {
                #20 or more objects remaining
                $x = 20
            }
            #Create json for batch, also last object cannot end with ","
            for ($i=1;$i -le $x;$i++) {
                if ($i -lt $x) {
                    $batch = @("
                            {
                                `"id`": `"$i`",
                                `"method`": `"POST`",
                                `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($syncHash.var_dataGridResults.SelectedItems[$objectTracker].id)/updateDeviceProperties`",
                                `"body`": {
                                    `"groupTag`": `"$($syncHash.txtboxGroupTag)`"
                                },
                                `"headers`": {
                                    `"Content-Type`": `"application/json`"
                                }
                            },`n
                    ")
                } else {
                    $batch = @("
                            {
                                `"id`": `"$i`",
                                `"method`": `"POST`",
                                `"url`": `"deviceManagement/windowsAutopilotDeviceIdentities/$($syncHash.var_dataGridResults.SelectedItems[$objectTracker].id)/updateDeviceProperties`",
                                `"body`": {
                                    `"groupTag`": `"$($syncHash.txtboxGroupTag)`"
                                },
                                `"headers`": {
                                    `"Content-Type`": `"application/json`"
                                }
                            }
                    ")
                }
                #Add object to json, save id toward object and prepare for next object
                $batches += $batch
                $objectTracker++
            }
            #Finalize json
            $batches += '
                ]
            }
            '
            #Query Graph and sort result
            $response = Invoke-RestMethod -Headers $syncHash.headers -uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
            if ($response.responses.status -eq 403) {
                Write-Host "Access denied."
                [System.Windows.Forms.MessageBox]::Show("Failed to update device(s).`nMake sure you have one of the following roles:`n- Intune Administrator`n- Global Admin","Insufficient permissions","OK","Error") | Out-Null
                return
            }
            Write-Host "GroupTag: Processed batch: " $batchCounter " / " $countFullBatches
            [int]$progress = [math]::Truncate((($batchCounter / $countFullBatches) * 100))
            Write-Progress -Activity "Updating Group Tags" -Status "$progress %" -PercentComplete $progress
            Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
            $batchCounter++
            #Loop until out of batches
        } while($batchCounter -le $countFullBatches)
        Write-Progress -Activity "Processing Autopilot devices" -Status "Ready" -Completed
        [System.Windows.Forms.MessageBox]::Show("Updated device(s).`nWill take a few minutes to see changes.","Updated device(s)","OK","Information") | Out-Null
    }
} )

$syncHash.var_btnBackupSelection.Add_Click( {
    if ($syncHash.var_datagridResults.SelectedItems.Count -lt 1) {
        [System.Windows.Forms.MessageBox]::Show("No selections.`nSelect items from list to backup.","No selections","OK","Information") | Out-Null
    } else {
        $date = Get-Date -format "yyyy.MM.dd-HH.mm.ss"
        $filename = "$($titleCut)-Backup-$($date).csv"
        try {
            if (-not (Test-Path "$env:LOCALAPPDATA\$titleCut")) {
                New-Item -Path "$env:LOCALAPPDATA\$titleCut" -ItemType Directory -Force | Out-Null
            }
            $syncHash.var_datagridResults.SelectedItems | Export-CSV "$env:LOCALAPPDATA\$titleCut\$filename" -Append -ErrorAction Stop | Out-Null
            Start-Sleep 1
            [System.Windows.Forms.MessageBox]::Show("Backup made.`nBackup location:`n$env:LOCALAPPDATA\$titleCut\$filename`n`nTHIS IS NOT AN AUTOPILOT HARDWARE HASH BACKUP!","Successful backup","OK","Information") | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Backup failed.`nBackup location:`n$env:LOCALAPPDATA\$titleCut\$filename","Failed backup","OK","Error") | Out-Null
        }
    }
} )

$syncHash.var_chkboxCache.Add_Click( {
    Switch ($syncHash.var_chkboxCache.IsChecked) {
        #Set interface
        "True" {$syncHash.var_chkboxAutopilotprofile.IsEnabled = $false}
        "False" {$syncHash.var_chkboxAutopilotprofile.IsEnabled = $true}
    }
} )

$syncHash.var_chkboxUpdateDelete.Add_Click( {
    Switch ($syncHash.var_chkboxUpdateDelete.IsChecked) {
        #Set interface
        "True" {
            $syncHash.var_chkboxLimitUpdate.IsEnabled = $false
            $syncHash.var_chkboxLimitUpdate.IsChecked = $false
            $syncHash.var_chkboxLimitDelete.IsEnabled = $true
            $syncHash.var_btnUpdateGroupTag.Visibility = "Hidden"
            $syncHash.var_btnDelete.Visibility = "Visible"
        }
        "False" {
            $syncHash.var_chkboxLimitDelete.IsEnabled = $false
            $synchash.var_chkboxLimitDelete.IsChecked = $false            
            $syncHash.var_chkboxLimitUpdate.IsEnabled = $true
            $syncHash.var_btnUpdateGroupTag.Visibility = "Visible"
            $syncHash.var_btnDelete.Visibility = "Hidden"
        }
    }

} )

$syncHash.var_btnDelete.Add_Click( {
    Remove-AutopilotDevice
} )

$syncHash.var_chkboxImportCsv.Add_Click( {
    #Import csv
    if ($syncHash.var_chkboxImportCsv.IsChecked) {
        $syncHash.csvDevices = Import-CsvDevices
        if ($syncHash.csvDevices) {
            Write-Host "Csv successfully imported."
            $syncHash.var_txtblkImportCsv.Visibility = "Visible"
            #Enable Autopilot upload
            $syncHash.var_btnUploadHash.Visibility = "Visible"
            $syncHash.var_btnUploadHash.IsEnabled = $true
            #Disable search box
            $syncHash.var_txtboxQuery.IsEnabled = $false
            $syncHash.var_txtboxQuery.Text = ""
        } else {
            $syncHash.var_chkboxImportCsv.IsChecked = $false
        }
    } else {
    #Unload csv: wipe variable and enable search box
        $syncHash.csvDevices = $null
        $syncHash.var_txtboxQuery.IsEnabled = $true
        $syncHash.var_txtblkImportCsv.Text = "Csv imported and used for query: "
        $syncHash.var_txtblkImportCsv.Visibility = "Hidden"
        #$syncHash.var_btnUploadHash.Visibility = "Hidden"
        $syncHash.var_btnUploadHash.IsEnabled = $false
    }
} )

$syncHash.var_btnUploadHash.Add_Click( {
    Import-APDevices
} )

#endregion UI

############################
###   LAUNCH GUI  ##########
############################ 

$syncHash.Window.Add_Closed( {
    $syncHash.windowIsLoaded = $false
    Write-Host "GUI was closed."
} )

$syncHash.windowIsLoaded = $true
$syncHash.Window.ShowDialog() | Out-Null

#Cleanup after exit
Remove-Runspace -Custom "RefreshToken" -Force #Force stop refreshing token
Remove-Runspace -Custom "ImportAPDevices" #Don't force, let it finish
Remove-Runspace -Custom "WatchAPImportRunspace" #Don't force, let it finish
