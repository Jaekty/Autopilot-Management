#######################################
###   Autopilot Management   ##########
#######################################
# Author - Espen Jaegtvik
# GitHub - https://github.com/Jaekty/Autopilot-Management
# 1.0.0 - 24.05.2023 - First version release.
# 1.0.1 - 27.06.2023 - Removed unnecessary scope permission causing difficulties manually granting adminconsent.
# 1.1.0 - 04.07.2023 - Context menu on datagrid (right click) to show/hide columns, changed global variables to script, grid counter, logout button.
# 1.1.1 - 18.07.2023 - Bugfix Autopilot upload report.
# 1.1.2 - 07.05.2024 - Replaced deprecated Enterprise App "Microsoft Intune PowerShell" with "Microsoft Graph Command Line Tools" for authentication. Also fixed a bug where the last 20 objects during group tag change were ignored.
# 1.2.0 - 15.11.2024 - Now supporting passwordless authentication with WebView2 Edge browser. Query throttle handling. Cache as default. Version check.
# 1.3.0 - 23.01.2025 - Rewrote some code, primarily deletion; added delete options only Intune, only Autopilot or both. Bugfix Autopilot upload, was missing "Assigned User".

# To-do:
# Add logging window which can be opened with a checkbox
# Permission check read for query, permission check admin for update group tag
# Make all buttons into Powershell runspaces for efficiency
# Save BitLocker info
# Double click Autopilot object to list more Intune-information
# Query efficiency and optional Intune data

############################
###   BUILD GUI   ##########
############################ 
#region Build GUI
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
$version = "1.3.0"
$title = "Autopilot Management"
$titleCut = "AutopilotManagement"
$inputXaml = @"
<Window x:Class="AutopilotManagement.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:AutopilotManagement"
        mc:Ignorable="d"
        Title="$($title)" Height="550" Width="1500">
    <Grid>
        <Label x:Name="lblAuthor" Content="Author: Espen Jaegtvik - $($version)" HorizontalAlignment="Left" Margin="683,13,0,0" VerticalAlignment="Top" Opacity="0.5" FontSize="10" RenderTransformOrigin="0.917,0.259"/>
        <Label x:Name="lblSerialnumber" Content="Serialnumber" HorizontalAlignment="Left" Margin="603,35,0,0" VerticalAlignment="Top" FontSize="16" Visibility="Hidden"/>
        <Label x:Name="lblGroupTag" Content="Group Tag" HorizontalAlignment="Left" Margin="10,136,0,0" VerticalAlignment="Top" FontSize="16" Width="104"/>
        <Label x:Name="lblProgress" Content="Progress:" HorizontalAlignment="Left" Margin="159,15,0,0" VerticalAlignment="Top" FontSize="16" Width="85"/>
        <Label x:Name="lblTenantName" Content="Tenant:" HorizontalAlignment="Left" Margin="10,54,0,0" VerticalAlignment="Top" FontSize="12" Width="300"/>
        <Label x:Name="lblCacheSize" Content="Cache size: " HorizontalAlignment="Left" Margin="498,147,0,0" VerticalAlignment="Top" Opacity="0.8" Visibility="Visible"/>
        <Label x:Name="lblUploading" Content="Upload in progress..." HorizontalAlignment="Left" Margin="858,82,0,0" VerticalAlignment="Top" Width="111" Height="26" FontSize="10" Visibility="Hidden"/>
        <TextBlock x:Name="txtblkImportCsv" HorizontalAlignment="Left" Margin="700,99,0,0" TextWrapping="Wrap" Text="Csv imported and used for query: " VerticalAlignment="Top" Width="315" Height="52" Opacity="0.8" Visibility="Hidden"/>
        <ProgressBar x:Name="progressBar" HorizontalAlignment="Left" Height="20" Margin="249,21,0,0" VerticalAlignment="Top" Width="237"/>
        <TextBox x:Name="txtboxQuery" HorizontalAlignment="Left" Margin="163,94,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="232" Height="28" FontSize="12"/>
        <TextBox x:Name="txtboxGroupTag" HorizontalAlignment="Left" Margin="163,139,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="232" Height="28" FontSize="12"/>
        <Button x:Name="btnLoginAzure" Content="Login Azure" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" Height="36" Width="76" FontSize="13"/>
        <Button x:Name="btnLogout" Content="Logout" HorizontalAlignment="Left" Margin="98,10,0,0" VerticalAlignment="Top" Height="36" Width="56" FontSize="13" IsEnabled="False"/>
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
            <DataGrid.Resources>
                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#0064FF"/>
                <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}" Color="#CCDAFF"/>
            </DataGrid.Resources>
            <DataGrid.ContextMenu>
                <ContextMenu>
                </ContextMenu>
            </DataGrid.ContextMenu>
            <DataGrid.Columns>
                <!-- Autopilot -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Serial number" Binding="{Binding serialNumber}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Group Tag" Binding="{Binding groupTag}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Manufacturer" Binding="{Binding manufacturer}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Model" Binding="{Binding model}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Enrollment state" Binding="{Binding enrollmentState}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Last Contact" Binding="{Binding lastContactedDateTime}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Profile assignment state" Binding="{Binding deploymentProfileAssignmentStatus}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Id" Binding="{Binding id}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Deployment profile assignment detailed status" Binding="{Binding deploymentProfileAssignmentDetailedStatus}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Deployment profile assigned DateTime" Binding="{Binding deploymentProfileAssignedDateTime}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Purchase order identifier" Binding="{Binding purchaseOrderIdentifier}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Product key" Binding="{Binding productKey}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Addressable username" Binding="{Binding addressableUserName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Assigned user" Binding="{Binding userPrincipalName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Resource name" Binding="{Binding resourceName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Sku number" Binding="{Binding skuNumber}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="System family" Binding="{Binding systemFamily}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Azure Active Directory device id" Binding="{Binding azureActiveDirectoryDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Azure AD device id" Binding="{Binding azureAdDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Managed device id" Binding="{Binding managedDeviceId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Display name" Binding="{Binding displayName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Device account UPN" Binding="{Binding deviceAccountUpn}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Device account password" Binding="{Binding deviceAccountPassword}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Device friendly name" Binding="{Binding deviceFriendlyName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Remediation state" Binding="{Binding remediationState}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Remediation state last modified DateTime" Binding="{Binding remediationStateLastModifiedDateTime}" Visibility="Hidden"/>
                <!-- Intune -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune Device name" Binding="{Binding intuneDeviceName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune User display name" Binding="{Binding intuneUserDisplayName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune User principal name" Binding="{Binding intuneUserPrincipalName}"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune id" Binding="{Binding intuneId}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune enrollment profile name" Binding="{Binding intuneEnrollmentProfileName}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune managed device owner type" Binding="{Binding intuneManagedDeviceOwnerType}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune enrolled DateTime" Binding="{Binding intuneEnrolledDateTime}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune OS version" Binding="{Binding intuneOsVersion}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune device enrollment type" Binding="{Binding intuneDeviceEnrollmentType}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune email address" Binding="{Binding intuneEmailAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune Wifi MAC address" Binding="{Binding intuneWifiMacAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune Ethernet MAC address" Binding="{Binding intuneEthernetMacAddress}" Visibility="Hidden"/>
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Intune free storage space in Bytes" Binding="{Binding intuneFreeStorageSpaceInBytes}" Visibility="Hidden"/>
                <!-- Autopilot profile -->
                <DataGridTextColumn CanUserSort="True" CanUserReorder="True" Header="Autopilot profile" Binding="{Binding autopilotDeploymentProfile}"/>
            </DataGrid.Columns>
        </DataGrid>
    </Grid>
</Window>
"@

#Cleanup XAML
$xaml = $inputXaml -Replace 'mc:Ignorable="d"', '' -Replace "x:N", 'N' -Replace '^<Win.*', '<Window' `
                   -Replace 'd:ItemsSource="{d:SampleData ItemCount=5}"', '' -Replace "x:Class=`"AutopilotManagement.MainWindow`"", ""
[XML]$xaml = $xaml

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$script:syncHash = [Hashtable]::Synchronized(@{})

try {
    $syncHash.Window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Warning $_.Exception
    throw
}

#Create variables
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try {
        #Write-Host "Variable: var_$($_.Name)"
        $syncHash.Add("var_$($_.Name)",$syncHash.Window.FindName($_.Name))
    } catch {
        throw
    }
}
$script:syncHash.token = $null
$script:syncHash.tokenAcquired = $null
$script:syncHash.headers = $null
$script:syncHash.cache = $null
$script:syncHash.csvDevices = $null
$script:syncHash.hashUploading = [System.Collections.ArrayList]::New()
$script:syncHash.apImportStatus = [System.Collections.ArrayList]::New()

#endregion Build GUI

############################
###   FUNCTIONS   ##########
############################ 
#region Functions

Function Get-CodeFlowAuthToken {
    #v0.1 - ebj@atea.no - 18.03.2022
    #v0.2 - ebj@atea.no - 21.03.2022 - bugfix PKCE
    #v1.0 - ebj@atea.no - 12.06.2022 - bugfix login window
    #v1.1 - ebj@atea.no - 17.01.2023 - added support for refresh token
    #v1.2 - ebj@atea.no - 24.01.2023 - bugfix refresh token
    #v1.3 - ebj@atea.no - 01.08.2023 - bugfix redirecturi
    #v2.0 - ebj@atea.no - 23.10.2024 - WebView2 support
    #v2.1 - ebj@atea.no - 24.10.2024 - added code check
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
        [Parameter(Mandatory = $false,
                   ParameterSetName = "New",
                   HelpMessage='This is the length of the random generated Proof Key for Code Exchange for acquiring the token through the flow. Default is 128, which is also the max.')]
                   [ValidateRange(43, 128)][int]$PKCELength = 128,
        [Parameter(Mandatory = $false,
                   ParameterSetName = "New",
                   HelpMessage='This is where you provide the root folder with dll files to load WebView2 programmatically. You will need "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll" and "WebView2Loader.dll". If these are not provided, or fail to import, legacy browser will be used.')]
                   [string]$WebView2RootDll,
        [Parameter(Mandatory = $true,
                   ParameterSetName = "Refresh",
                   HelpMessage='Used to refresh the token. Pass your current token which has the "access_token", "id_token" and "refresh_token".')]
                   [ValidateNotNullOrEmpty()][object]$CurrentToken
    )
    #Create PKCE
    $codeChallenge = $null
    $codeVerifier = $null
    [int]$count = 0
    #Random string
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
    } while ($count -lt $PKCELength)
    #Create code challenge with S256-hash and base64url
    $sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("sha256")
    $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
    $base64 = ([System.Convert]::ToBase64String($hash)).SubString(0,43)
    $codeChallenge = ($base64.Split("=")[0]).Replace("+","-").Replace("/","_").Replace("=","")
    #The actual PKCE object
    $PKCE = New-Object psobject -Property @{
        CodeVerifier = $codeVerifier
        CodeChallenge = $codeChallenge
    }

    #Variables to create uri
    if ($tenantName -ne "common") { $tenantName = ((Invoke-RestMethod -uri "https://login.microsoftonline.com/$tenantName/.well-known/openid-configuration").token_endpoint).Replace("https://login.microsoftonline.com/","").Replace("/oauth2/token","") }
    if ($PSCmdlet.ParameterSetName -eq "New") {
        $convertedScope, $convertedRedirectUri = $null
        $convertedScope = [System.Uri]::EscapeDataString($scope) #(Get-HTMLFriendly -Replace $scope) -join "%20"
        $convertedRedirectUri = [System.Uri]::EscapeDataString($RedirectUri) #Get-HTMLFriendly -Replace $redirectUri
        $state = $codeChallenge.Substring(0, 27)
        $prompt = "prompt=select_account"
        $codeChallenge = $PKCE.codeChallenge
        $codeVerifier = $PKCE.codeVerifier
    }

    #Add required assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Web
    $Legacy = $true
    if ($WebView2RootDll) {
        try {
            Get-ChildItem -Path "$WebView2RootDll\WebView2Loader.dll" -ErrorAction Stop | Out-Null
            Add-Type -Path "$WebView2RootDll\Microsoft.Web.WebView2.Core.dll" -ErrorAction Stop
            Add-Type -Path "$WebView2RootDll\Microsoft.Web.WebView2.WinForms.dll" -ErrorAction Stop
            Write-Host "Successfully imported WebView2 (Edge) dll files, can disable legacy mode and continue."
            $Legacy = $false
        } catch {
            Write-Warning "Failed to import one or several of the required files: Microsoft.Web.WebView2.Core.dll, Microsoft.Web.WebView2.WinForms.dll, WebView2Loader.dll from root dll folder `"$WebView2RootDll`". Fallback to legacy browser."
        }
    }

    #New token
    if ($PSCmdlet.ParameterSetName -eq "New") {
        $uri = "https://login.microsoftonline.com/$($tenantName)/oauth2/v2.0/authorize?client_id=$($clientId)&scope=$($convertedScope)&redirect_uri=$($convertedRedirectUri)&response_mode=query&response_type=code&code_challenge=$($codeChallenge)&code_challenge_method=S256&$($prompt)" #&$($authority)
    } 

    #Refresh token
    else { 
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
    $global:code = @{}
    #Legacy browser
    if ($Legacy) {
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
        #Extract code
        $global:code = @{}
        #First attempt to get code
        foreach ($key in $queryOutput.Keys) {
            $code["$key"] = $queryOutput[$key]
        }
        #Second attempt to get code
        if ($code.code -eq $null) {
            try {
                $ErrorActionPreference = "Stop"
                $tempCode = ([string]($web.DocumentText.Split("`n") | `
                #Select-String -Pattern "document.location.replace")).Replace("document.location.replace(`"urn:ietf:wg:oauth:2.0:oob?","")
                Select-String -Pattern "document.location.replace")).Replace("document.location.replace(`"$redirectUri","")
                $tempCode = ($tempCode.Split("\") | Where-Object {$_ -match "code="}).Replace(" ","").Replace("code=","")
                $code.code = $tempCode
                $ErrorActionPreference = "Continue"
            } catch {
                $ErrorActionPreference = "Continue"
                Write-Host "Failed to get code. Can not retrieve token. Reason: User might have cancelled web form."
                return
            }
        }
        #Save code to single string
        $code = $code.code
    }
    #WebView2 / Edge browser
    else {
        #Set user data folder path
        $userData = "$env:LOCALAPPDATA\Temp"
        #Create a new form
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        $form = [Windows.Forms.Form]@{
            Size = [Drawing.Size]::new(800, 600)
        }
        #Create a new WebView2 control
        $webView2 = [Microsoft.Web.WebView2.WinForms.WebView2]::new()
        $webView2.Size = $form.ClientSize
        $webView2.CreationProperties = [Microsoft.Web.WebView2.WinForms.CoreWebView2CreationProperties]::new()
        $webView2.CreationProperties.UserDataFolder = $userData
        #Add the WebView2 control to the form
        [void]$form.Controls.Add($webView2)
        #Configure WebView2 cleanup when form closes
        $form.add_Closed({
            $webView2.Dispose()
        })
        #Configure WebView2 once the environment is ready
        $webView2.add_CoreWebView2InitializationCompleted({
            param ($sender, $e)
            if ($e.IsSuccess) {
                #CoreWebView2 is now initialized
                $webView2.CoreWebView2.Navigate($uri)
                #Attach the NavigationCompleted event handler
                $webView2.CoreWebView2.add_NavigationCompleted({
                    param ($sender, $e)
                    if ($e.IsSuccess) {
                    } elseif ($sender.Source -like "$($redirectUri)*") {
                        $global:code = $sender.Source -replace "$($redirectUri)\/\?code=","" -replace "&session_state=.*"
                        [void]$webView2.Dispose()
                        [void]$form.Close()
                    }
                })
            } else {
                Write-Error "WebView2 initialization failed: $($e.InitializationException.Message)"
            }
        })
        #Start initializing the WebView2 environment
        $webView2.EnsureCoreWebView2Async($webView2EnvTask.Result) | Out-Null
        #Display the form
        [void]$form.ShowDialog()
    }

    #Verify response
    if ($code -eq "" -or $code.Count -eq 0) {
        Write-Warning "Authentication was either canceled by the user, or failed."
        return #Invalid code returned, can not continue
    }

    #Get token using code and code verifier
    $uri = "https://login.microsoftonline.com/$($tenantName)/oauth2/v2.0/token"
    $scope = $scope -join " "
    $body = @{
        grant_type = "authorization_code"
        client_id = $clientId
        scope = $scope -join ""
        code = $code
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

    #Return token
    Write-Host "Returning token."
    return $token
}
#endregion token

Function Start-PrepareEnvironment {
    #Set session to use TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    #syncHash variables
    $syncHash.workDirRoot = "$($env:LOCALAPPDATA)\$titleCut"
    $syncHash.workDirTemp = "$($syncHash.workDirRoot)\Temp"
    $syncHash.workDirDll  = "$($syncHash.workDirRoot)\dll"

    #Work directory
    if ((Test-Path -Path "$($syncHash.workDirRoot)" -PathType Container) -eq $false) {
        try {
            New-Item -Path $syncHash.workDirRoot -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Failed to create working directory at `"$($syncHash.workDirRoot)`". Error: $($_.Exception.Message)"
            return
        }
    }

    #Temp directory
    if ((Test-Path -Path "$($syncHash.workDirTemp)" -PathType Container) -eq $false) {
        try {
            New-Item -Path $syncHash.workDirTemp -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Failed to create temp directory at `"$($syncHash.workDirTemp)`". Error: $($_.Exception.Message)"
            return
        }
    }

    #Dll directory
    if ((Test-Path -Path "$($syncHash.workDirDll)" -PathType Container) -eq $false) {
        try {
            New-Item -Path $syncHash.workDirDll -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Failed to create dll directory at `"$($syncHash.workDirDll)`". Error: $($_.Exception.Message)"
            return
        }
    }

    #Download WebView2 / Edge dll files for authentication browser prompt. Workdir must exist for this to run
    try {
        $dlls = Get-ChildItem -Path $syncHash.workDirDll -Filter "*.dll" -ErrorAction Stop
        $downloadDlls = $true
        foreach ($dll in $dlls) {
            if ([version]$dll.VersionInfo.ProductVersion -ge $dllsTargetVersion) {
                $downloadDlls = $false
            }
        }
        if ($downloadDlls) {
            Invoke-RestMethod -Uri "https://github.com/Jaekty/WebView2/raw/refs/tags/v1.0.864.35/Microsoft.Web.WebView2.Core.dll" -OutFile "$($syncHash.workDirDll)\Microsoft.Web.WebView2.Core.dll" -ErrorAction Stop
            Invoke-RestMethod -Uri "https://github.com/Jaekty/WebView2/raw/refs/tags/v1.0.864.35/Microsoft.Web.WebView2.WinForms.dll" -OutFile "$($syncHash.workDirDll)\Microsoft.Web.WebView2.WinForms.dll" -ErrorAction Stop
            Invoke-RestMethod -Uri "https://github.com/Jaekty/WebView2/raw/refs/tags/v1.0.864.35/WebView2Loader.dll" -OutFile "$($syncHash.workDirDll)\WebView2Loader.dll" -ErrorAction Stop
            Write-Host "WebView2 dlls (Edge authenticaion browser) successfully downloaded to `"$($syncHash.workDirDll)`"."
        }
    } catch {
        Write-Host "Failed to verify or download WebView2 dll files for browser authentication, fallback to legacy browser. Error: $($_.Exception.Message)"
    }

    #Verify if running latest version
    $gitHtml = Invoke-RestMethod -Uri "https://github.com/Jaekty/Autopilot-Management" -Method Get
    $gitHtml -match "Autopilot.Management.*.v(\d+\.\d+\.\d+).exe" | Out-Null
    $gitVersion = $Matches[1]
    if ([version]$version -lt [version]$gitVersion) {
        Write-Host "New version is available on github @ https://github.com/Jaekty/Autopilot-Management"
        [System.Windows.Forms.MessageBox]::Show("New version is available on github @ https://github.com/Jaekty/Autopilot-Management","New version available","OK","Information") | Out-Null
    }

}

Function Start-CleanupEnvironment {
    if ((Test-Path "$($syncHash.workDirTemp)")) {
        try {
            Remove-Item "$($syncHash.workDirTemp)\*.*" -Recurse -ErrorAction Stop
        } catch {
            Write-Host "Failed to cleanup temporary files in workdir temporary directory at `"$($syncHash.workDirTemp)`". Error $($_.Exception.Message)"
        }
    }
    #Cleanup after exit
    Remove-Runspace -Custom "RefreshToken" -Force #Force stop refreshing token
    Remove-Runspace -Custom "ImportAPDevices" #Don't force, let it finish
    Remove-Runspace -Custom "WatchAPImportRunspace" #Don't force, let it finish
}

Function Disconnect-Azure {
    #Logout from Azure and clear token
    param(
        [Parameter(
            Mandatory=$false,
            HelpMessage="Client app client Id, ex. `"d1ddf0e4-d672-4dae-b554-9d5bdfd93547`" for Microsoft Intune Powershell .")]
            [string]$ClientId,
        [Parameter(
            Mandatory=$false,
            HelpMessage="Force logout of session and clear token.")]
            [switch]$Force
    )
    $Logout = {
        Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=$RedirectUri&clientId=$($ClientId)" | Out-Null
        $syncHash.token = $null
        Disable-UI
        Write-Host "User logged out."
    }
    if ($Force) {
        #Ignore any active queries
        & $Logout
    } else {
        #Insert check for active Autopilot search
        #Code here
        #Check if token is still required
        $runspace = Get-Runspace | Where-Object {$_.Custom -in "ImportAPDevices" -and $_.RunspaceAvailability -ne "Available"}
        if (-not [string]::IsNullOrEmpty($runspace)) {
            $confirmLogout = [System.Windows.Forms.MessageBox]::Show("Jobs are still active.`nLogging out might make queries incomplete.`nAre you sure you want to log out?","Active jobs","YesNoCancel","Warning","Button2")
            if ($confirmLogout -eq "Yes") {
                & $Logout
            } else {
                Write-Host "Logout cancelled by user."
                return $false
            }
        } else {
            & $Logout
        }
    }
    
    return $true
}

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

Function Update-Token {
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
            Write-Host "Token still valid. No need to refresh token."
        } else {
            Write-Host "Token about to expire. Refresh token."
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
    $syncHash.var_btnLogout.IsEnabled = $false
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
            [System.Windows.Forms.MessageBox]::Show("Failed to update device(s).`nMake sure you have one of the following roles:`n- Intune Administrator`n- Global Admin`n`nEnterprise application:`n- `"Microsoft Graph Command Line Tools`" must be admin consented.`n- You must be granted permission to login to the Enterprise app.","Insufficient permissions","OK","Error") | Out-Null
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
            #Auto-enable cache query
            $syncHash.var_chkboxCache.IsChecked = $true
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
                do {
                    $response = Invoke-RestMethod -Headers $syncHash.headers -Uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                    $responseResponses = $response.responses | Sort-Object {[int]$_.Id}
                    #Check for throttle
                    $isThrottled = $false
                    foreach ($resp in $responseResponses) {
                        if ($resp.body.error.message -eq "Too Many Requests") {
                            Write-Host "Throttled! Sleeping for 10 seconds."
                            Start-Sleep -Seconds 10
                            $isThrottled = $true
                            break
                        }
                    }
                } while ($isThrottled) # Retry if throttled
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
                do {
                    $response = Invoke-RestMethod -Headers $syncHash.headers -Uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                    $responseResponses = $response.responses | Sort-Object {[int]$_.Id}
                    #Check for throttle
                    $isThrottled = $false
                    foreach ($resp in $responseResponses) {
                        if ($resp.body.error.message -eq "Too Many Requests") {
                            Write-Host "Throttled! Sleeping for 10 seconds."
                            Start-Sleep -Seconds 10
                            $isThrottled = $true
                            break
                        }
                    }
                } while ($isThrottled) # Retry if throttled
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

Function Test-DeleteLimit {
    #If limit is not checked:
    if ($syncHash.var_chkboxLimitDelete.IsChecked -eq $false) {
        Switch ($syncHash.var_datagridResults.SelectedItems.Count) {
            "0" {[System.Windows.Forms.MessageBox]::Show("Make a selection to delete a device.`n","Make a selection","OK","Information") | Out-Null; $continue = $false}
            {$_ -ge "2"} {[System.Windows.Forms.MessageBox]::Show("Deletion is limited to one device at a time.","Too many selections","OK","Information") | Out-Null; $continue = $false}
            "1" {$continue = $true}
            default {Write-Host "Not sure what happened, will exit."; $continue = $false}
        }
    } else {
        Write-Host "Set to override delete limit of 1."
        $continue = $true
    }
    return $continue
}

Function Test-UpdateLimit {
    #If limit is not checked:
    if ($syncHash.var_chkboxLimitUpdate.IsChecked -eq $false) {
        Switch ($syncHash.var_datagridResults.SelectedItems.Count) {
            "0" {[System.Windows.Forms.MessageBox]::Show("Make a selection to delete a device.`n","Make a selection","OK","Information") | Out-Null; $continue = $false}
            {$_ -ge "2"} {[System.Windows.Forms.MessageBox]::Show("Deletion is limited to one device at a time.","Too many selections","OK","Information") | Out-Null; $continue = $false}
            "1" {$continue = $true}
            default {Write-Host "Not sure what happened, will exit."; $continue = $false}
        }
    } else {
        Write-Host "Set to override delete limit of 1."
        $continue = $true
    }
    return $continue
}

Function Remove-IntuneDevice {
    param(
        [array]$IntuneDevices, #Only pass Intune devices to this function
        [switch]$Autopilot #Notify that we will delete Autopilot devices aswell (progress bar will be 50%)
    )
    
    #Check token status
    if ((Confirm-TokenValidity -TokenAcquired $syncHash.tokenAcquired -TokenLifetime $syncHash.token.expires_in) -ne $true) {
        Write-Host "Invalid or expired token."
        Disable-UI
        [System.Windows.Forms.MessageBox]::Show("Expired or invalid authentication.`nPlease reauthenticate by using `"Login Azure`".","Invalid/expired token","OK","Information") | Out-Null
        return
    }

    #Reset progress bar
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 0

    #Delete Intune device, batches
    $objectsFinalBatch = ($IntuneDevices | Measure-Object).Count % 20
    $objectTracker = 0
    $objectPointer = 0
    $batchCounter = 1
    $i = $null
    $batches = $null
    $syncHash.allIntuneBatches = $null
    $countFullBatches = [math]::Ceiling(($IntuneDevices | Measure-Object).Count / 20)
    [array]$statusIntuneDeletion = $null

    do {
        $batches = '
            {
                "requests": [
        '
        #Determine how many objects to put in batch, limit is always 20, but we might have less objects remaining
        if ((($IntuneDevices | Measure-Object).Count - ($objectTracker + 1) -lt 20)) {
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
                        `"id`": `"$($IntuneDevices[$objectTracker].id)`",
                        `"method`": `"DELETE`",
                        `"url`": `"deviceManagement/managedDevices/$($IntuneDevices[$objectTracker].intuneId)`"
                    },`n
                ")
            } else {
                $batch = @("
                    {
                        `"id`": `"$($IntuneDevices[$objectTracker].id)`",
                        `"method`": `"DELETE`",
                        `"url`": `"deviceManagement/managedDevices/$($IntuneDevices[$objectTracker].intuneId)`"
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
        #Query graph, but pause if throttled
        do {
            $response = Invoke-RestMethod -Headers $syncHash.headers -Uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
            $responseResponses = $response.responses
            #Check for throttle
            $isThrottled = $false
            foreach ($resp in $responseResponses) {
                if ($resp.body.error.message -eq "Too Many Requests") {
                    Write-Host "Throttled! Sleeping for 10 seconds."
                    Start-Sleep -Seconds 10
                    $isThrottled = $true
                    break
                }
            }
        } while ($isThrottled) # Retry if throttled
        foreach ($response in $responseResponses) {
            $statusIntuneDeletion += $response
        }
        Write-Host "Intune delete initiated."
        $objectPointer = $objectTracker - $x
        $syncHash.allIntuneBatches += $batches
        #Progress
        Write-Host "Intune: Processed batch: " $batchCounter " / " $countFullBatches
        if ($Autopilot.IsPresent) {
            [int]$progress = [math]::Truncate((($batchCounter / $countFullBatches) * 100 / 2)) #Max 50% because we have Autopilot devices to delete aswell
        } else {
            [int]$progress = [math]::Truncate(($batchCounter / $countFullBatches) * 100) #Only deleting Intune devices
        }
        Write-Progress -Activity "Deleting Intune devices" -Status "$progress %" -PercentComplete $progress
        Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
        $batchCounter++
    } while($batchCounter -le $countFullBatches)

    #Log if any Intune devices failed to delete
    if ($statusIntuneDeletion.status -ne 204) {
        [array]$errorArray = $null
        Write-Host "Some Intune devices failed to delete. Writing failed devices to logfile."
        foreach ($status in $statusIntuneDeletion | Where-Object {$_.status -ne 200}) {
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
            $filename = "$($titleCut)-IntuneDeletionFailed-$($date).log"
            $errorArray | Out-File "$($syncHash.workDirRoot)\$filename" -Append
            [System.Windows.Forms.MessageBox]::Show("Some devices failed to delete from Intune. Please review log written under:`n`n`"$($syncHash.workDirRoot)`"","Intune device(s) failed to delete","OK","Warning") | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Some devices failed to delete from Intune.","Intune device(s) failed to delete","OK","Warning") | Out-Null
        }
        Write-Host "Deletion completed."
    }
}

Function Remove-AutopilotDevice {
    param(
        [switch]$Intune #Notify that we will delete Intune devices aswell (progress bar will start at 50%)
    )
    #Check token status
    if ((Confirm-TokenValidity -TokenAcquired $syncHash.tokenAcquired -TokenLifetime $syncHash.token.expires_in) -ne $true) {
        Write-Host "Invalid or expired token."
        Disable-UI
        [System.Windows.Forms.MessageBox]::Show("Expired or invalid authentication.`nPlease reauthenticate by using `"Login Azure`".","Invalid/expired token","OK","Information") | Out-Null
        return
    }

    #Set progress bar
    if ($Intune.IsPresent) {
        Update-Progressbar -Object $syncHash.var_progressBar -Percent 50 #Means we just delete some Intune devices
    } else {
        Update-Progressbar -Object $syncHash.var_progressBar -Percent 0
    }

    #Continue deletion
    [array]$devices = $syncHash.var_datagridResults.SelectedItems
    
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
        do {
            $response = Invoke-RestMethod -Headers $syncHash.headers -Uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
            $responseResponses = $response.responses
            #Check for throttle
            $isThrottled = $false
            foreach ($resp in $responseResponses) {
                if ($resp.body.error.message -eq "Too Many Requests") {
                    Write-Host "Throttled! Sleeping for 10 seconds."
                    Start-Sleep -Seconds 10
                    $isThrottled = $true
                    break
                }
            }
        } while ($isThrottled) # Retry if throttled
        Write-Host "Autopilot delete initiated."
        foreach ($response in $responseResponses) {
            $statusAutopilotDeletion += $response
        }
        $objectPointer = $objectTracker - $x
        $syncHash.allAutopilotBatches += $batches

        #Progress
        Write-Host "Autopilot: Processed batch: " $batchCounter " / " $countFullBatches
        if ($Intune.IsPresent) {
            [int]$progress = [math]::Truncate((($batchCounter / $countFullBatches) * 100 / 2))
        } else {
            [int]$progress = [math]::Truncate(($batchCounter / $countFullBatches) * 100)
        }
        Write-Progress -Activity "Processing Autopilot devices" -Status "$progress %" -PercentComplete $progress
        Update-Progressbar -Object $syncHash.var_progressBar -Percent $progress
        $batchCounter++
    } while($batchCounter -le $countFullBatches)
    
    #Set progress to 100%
    Update-Progressbar -Object $syncHash.var_progressBar -Percent 100
    Write-Progress -Activity "Deleting Autopilot devices" -Status "100 %" -PercentComplete 100
    Write-Progress -Activity "Deleting Autopilot devices" -Status "Ready" -Completed

    #For troubleshooting purposes
    $syncHash.allIntuneBatches
    $syncHash.allAadBatchesGet
    $syncHash.allAadBatchesDel
    $syncHash.allAutopilotBatches

    #In case some devices failed to delete we log the information to workdir folder
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
            $errorArray | Out-File "$($syncHash.workDirRoot)\$filename" -Append
            [System.Windows.Forms.MessageBox]::Show("Some devices failed to delete from Autopilot. Please review log written under:`n`n`"$($syncHash.workDirRoot)`"","Autopilot device(s) failed to delete","OK","Warning") | Out-Null
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
        $csvVerified = $syncHash.csvDevices | Select-Object 'Device Serial Number','Windows Product ID','Hardware Hash','Group Tag','Assigned User'
        #Verifiy Assigned User, only run if any Assigned User is defined
        if ($csvVerified.'Assigned User' -ne $null) {
            try {
                $domainQuery = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/domains" -Headers $syncHash.headers -Method Get -ErrorAction Stop
                $domainIds = $domainQuery.value.id
            } catch {
                Write-Host "Failed to get Entra Id domains."
                [System.Windows.Forms.MessageBox]::Show("Failed to retrieve Entra Id domains for assigned user verification. Aborting...","Query failed","OK","Error") | Out-Null
                return
            }
            $invalidDomainText = ""
            foreach ($user in $csvVerified.'Assigned User') {
                if ([string]::IsNullOrEmpty($user)) { #Allow empty Assigned User
                    break
                }
                if ($user -match '@') { #Make sure it has an email format
                    $userDomain = $user.Split('@')[-1]
                    if ($domainIds -contains $userDomain) {
                    } else {
                        Write-Host "Assigned User $($user) has an invalid domain: $($userDomain). Allowed domains are: $($domainIds)"
                        $invalidDomainText = "One or more assigned users have an invalid domain. Allowed domains are: $($domainIds -join " ")."
                    }
                } else {
                    Write-Host "Assigned User $($user) does not have a valid email format."
                    $invalidDomainText = "One or more assigned users have an invalid domain. Allowed domains are: $($domainIds -join " ")."
                }
            }
        }
    } else {
        Write-Host "Invalid headers in Autopilot hash csv-file."
        [System.Windows.Forms.MessageBox]::Show("Invalid headers in csv-file.`nMake sure this is a valid Autopilot hash file","Invalid Autopilot csv","OK","Warning") | Out-Null
        return
    }
    if ($invalidDomainText -ne "") {
        [System.Windows.Forms.MessageBox]::Show("$($invalidDomainText)","Invalid assigned user","OK","Error") | Out-Null
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
            if ($csvVerified[$objectTracker].'Group Tag') { #Add group tag if defined
                $groupTag = $csvVerified[$objectTracker].'Group Tag'.TrimEnd(" ")
            } else {
                $groupTag = ""
            }
            if ($csvVerified[$objectTracker].'Assigned User') { #Add assigned user if defined
                $assignedUser = $csvVerified[$objectTracker].'Assigned User'.TrimEnd(" ")
            } else {
                $assignedUser = ""
            }

            if ($i -lt $x) {
                $batch += @("
                {
                    `"serialNumber`": `"$($csvVerified[$objectTracker].'Device Serial Number'.TrimEnd(" "))`",
                    `"productKey`": `"$($csvVerified[$objectTracker].'Windows Product Id'.TrimEnd(" "))`",
                    `"hardwareIdentifier`": `"$($csvVerified[$objectTracker].'Hardware Hash'.TrimEnd(" "))`",
                    `"groupTag`": `"$($groupTag)`",
                    `"assignedUserPrincipalName`": `"$($assignedUser)`"
                },")
            } else {
                $batch += @("
                {
                    `"serialNumber`": `"$($csvVerified[$objectTracker].'Device Serial Number'.TrimEnd(" "))`",
                    `"productKey`": `"$($csvVerified[$objectTracker].'Windows Product Id'.TrimEnd(" "))`",
                    `"hardwareIdentifier`": `"$($csvVerified[$objectTracker].'Hardware Hash'.TrimEnd(" "))`",
                    `"groupTag`": `"$($groupTag)`",
                    `"assignedUserPrincipalName`": `"$($assignedUser)`"
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
        $importIds = $responses[0].value.importId
        if ($importIds.Count -gt 1) {
            $importIds = $importIds[0]
        }
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
            [ValidateNotNullorEmpty()][string]$Path = "$($syncHash.workDirRoot)",
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

Function Invoke-MenuItemAction {
    #Support function to update context menu visibility
    Param(
        [Parameter(
            Mandatory=$true,
            HelpMessage="Object passed from the invoke/click.")]
            $Sender,
        [Parameter(
            Mandatory=$true,
            HelpMessage="Datagrid columns existing in the datagrid. Needed to update the context menu accordingly.")]
            [array]$Columns,
        [Parameter(
            Mandatory=$true,
            HelpMessage="The whole context menu object.")]
            [System.Windows.Controls.ContextMenu]$ContextMenu,
        [Parameter(
            Mandatory=$false,
            HelpMessage="The list/array of default menu items.")]
            [array]$DefaultMenuItems
    )
    if (-not $DefaultMenuItems) {
        $defaultItemMenu = @(
            "Serial number",
            "Group Tag",
            "Manufacturer",
            "Model",
            "Enrollment state",
            "Last Contact",
            "Profile assignment state",
            "Intune Device name",
            "Intune User display name",
            "Intune User principal name",
            "Autopilot profile"
        )
    }
    
    Write-Host "Menu item $($sender.Header) invoked."
    switch ($Sender.Header) {
        "Select all" {
            foreach ($column in $Columns) {
                $column.Visibility = [Windows.Visibility]::Visible
                foreach ($menuItem in $ContextMenu.Items | Where-Object {$_.Header -notin "Select all","Select none","Select default"}) {
                    $menuItem.IsChecked = $true
                }
            }
        }
        "Select none" {
            foreach ($column in $Columns) {
                $column.Visibility = [Windows.Visibility]::Hidden
                foreach ($menuItem in $ContextMenu.Items | Where-Object {$_.Header -notin "Select all","Select none","Select default"}) {
                    $menuItem.IsChecked = $false
                }
            }
        }
        "Select default" {
            foreach ($menuItem in $ContextMenu.Items | Where-Object {$_.Header -notin "Select all","Select none","Select default",$defaultItemMenu}) {
                $column.Visibility = [Windows.Visibility]::Hidden
                $menuItem.IsChecked = $false
            }
            foreach ($menuItem in $ContextMenu.Items | Where-Object {$_.Header -in $defaultItemMenu}) {
                $column.Visibility = [Windows.Visibility]::Visible
                $menuItem.IsChecked = $true
            }
            foreach ($column in $Columns) {
                if ($column.Header -in $defaultItemMenu) {
                    $column.Visibility = [Windows.Visibility]::Visible
                } else {
                    $column.Visibility = [Windows.Visibility]::Hidden
                }
            }
        }
        default {
            foreach ($column in $Columns) {
                if ($column.Header -eq $sender.Header) {
                    if ($column.Visibility -eq [Windows.Visibility]::Visible) {
                        $column.Visibility = [Windows.Visibility]::Hidden
                        $sender.IsChecked = $false
                    } else {
                        $column.Visibility = [Windows.Visibility]::Visible
                        $sender.IsChecked = $true
                    }
                }
            }
        }
    }

}

Function Add-MenuItem {
    #Function to add menu items to context menu
    Param(
        [Parameter(
            Mandatory=$true,
            HelpMessage="The whole context menu object.")]
            [System.Windows.Controls.ContextMenu]$ContextMenu,
        [Parameter(
            Mandatory=$true,
            HelpMessage="Header of menu item. Can be an array of strings")]
            [array]$ItemHeaders,
        [Parameter(
            Mandatory=$false,
            HelpMessage="All the columns residing in the datagrid.")]
            [array]$Columns,
        [Parameter(
            Mandatory=$false,
            HelpMessage="Toggle visibility.")]
            [switch]$Visibility
    )

    foreach ($header in $ItemHeaders) {
        $menuItem = New-Object Windows.Controls.MenuItem
        $menuItem.Header = $header
        if ($Visibility) {
            $menuItem.IsChecked = ($columns | Where-Object {$_.Header -eq $header}).Visibility -eq [Windows.Visibility]::Visible
        }
        $menuItem.Add_Click( {
            param($sender)
            Invoke-MenuItemAction -Sender $sender -Columns $columns -ContextMenu $ContextMenu
        })
        [void]$contextMenu.Items.Add($menuItem)
    }
}

Function Show-CustomMessageBox {
    param (
        [string]$Message = "Choose an option:",
        [string]$Title = "Custom MessageBox",
        [array]$Buttons
    )

    #Set default value to Cancel
    $global:Result = "Cancel"

    #Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 450
    $form.Height = 240
    $form.StartPosition = "CenterScreen"

    #Create a larger font based on the system default font
    $fontFamily = New-Object System.Drawing.FontFamily("Microsoft Sans Serif")
    $font = New-Object System.Drawing.Font($fontFamily, 9)

    #Add a label for the message
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Message
    $label.AutoSize = $true
    $label.Top = 20
    $label.Left = 20
    $label.Font = $font
    $form.Controls.Add($label)

    #Set the background color to match a standard MessageBox
    $form.BackColor = [System.Drawing.SystemColors]::Control
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowIcon = $false
    $form.ShowInTaskbar = $false

    #Create a panel for the button area with a lighter color
    $buttonPanel = New-Object System.Windows.Forms.Panel
    $buttonPanel.Dock = "Bottom"
    $buttonPanel.Height = 50
    $buttonPanel.BackColor = [System.Drawing.SystemColors]::ControlLight
    $form.Controls.Add($buttonPanel)

    #Add buttons
    $buttonPosition = $form.Width - 100 * $Buttons.Length - 10  # Start from the right
    foreach ($button in $Buttons) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = $button
        $btn.Left = $buttonPosition
        $btn.Top = 10
        $btn.Width = 80
        $btn.Font = $font

        # Capture the current value of $button using a closure
        $btn.Add_Click({
            param($sender, $eventArgs)
            $global:Result = $sender.Text
            $form.Close()
        })

        $buttonPanel.Controls.Add($btn)
        $buttonPosition += 90
    }

    # Show the form
    $form.ShowDialog() | Out-Null

    # Return the result
    return $global:Result
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
    $syncHash.clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e" #Microsoft Graph Command Line Tools
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
        #"Directory.AccessAsUser.All" #Extra: for deleting Azure AD devices #Removed 27.06.2023 handled by MS backend
    )
    $redirectUri = "http://localhost"
    $syncHash.token = Get-CodeFlowAuthToken -RedirectUri $redirectUri -Scope $scope -ClientId $syncHash.clientId -WebView2RootDll "$($syncHash.workDirDll)"
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
        $powershell.AddScript( { Update-Token } ) #Code to run
        $runspace | Add-Member -MemberType NoteProperty -Name "Custom" -Value "RefreshToken" #Information about runspace
        $asyncObject = $powershell.BeginInvoke() #Start runspace
        
        #Enable UI
        $syncHash.var_btnLogout.IsEnabled = $true
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

$syncHash.var_btnLogout.Add_Click( {
    #Logout from Azure and clear token
    Disconnect-Azure -ClientId $syncHash.clientId
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
    #Count devices visible in datagrid
    $syncHash.var_lblCacheSize.Content -match "(^Cache\ssize:\s\d*\sdevices)" | Out-Null
    Update-Cache -Object $syncHash.var_lblCacheSize -Text "$($Matches[1]) | Grid count: $($syncHash.var_datagridResults.Items.Count) devices" -Enabled

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
            if (($syncHash.var_dataGridResults.SelectedItems.Count - $objectTracker -lt 20)) { # - ($objectTracker + 1)
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
            do {
                $response = Invoke-RestMethod -Headers $syncHash.headers -Uri "https://graph.microsoft.com/beta/`$batch" -Method Post -Body $batches
                $responseResponses = $response.responses
                #Check for throttle
                $isThrottled = $false
                foreach ($resp in $responseResponses) {
                    if ($resp.body.error.message -eq "Too Many Requests") {
                        Write-Host "Throttled! Sleeping for 10 seconds."
                        Start-Sleep -Seconds 10
                        $isThrottled = $true
                        break
                    }
                }
            } while ($isThrottled) # Retry if throttled

            if ($responseResponses.status -eq 403) {
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
    $continue = Test-DeleteLimit
    $global:choice = "Cancel"
    if ($continue -eq $false) {
        return
    }
    #Continue to detect Intune devices if not limited by delete limit
    $intuneDevices = @()
    $syncHash.var_dataGridResults.SelectedItems | ForEach-Object {
        if ($_.intuneId) {
            $intuneDevices += $_
        }
    }

    #Confirmation scriptblocks
    $sbConfirmAll = {
        $confirmChoice = [System.Windows.Forms.MessageBox]::Show("Selected Autopilot and Intune devices will be deleted`n`nWarning: `n- Device cannot be recovered.`n- All Intune settings will remain on device (stuck).`n- Azure AD Joined only devices need local accounts to log on.`n`- BitLocker key will be lost.`n- You must re-upload Autopilot hardware hash of device`n`nContinue?","Confirm delete","YesNo","Warning","Button2")
        if ($confirmChoice -ne "Yes") {
            $global:choice = "Cancel"
            break
        }
    }
    $sbConfirmIntune = {           
        $confirmChoice = [System.Windows.Forms.MessageBox]::Show("Selected Intune devices will be deleted`n`nWarning: `n- Device cannot be recovered.`n- All Intune settings will remain on device (stuck).`n`nContinue?","Confirm delete","YesNo","Warning","Button2")
        if ($confirmChoice -ne "Yes") {
            $global:choice = "Cancel"
            break
        }
    }
    $sbConfirmAutopilot = {
        $confirmChoice = [System.Windows.Forms.MessageBox]::Show("Selected Autopilot devices will be deleted`n`nWarning: `n- After deletion you must re-upload Autopilot hardware hash of device.`n- Group tag for device is removed and device will lose it's dynamic membership.`n- Device will no longer be visible using this tool.`n`nContinue?","Confirm delete","YesNo","Warning","Button2")
        if ($confirmChoice -ne "Yes") {
            $global:choice = "Cancel"
            break
        }
    }

    #Process if one or more selected device is Intune devices
    if ($intuneDevices) {
        $global:choice = Show-CustomMessageBox -Message "One or more of the selected devices are Intune devices.`n`nYou have multiple options:`nAll: delete both Intune and Autopilot devices`nAutopilot: keep Intune devices if it exist, delete only Autopilot devices`nIntune: keep Autopilot devices, but delete Intune devices`n`nChoose device type you want to delete`n" -Title "Intune device(s) found" -Buttons @("Cancel", "All", "Autopilot", "Intune")
        switch ($global:choice) {
            "Cancel" {Write-Host "User cancelled deletion."; return}
            "All" { & $sbConfirmAll }
            "Intune" { & $sbConfirmIntune }
            "Autopilot" { & $sbConfirmAutopilot }
            default {Write-Host "System cancelled deletion."; return}
        }
    } else {
        #No Intune devices in the selection found
        $global:choice = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete the selected Autopilot device(s)?","Confirm delete","YesNo","Warning","Button2")
        if ($global:choice -eq "Yes") {
            $global:choice = "Autopilot"
        } else {
            Write-Host "User cancelled deletion."
            $global:choice = "Cancel"
            return
        }
    }

    #Do the actual deletion, unless instructed to cancel
    switch ($global:choice) {
        "Cancel" {
            Write-Host "User cancelled deletion."
            return
        }
        "All" {
            #Delete both Intune and Autopilot device(s)
            Remove-IntuneDevice -IntuneDevices $intuneDevices -Autopilot
            Remove-AutopilotDevice -Intune
        }
        "Intune" {
            #Delete Intune device(s), keep Autopilot device(s)
            Remove-IntuneDevice -IntuneDevices $intuneDevices
        }
        "Autopilot" {
            #Delete Autopilot device(s), keep Intune device(s)
            Remove-AutopilotDevice
        }
    }
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

#Prepare environment
Start-PrepareEnvironment
#Build context menu for the datagrid
$contextMenu = $syncHash.var_datagridResults.ContextMenu
#Add some menu items to contextmenu for basic control
Add-MenuItem -ContextMenu $contextMenu -ItemHeader "Select all","Select none","Select default"
#Add columns as menu items
$columns = $syncHash.var_datagridResults.Columns
foreach ($column in $columns) {
    Add-MenuItem -ContextMenu $contextMenu -ItemHeader $column.Header -Columns $columns -Visibility
}

#endregion UI

############################
###   LAUNCH GUI  ##########
############################ 

$syncHash.Window.Add_Closing( {
    param($sender,$eventargs)
    try {
        $disconnectAzure = Disconnect-Azure -ClientId $syncHash.clientId
    } catch {
        $disconnectAzure = $false
    } finally {
        if (-not $disconnectAzure) {
            $eventargs.Cancel = $true
        } 
    }
} )

$syncHash.Window.Add_Closed( {
    Write-Host "GUI was closed."
} )

$syncHash.windowIsLoaded = $true
$syncHash.Window.ShowDialog() | Out-Null

#Cleanup after exit
Start-CleanupEnvironment
