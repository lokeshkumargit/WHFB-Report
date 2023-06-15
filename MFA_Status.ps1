<#
    This script is for getting all Member or Guest userType accounts MFA Methods that have at least signed with a registered method and then saving it to a CSV file.

	1.  Uses a REST API call to get the Access Token.
	2.  Connects using the Access Token with the Graph CmdLet.
	3.  Gets all of the Account types specified.
	4.  Gets all of the Auth. Methods for all users that have registered a Auth. Method and signed in.
	5.  Returns the data in Grid-View(remarked out) and saves it to a .CSV file.
	6.  The .CSV file is saved into a folder called "MFA_Status_Logs" where the script resides.
	
	Note:  This process in it's current form takes at least 3 days to process all accounts.

	Requirements:  
		1. Azure AD Application with ClientID and Secret
		2. Latest version of the Microsoft.Graph CmdLet.
			a.  Install-Module -Name Microsoft.Graph -Repository PSGallery -AllowClobber -Force -WarningAction SilentlyContinue
	

    Permissions - These are the following applications permissions required to run this script.
        Application: "UserAuthenticationMethod.Read.All, Directory.Read.All, User.Read.All, Auditlog.Read.All"

    Author :   Keith Oleszkowicz koleszk2@ford.com 
	Contributors:  asures33@ford.com
    Version: 1.1.0 - fixed bug on Auth methods repeating for all users, added search by group ID functionality, added export of extension attributes.
	Date of Release:  02/09/2023
    Version: 1.0.0 - initial version
	Date of Release:  12/14/2022
    #>

#DEV Azure Tenant Information
# Variables that need to be set.
#$tenantId = "60986bc4-74a6-4b4b-af58-6bc104cca355"
#$clientId = "d09c7e79-b563-4451-85f6-8a59696261ec"
# Base64 encoded secret
#$clientSecret = ""

#PROD Azure Tenant Information
# Variables that need to be set.
$tenantId = "c990bb7a-51f4-439b-bd36-9c07fb1041c0"
$clientId = "2ba121b6-884a-4c9a-90cb-91fd20536471"
# Base64 encoded secret
$clientSecret = ""

$authEndpoint = "https://login.microsoftonline.com/"+$tenantId+"/oauth2/token"
$resource = "https://graph.microsoft.com/"

# General Purpose Rest Call Format that can be reused.
Function Make_Rest_Call($httpVerb, $url, $headers, $bodyData)
{
    $retVal = @{};
    try {
        if($url -and $headers -and $httpVerb -and $bodyData)
        {
            $retVal = Invoke-WebRequest -Method $httpVerb -Uri $url -Headers $headers -Body $bodyData
        }
        elseif($httpVerb -ieq "GET")
        {
            $retVal = Invoke-WebRequest -Method $httpVerb -Uri $url -Headers $headers
        }
        else
        {
            Write-Warning "`nNot all parameters populated to make the REST call...ABorting!!!"
            exit
        }
    }
    catch {
        throw "Exception Invoking Rest Call. `n$httpVerb`n$url`n$headers`n$bodyData . Exception: $($_.Exception.Message)" 
        exit
    }

    return $retVal;
}

# Creates the Formatted Data to be used in a Rest API Call with Credentials.
Function Client_Credential($clientId, $clientSecret, $resource, $url)
{
    $accessToken = 
        @{
            "AccessToken" = "";
            "ExpiresIn" = $(Get-Date -Format "MM/dd/yyyy HH:mm:ss");
        };
    try 
    {
        $headers = 
        @{
            "Content-Type" = "application/x-www-form-urlencoded";
        }
        
        $formData = @{
            "grant_type" = "client_credentials";
            "client_id" = $clientId;
            "client_secret" = $clientSecret;
            "resource" = $resource;
        }
        $response = Make_Rest_Call -httpVerb "POST" -url $url -headers $headers -bodyData $formData

        if($response.StatusCode -and $response.StatusCode -eq 200)
        {
            $responseBody = ConvertFrom-Json -InputObject $response.Content
            if($responseBody.access_token -and $responseBody.expires_in)
            {
                $accessToken.AccessToken = $responseBody.access_token;
                $accessToken.ExpiresIn = (Get-Date).AddSeconds($responseBody.expires_in).AddSeconds(-600).ToString("MM/dd/yyyy HH:mm:ss"); #Remove 10 minutes from Expiration
            }
            else {
                throw "Error: Call to Azure Returned an invalid Response. Response: $responseBody"
            }
        }
        else {
            throw "Error: Call to Obtain Access Token returned an invalid Status Code. Response StatusCode: $response.StatusCode"
        }
    }
    catch {
                throw "Exception from Client Credential. Client ID: $clientId -- Resource: $resource -- Url: $url. Exception: $($_.Exception.Message)"
                exit
    }
    return $accessToken
}

# Makes the REST API call to get the Access Token and set the global variables with expirey date.
Function Get_Token
{
    try
    {
        
        $accessToken = $env:ACCESS_TOKEN
        $expiresIn = $env:EXPIRES_IN
        Write-Host "`nChecking Access Token..."
        if(-not $accessToken -or ((Get-Date -Format "MM/dd/yyyy HH:mm:ss") -ge (Get-Date $expiresIn -Format "MM/dd/yyyy HH:mm:ss")))
        #if(-not $accessToken)

        { 
            Write-Host "`r`nAccess Token does not exist or expired, getting new access token`n"
            Start-Sleep -Seconds 1
            $response = Client_Credential -clientId $clientId -clientSecret ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clientSecret))) -resource $resource -url $authEndpoint
            [Environment]::SetEnvironmentVariable("ACCESS_TOKEN", $($response.AccessToken))
            [Environment]::SetEnvironmentVariable("EXPIRES_IN", $($response.ExpiresIn))
            write-host "`r`nNew Access token details: "
            write-host "`nexpires in: " -NoNewline -ForegroundColor Yellow
            write-host $($response.ExpiresIn) 
        }
        else 
        {
            Write-Host "`r`nWe already have an access token"
            #Write-Host "access token:`n"$accessToken 
            write-host "expires in: " -ForegroundColor Yellow -NoNewline
            Write-Host $expiresIn
        }
        return
    }
    catch
    {
        Write-Warning "ABORTING" 
        Write-Error -Message "ERROR: Exception from Check_Access_Token. Exception: " -Exception $_.Exception
        Return
    }
}

 
    # .CSV File Path
    $FilePath = "$($PSScriptRoot)/$("MFA_Status_Logs")"
    # Tests if Folder  exists.
    if (Test-Path "$FilePath")
        {
            $TodayDate = (Get-Date -Format "MMddyyyy_HHmmss")
			$FilePath = $FilePath + "\MFA_Status_" + $TodayDate + ".csv"
        }
    else
        {
            write-host -ForegroundColor yellow "`n`rChecking if Log Folder exists: $FilePath not found - Creating Folder and File Path......"
            New-Item -Path $FilePath -ItemType Directory
			$TodayDate = (Get-Date -Format "MMddyyyy_HHmmss")
			$FilePath = $FilePath + "\MFA_Status_" + $TodayDate + ".csv"
			
        }

Import-Module Microsoft.Graph.Users

Get_Token
Connect-MgGraph -AccessToken $env:ACCESS_TOKEN


Select-MgProfile Beta
$Details = Get-MgContext
$Scopes = $Details | Select -ExpandProperty Scopes
$Scopes = $Scopes -Join ", "
#$ProfileName = (Get-MgProfile).Name
$Organization = Get-MgOrganization
#Clear-Host
Write-Host "`nMicrosoft Graph Connection Information"
Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
Write-Host ("Connected to Tenant {0} ({1}) as account {2}" -f $Details.TenantId, $Organization.DisplayName, $Details.Account)
Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
#Write-Host ("Profile set as {0}. The following permission scope is defined: {1}" -f $ProfileName, $Scopes)
Write-Host "Time now - " $(Get-date -Format "MM/dd/yyyy HH:mm:ss")

# Get user accounts (Set if you want ALL/Members/Guests)
Write-Host "Looking Up Group Members..."
[array]$Users = {}
$Users.Clear()
#added by asures33 - 02/02/2023 ----- code start
#This is the filter section to pull the members of a targetted Group
#COMMENT THIS GROUP TO USE FILTER BY USER.
#####################################################################################################################################
#$userIds = Get-MgGroupMember -GroupId 5a7ff992-f536-4e13-82c2-073f28343b71 |select Id
#$userIds = Get-MgGroupMember -GroupId 14d5ed9d-ff63-43e0-a201-cf47279b971c -All |select Id
#$userIds = Get-MgGroupMember -GroupId 3ede2271-e0ef-42c5-919f-23ec76823178 -All |select Id
#$userIds = Get-MgGroupMember -GroupId c3ef870f-37aa-4a52-a3be-2403a166d026 -All |select Id
$userIds = Get-MgGroupMember -GroupId 14b0bf6e-6ad4-4994-b4ac-64fa7f86e0ab -All |select Id   
<#foreach ($Id in $userIds) 
{ 
    Write-Host "Id: " ($Id.Id)
    $Users += (get-mguser -UserId ($Id.Id));
    #$Users.Add((get-mguser -UserId ($Id.Id)));
}
#>

$count = $userIds.Count;
Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
write-host "The group contains: " $count " users in it.`nNow trying to retrieve users details...."
Write-Host "Time now - " $(Get-date -Format "MM/dd/yyyy HH:mm:ss")
Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
for($q = 0;$q -le $count; $q++)
{
    #Write-Host "Id: " ($userIds[$q].Id)
    if (-not $env:ACCESS_TOKEN -or ((Get-Date -Format "MM/dd/yyyy HH:mm:ss") -ge (Get-Date $env:EXPIRES_IN -Format "MM/dd/yyyy HH:mm:ss")))
    {
        Get_Token
		Connect-MgGraph -AccessToken $env:ACCESS_TOKEN
    }
    $Users += (get-mguser -UserId ($userIds[$q].Id));
}

#####################################################################################################################################
#added by asures33 - 02/02/2023 ----- code ends

#This is the filter section to pull the data for a targeted group of user(s) or types.
#COMMENT THIS GROUP TO USE FILTER BY GROUP.
#####################################################################################################################################
#$Users = Get-MgUser -Filter "userPrincipalName eq 'ASURES33@ford.com'"
#$Users = Get-MgUser -Filter "onPremisesExtensionAttributes/any(s:s/ExtensionAttribute15 eq H)'"
#$Users = Get-MgUser -All -Filter "onPremisesSyncEnabled eq true and UserType eq 'Guest'"
#$Users = Get-MgUser -All -Filter "UserType eq 'Guest'"
#$Users = Get-MgUser -All -Filter "UserType eq 'Member'"
#$Users = (Get-MgUser -All -Top 15 -Filter "UserType eq 'Member'")
#[array]$Users = Get-MgUser -All # Gets all user Types
#####################################################################################################################################

If (!($Users)) { Write-Host "No accounts found for some reason... exiting" ; break}
    Else 
    { 
        Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
        Write-Host ("{0} Azure AD accounts found (not all are user accounts will have authenticated)" -f $Users.count )
        Write-Host "Time now - " $(Get-date -Format "MM/dd/yyyy HH:mm:ss")
        Write-Host "+-------------------------------------------------------------------------------------------------------------------+"
    }
$CheckedUsers = 0
$Report = [System.Collections.Generic.List[Object]]::new()
$RunTimeCount = 0 #This count will be displayed during run time to show how many users are processed.
ForEach ($User in $Users) 
{
	If (-not $env:ACCESS_TOKEN -or ((Get-Date -Format "MM/dd/yyyy HH:mm:ss") -ge (Get-Date $env:EXPIRES_IN -Format "MM/dd/yyyy HH:mm:ss")))
    #    If (-not $env:ACCESS_TOKEN)
	{
		Get_Token
		Connect-MgGraph -AccessToken $env:ACCESS_TOKEN
    
		# Try and find a sign in record for the user - this eliminates unused accounts 
		$UserLastSignIn = (Get-MgUser -UserId $User.Id -Property signinactivity) | Select-Object -ExpandProperty SignInActivity
		$UserLastSign = $UserLastSignIn.LastSignInDateTime
		
		
        #$ExtensionAttributes = (Get-MgUser -UserId $User.Id).OnPremisesExtensionAttributes | Where-Object -Property "ExtensionAttribute15" -eq "H"
		$ExtensionAttributes = (Get-MgUser -UserId $User.Id).OnPremisesExtensionAttributes
		
        $RunTimeCount += 1;
		# This will write to the console if you need to validate some of the data output.
		Write-Host "Checking " $RunTimeCount "- " "UserID: " $User.Id "UserType: " $User.userType " - AccountSynced: " $User.onPremisesSyncEnabled " - UPN: " $User.UserPrincipalName " - OnPremisesDN: " $User.OnPremisesDistinguishedName " - Building Abrev: " $ExtensionAttributes.ExtensionAttribute2 " - Building Name: " $ExtensionAttributes.ExtensionAttribute3 " - Employee Type: " $ExtensionAttributes.ExtensionAttribute15 " - fordDeptCode: " $ExtensionAttributes.ExtensionAttribute8 " - fordHRDeptCode: " $ExtensionAttributes.ExtensionAttribute9 " - fordBusinessUnitCode: " $ExtensionAttributes.ExtensionAttribute7 " - Division: " $ExtensionAttributes.ExtensionAttribute14 " - fordMRRole: " $ExtensionAttributes.ExtensionAttribute10 " - fordSponsorCDSID: " $ExtensionAttributes.ExtensionAttribute12
		
		#This will only process users that have a registered method for their account.
		If ($UserLastSign) 
		{
			$CheckedUsers++
			
			#Write-Host "Sign in found - checking authentication methods for" $User.DisplayName
			[array]$MfaData = Get-MgUserAuthenticationMethod -UserId $User.Id 
			
			#Process each of the authentication methods found for an account
  		    ForEach ($MfaMethod in $MfaData) 
			{   
				Switch ($MfaMethod.AdditionalProperties["@odata.type"]) {
				 "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  { # Microsoft Authenticator App
					   $AuthType     = 'MSAuthenticatorApp'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
				 "#microsoft.graph.phoneAuthenticationMethod"                  { # Phone authentication
					   $AuthType     = 'PhoneAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["phoneType", "phoneNumber"] -join ' '  } 
				 "#microsoft.graph.fido2AuthenticationMethod"                   { # FIDO2 key
					   $AuthType     = 'Fido2'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["model"] }  
				 "#microsoft.graph.passwordAuthenticationMethod"                { # Password
					   $AuthType     = 'PasswordAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
				 "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { # Windows Hello
					   $AuthType     = 'WindowsHelloForBusiness'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                        
				 "#microsoft.graph.emailAuthenticationMethod"                   { # Email Authentication
					   $AuthType     = 'EmailAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["emailAddress"] }               
				 "microsoft.graph.temporaryAccessPassAuthenticationMethod"    { # Temporary Access pass
					   $AuthType     = 'TemporaryAccessPass'
					   $AuthTypeDetails = 'Access pass lifetime (minutes): ' + $MfaMethod.AdditionalProperties["lifetimeInMinutes"] }
				 "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" { # Passwordless
					   $AuthType     = 'Passwordless'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                      
				 "#microsoft.graph.softwareOathAuthenticationMethod" { # Oath2 TOTP Authenticator App
					   $AuthType     = 'AuthenticatorApp'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                      	   
				   } # End switch 
			   # Note what we found
				$ReportLine  = [PSCustomObject][Ordered]@{
					User                 = $User.DisplayName
					UPN                  = $User.UserPrincipalName 
					UserType		     = $User.userType
					EmployeeType         = $ExtensionAttributes.ExtensionAttribute15
					BldgAbbrev		     = $ExtensionAttributes.ExtensionAttribute2
					BldgName		     = $ExtensionAttributes.ExtensionAttribute3
                    #added by asures33 - 02/02/2023 ----- code starts
                    fordDeptCode         = $ExtensionAttributes.ExtensionAttribute8
                    fordHrDeptCode       = $ExtensionAttributes.ExtensionAttribute9
                    fordBusinessUnitCode = $ExtensionAttributes.ExtensionAttribute7
                    fordMRRole           = $ExtensionAttributes.ExtensionAttribute10
                    fordSponsorCDSID     = $ExtensionAttributes.ExtensionAttribute12
                    division             = $ExtensionAttributes.ExtensionAttribute14
                    #added by asures33 - 02/02/2023 ----- code ends
					UserOnPremDN	     = $User.OnPremisesDistinguishedName
					UserSynced		     = $User.onPremisesSyncEnabled
					Method               = $AuthType
					Details              = $AuthTypeDetails
					#LastSignIn          = $LastSignIn.CreatedDateTime
					LastSignIn           = $UserLastSign}
					#LastSignInApp       = $LastSignIn.AppDisplayName}
				$Report.Add($ReportLine) 
			} #End Foreach MfaMethod
	  } # End if
	}
	else
    {
		
		# Try and find a sign in record for the user - this eliminates unused accounts 
		$UserLastSignIn = (Get-MgUser -UserId $User.Id -Property signinactivity) | Select-Object -ExpandProperty SignInActivity
		$UserLastSign = $UserLastSignIn.LastSignInDateTime
		
		$ExtensionAttributes = (Get-MgUser -UserId $User.Id).OnPremisesExtensionAttributes
        #$ExtensionAttributes = (Get-MgUser -UserId $User.Id).OnPremisesExtensionAttributes | Where-Object -Property "ExtensionAttribute15" -eq "H"
		#asures33 - 02/02/2023 ----- code change starts
		# This will write to the console if you need to validate some of the data output.
        Write-Host "Checking - " "UserID: " $User.Id "UserType: " $User.userType " - AccountSynced: " $User.onPremisesSyncEnabled " - UPN: " $User.UserPrincipalName " - OnPremisesDN: " $User.OnPremisesDistinguishedName " - Building Abrev: " $ExtensionAttributes.ExtensionAttribute2 " - Building Name: " $ExtensionAttributes.ExtensionAttribute3 " - Employee Type: " $ExtensionAttributes.ExtensionAttribute15 " - fordDeptCode: " $ExtensionAttributes.ExtensionAttribute8 " - fordHRDeptCode: " $ExtensionAttributes.ExtensionAttribute9 " - fordBusinessUnitCode: " $ExtensionAttributes.ExtensionAttribute7 " - Division: " $ExtensionAttributes.ExtensionAttribute14 " - fordMRRole: " $ExtensionAttributes.ExtensionAttribute10 " - fordSponsorCDSID: " $ExtensionAttributes.ExtensionAttribute12
		#asures33 - 02/02/2023 ----- code change ends	
		#This will only process users that have a registered method for their account.	
		If ($UserLastSign) 
		{
			$CheckedUsers++
			#Write-Host "Sign in found - checking authentication methods for" $User.DisplayName
			[array]$MfaData = Get-MgUserAuthenticationMethod -UserId $User.Id 
			#Process each of the authentication methods found for an account
			  ForEach ($MfaMethod in $MfaData) 
			  {   
				Switch ($MfaMethod.AdditionalProperties["@odata.type"]) {
				 "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  { # Microsoft Authenticator App
					   $AuthType     = 'MSAuthenticatorApp'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
				 "#microsoft.graph.phoneAuthenticationMethod"                  { # Phone authentication
					   $AuthType     = 'PhoneAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["phoneType", "phoneNumber"] -join ' '  } 
				 "#microsoft.graph.fido2AuthenticationMethod"                   { # FIDO2 key
					   $AuthType     = 'Fido2'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["model"] }  
				 "#microsoft.graph.passwordAuthenticationMethod"                { # Password
					   $AuthType     = 'PasswordAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] } 
				 "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { # Windows Hello
					   $AuthType     = 'WindowsHelloForBusiness'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                        
				 "#microsoft.graph.emailAuthenticationMethod"                   { # Email Authentication
					   $AuthType     = 'EmailAuthentication'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["emailAddress"] }               
				 "microsoft.graph.temporaryAccessPassAuthenticationMethod"    { # Temporary Access pass
					   $AuthType     = 'TemporaryAccessPass'
					   $AuthTypeDetails = 'Access pass lifetime (minutes): ' + $MfaMethod.AdditionalProperties["lifetimeInMinutes"] }
				 "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" { # Passwordless
					   $AuthType     = 'Passwordless'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                      
				 "#microsoft.graph.softwareOathAuthenticationMethod" { # Oath2 TOTP Authenticator App
					   $AuthType     = 'AuthenticatorApp'
					   $AuthTypeDetails = $MfaMethod.AdditionalProperties["displayName"] }                      	   
				   } # End switch 
				# Note what we found
				$ReportLine  = [PSCustomObject][Ordered]@{
					User                 = $User.DisplayName
					UPN                  = $User.UserPrincipalName 
					UserType		     = $User.userType
					EmployeeType         = $ExtensionAttributes.ExtensionAttribute15
					BldgAbbrev		     = $ExtensionAttributes.ExtensionAttribute2
					BldgName		     = $ExtensionAttributes.ExtensionAttribute3
                    #added by asures33 - 02/02/2023 ----- code starts
                    fordDeptCode         = $ExtensionAttributes.ExtensionAttribute8
                    fordHrDeptCode       = $ExtensionAttributes.ExtensionAttribute9
                    fordBusinessUnitCode = $ExtensionAttributes.ExtensionAttribute7
                    fordMRRole           = $ExtensionAttributes.ExtensionAttribute10
                    fordSponsorCDSID     = $ExtensionAttributes.ExtensionAttribute12
                    division             = $ExtensionAttributes.ExtensionAttribute14
                    #added by asures33 - 02/02/2023 ----- code ends
					UserOnPremDN	     = $User.OnPremisesDistinguishedName
					UserSynced		     = $User.onPremisesSyncEnabled
					Method               = $AuthType
					Details              = $AuthTypeDetails
					#LastSignIn          = $LastSignIn.CreatedDateTime
					LastSignIn           = $UserLastSign}
					#LastSignInApp       = $LastSignIn.AppDisplayName}
				$Report.Add($ReportLine) 
			} #End Foreach MfaMethod
	  } # End if
    }
} # End ForEach Users

#initializing the MFAStatus variables to empty before usage to avoid data descrepency

# Take the report file and check each user to see if they use a strong authentication method 
$OutputFile = [System.Collections.Generic.List[Object]]::new()
#added fordDeptCode, fordHrDeptCode, fordBusinessUnitCode in the next line by asures33 - 02/02/2023
[array]$AuthUsers = $Report | Sort-Object UPN -Unique | Select-Object UPN, User, UserType, EmployeeType, BldgAbbrev, BldgName,fordDeptCode, fordHrDeptCode, fordBusinessUnitCode,fordMRRole,fordSponsorCDSID, division, UserOnPremDN, UserSynced, LastSignIn
ForEach ($AuthUser in $AuthUsers) {
    $MFAStatus = $Null
    $Records = $Report | ? {$_.UPN -eq $AuthUser.UPN}
    $Methods = $Records.Method | Sort -Unique
    Switch ($Methods) {
      "PasswordAuthentication"  { $MFAStatus = "YES" }
	  "Fido2"               { $MFAStatus1 = "YES" }
      "PhoneAuthentication" { $MFAStatus2 = "YES" }
      "MSAuthenticatorApp"    { $MFAStatus3 = "YES" }
      "Passwordless"        { $MFAStatus4 = "YES" }
      "EmailAuthentication" { $MFAStatus5 = "YES" }
	  "WindowsHelloForBusiness"  { $MFAStatus6 = "YES" }
	  "TemporaryAccessPass"    { $MFAStatus7 = "YES" }
	  "AuthenticatorApp"    { $MFAStatus8 = "YES" }
	  #Default              { $MFAStatus = "Check!" } - This currently does not work per MS article.
    } # End Switch
    $ReportLine  = [PSCustomObject][Ordered]@{
         User                 = $AuthUser.User
         UPN                  = $AuthUser.UPN
         UserType	       	  = $AuthUser.UserType
		 EmployeeType         = $AuthUser.EmployeeType
		 BldgAbbrev		      = $AuthUser.BldgAbbrev
		 BldgName		      = $AuthUser.BldgName
         fordDeptCode         = $AuthUser.fordDeptCode
         fordHrDeptCode       = $AuthUser.fordHRDeptCode
         fordBusinessUnitCode = $AuthUser.fordBusinessUnitCode
         fordMRRole           = $AuthUser.fordMRRole
         fordSponsorCDSID     = $AuthUser.fordSponsorCDSID
         division             = $AuthUser.division
		 UserOnPremDN	      = $AuthUser.UserOnPremDN
		 UserSyned		      = $AuthUser.UserSynced
         Methods              = $Methods -Join ", "
         PwdAuth              = $MFAStatus
         Fido2			      = $MFAStatus1
		 PhoneAuth		      = $MFAStatus2
		 MSAuthApp		      = $MFAStatus3
		 PwdLess		      = $MFAStatus4
		 EmailAuth		      = $MFAStatus5
		 WHFB			      = $MFAStatus6
		 TempAccPass	      = $MFAStatus7
		 AuthApp		      = $MFAStatus8
		 LastSignIn           = $AuthUser.LastSignIn}
         #LastSignInApp       = $AuthUser.LastSignInApp }
    $OutputFile.Add($ReportLine) 
    $MFAStatus = ""
    $MFAStatus1 = ""
    $MFAStatus2 = ""
    $MFAStatus3 = ""
    $MFAStatus4 = ""
    $MFAStatus5 = ""
    $MFAStatus6 = ""
    $MFAStatus7 = ""
    $MFAStatus8 = ""
    $Methods = ""
} 
   
$OutputFile | Out-GridView
$OutputFile | Export-CSV -NoTypeInformation -Path $FilePath
Write-Host "Script End time - " (Get-Date -Format "MM/dd/yyyy HH:mm:ss")