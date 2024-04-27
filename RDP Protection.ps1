##################################
### To do
### lookback vs allowafter what's the point again of these being different?
### -mode reset to reset blocks
##################################

##################################
### Parameters
##################################
Param 
	(
	[switch] $quiet= $false        ## Proceed without user input (for automation)
    , $mode = "Normal"             ## -mode Normal (or omit) to install/run, -mode Uninstall to uninstall, -mode reset to -reset the block and allow lists
    ,[switch] $verbose = $false    ## to popup grids
    ,[switch] $nosched = $false    ## don't schedule
    ,[switch] $nofirewall = $false ## don't add any firewall rules (just report)
    , $settingname  = ""           ## update RDP Protection Settings.csv, this Name
    , $settingvalue = ""           ## update RDP Protection Settings.csv, this Value
	)

##################################
### Functions
##################################
Function SaveStatsToCSV
{
<#
#>
    Param (
        [string] $LogType="Username"  #IPAddress
        ,[System.Array] $LogItems 
        ,[string] $Logfolder= "C\Logs"
        ,[int] $LookBackMins = 1440
        ,[string] $CSVDatePattern = "M/dd/yyyy h:mm:ss tt"
    )
    ## is there anything to do?
    if (-not ($LogItems)) {Return}
    if ($LogItems.Count -eq 0) {Return}
    #
    $HitDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Logfilename = "$($Logfolder)\Logged_$($LogType)-Hits.csv"
    if (Test-Path "$($Logfilename)" -PathType Leaf)
    {
        $FileItems = @(Import-Csv "$($Logfilename)")
    }
    Else
    {   
        $FileItems=@()
    }
    ### Inspect each new LogItem
    $Updated = $false
    ForEach ($LogItem in $LogItems)
    {
        $FileItem = $FileItems | Where-Object -Property $LogType -eq $LogItem.$LogType
        if ($FileItem)
        { #update existing items
            ####### Update checks
            $Update = $False #assume not
            # figure out what the heck the date is from the string
            # en-US is 3/23/2021 2:34:33 PM
            # which is M/dd/yyyy h:mm:ss tt 
            Try
                {$FileLastHit=$FileLastHit=[datetime]::ParseExact($FileItem.LastHitTime, $CSVDatePattern, $null)}
            Catch
                {$FileLastHit=$null}

            if (-not($Update))
            {
                if (-not($FileLastHit))
                {$Update = $true} #No valid date in file, update
            }
            if (-not($Update))
            {
                #if (($LogItem.HitTime - $FileLastHit).TotalMinutes -gt $LookBackMins)
                #{$Update = $true} #Data is old, update
                $Update = $true # always update
            }
            #######
            if ($Update)
            {
                $FileItem.LastHitTime = $Logitem.LastHitTime  #Update the hitdate
                Try
                {
                    $filehits = 0
                    $filehits = [int] $FileItem.Hits
                }
                Catch 
                {
                    Write-Host  "[Warning] $($Logfilename): $($FileItem.IPAddress) Hits value isn't an integer: $($FileItem.Hits) (assuming 0)"
                }
                $FileItem.Hits = $filehits + [int] $LogItem.Hits #add this to the hitcount
                $Updated = $true
            }
        }
        else
        { #append missing items
            if ($LogType -eq "Username")
            {
                $Fileitems+=$LogItem | Select-Object Username,Hits,LastHitTime,LastIPAddress
            }
            elseif ($LogType -eq "IPAddress")
            {
                $Fileitems+=$LogItem | Select-Object IPAddress,Hits,LastHitTime,LastUsername
            }
            $Updated = $true
        }
    }
    ## Write the file back
    if ($Updated)
    {
        # Try to create folder if it doesn't exist
        if (-not (Test-Path -Path $LogFolder -PathType Container))
        {
            New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
            if (-Not(Test-Path -Path $LogFolder -PathType Container))
            {
                Throw "Could not create vault folder '$($LogFolder)'"
            }
        }
        $Fileitems | Export-CSV $Logfilename -NoTypeInformation
    }
}

######################
## Main Procedure
######################
###
## To enable scrips, Run powershell 'as admin' then type
## Set-ExecutionPolicy Unrestricted
###
### Main function header - Put ITAutomator.psm1 in same folder as script
$scriptFullname = $PSCommandPath ; if (!($scriptFullname)) {$scriptFullname =$MyInvocation.InvocationName }
$scriptXML      = $scriptFullname.Substring(0, $scriptFullname.LastIndexOf('.'))+ ".xml"  ### replace .ps1 with .xml
$scriptDir      = Split-Path -Path $scriptFullname -Parent
$scriptName     = Split-Path -Path $scriptFullname -Leaf
$scriptBase     = $scriptName.Substring(0, $scriptName.LastIndexOf('.'))
$scriptVer      = "v"+(Get-Item $scriptFullname).LastWriteTime.ToString("yyyy-MM-dd")
if ((Test-Path("$scriptDir\ITAutomator.psm1"))) {Import-Module "$scriptDir\ITAutomator.psm1" -Force} else {write-host "Err: Couldn't find ITAutomator.psm1";return}
# Get-Command -module ITAutomator  ##Shows a list of available functions
######################
$ErrCode = 0
$ErrMsg ="OK:No unblocked threats"
###

##
If (-not(IsAdmin))
{
    ErrorMsg -Fatal -ErrCode 101 -ErrMsg "This script requires Administrator priviledges, re-run with elevation (right-click and Run as Admin)"
}


### Create initial folder
$FolderRDPProtect = "C:\RDP Protection"
if (-not (Test-Path $FolderRDPProtect -PathType Container))
{
    New-Item -ItemType Directory -Force -Path $FolderRDPProtect | Out-Null
    $ErrCode,$ErrMsg=ErrorMsg ErrorMsg -ErrCode 207 -ErrMsg "Creating new folder: $($FolderRDPProtect)"
}
###

<# 
### Update script file
$ps1Target = "$($FolderRDPProtect)\$($scriptName)"
if ($ps1Target -ne $scriptFullname)
{ ## not same file as this
    $retcode, $retmsg= CopyFileIfNeeded $scriptFullname $FolderRDPProtect
    if ($retcode -ne 0)
    {
        $retmsg | Write-Host
    }
} ## not same file as this

### Update ITAutomator.psm1
$retcode, $retmsg= CopyFileIfNeeded "$($scriptDir)\ITAutomator.psm1" $FolderRDPProtect
if ($retcode -ne 0)
{
    $retmsg | Write-Host
}
###
#>

### Update RDP Protection.cmd
if ($scriptDir -ne $FolderRDPProtect)
{
    $retcode, $retmsg= CopyFilesIfNeeded $scriptDir $FolderRDPProtect
    if ($retcode -ne 0)
    {
        $retmsg | Write-Host
    }
}
###

## Locked file?
$LockMsg  = ""
$Locked   = $false
$LockFile = "$($FolderRDPProtect)\IsRunning.txt"
If (Test-Path $LockFile)
{
    $LockDate = (get-item $LockFile).LastWriteTime
    $LockAgeMins = ((Get-Date) - $LockDate).TotalMinutes
    #
    If ($LockAgeMins -gt 5)
    {
        # older
        $LockMsg = "Old lock file found ($($LockAgeMins.tostring("0.#")) min) deleted. More than 5 min."
        $Locked = $false
        Remove-Item $LockFile
    }
    Else
    {
        # newer
        $LockMsg = "Lock file found ($($LockAgeMins.tostring("0.#")) min old). Under 5 min."
        $Locked = $true
    }
}
If (-not $Locked)
{ # Create lock (semaphore) file
    Set-Content $LockFile "Locked for up to 5 mins by Computer:$env:computername User:$env:username starting $(Get-Date)"
}

###
$TranscriptTarget = LogsWithMaxSize -Logfolder "$($FolderRDPProtect)\Logs" -MaxMB 50 -Prefix "Transcript" -Ext "txt"
if ($mode -ne "Uninstall")
{
    Start-Transcript -path $TranscriptTarget | Out-Null
}
###
Write-Host "-----------------------------------------------------------------------------"
Write-Host "$($scriptName) $($scriptVer)       Computer:$($env:computername) User:$($env:username) PSver:$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
Write-Host ""
Write-Host "  - Checks Event log for failed access attempts and blocks those IPs using Windows firewall"
Write-Host "  - Succesful attempts can be added to the allow list automatically"
Write-Host "  - blocks and allows are maintened in a CSV file"
Write-Host ""
Write-Host "[Options]"
Write-Host " -Mode $($mode)"
if ($quiet)      {Write-Host " -quiet"}
if ($verbose)    {Write-Host " -verbose (popup grids)"}
if ($nofirewall) {Write-Host " -nofirewall (don't add any firewall rules (just report))"}
if ($nosched)    {Write-Host " -nosched (don't schedule)"}
if ($settingname -ne "")  {Write-Host " -settingname $($settingname)"}
if ($settingvalue -ne "") {Write-Host " -settingvalue $($settingvalue)"}
Write-Host "$($LockMsg)"
#############
Write-Host "-----------------------------------------------------------------------------"

If ($Locked)
{
    Write-Host "$(Split-Path -Path $LockFile -Leaf) $($LockMsg) Exiting."
    Start-Sleep 5
    Exit
}

if ($mode -eq "Uninstall")
{
    Write-Host "Uninstall (-Mode Uninstall)"
    Start-Sleep 5

    ## Delete firewall rule
    $fwallrules = Get-NetFirewallRule -DisplayName "RDP Protect*"
    ForEach ($fwallrule in $fwallrules)
    {
        Write-Host "Removing rule: $($fwallrule.DisplayName)"
        $fwallrule | Remove-NetFirewallRule
    }

    ## Delete folder
    $FolderRDPProtect = "C:\RDP Protection"
    if (Test-Path $FolderRDPProtect -PathType Container)
    {
        Try
        {
            Remove-Item -LiteralPath $FolderRDPProtect -Force -Recurse
        }
        Catch
        {
            $ErrCode,$ErrMsg=ErrorMsg -ErrCode 109 -ErrMsg "Uninstall couldn't delete $($FolderRDPProtect).  Is it open?"
        }
    }

    ## Exit
    $ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 105 -ErrMsg "Program has been uninstalled"
}

Write-Host "[Status]"
$dummyip = "1.2.3.4"
## get the netork cards and their network categories
$nics = @(Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,IPv4Connectivity,NetworkCategory)
$fwall_active = $True #assume OK
foreach ($nic in $nics)
{
    $niccat =$nic.NetworkCategory
    if ($niccat -eq "DomainAuthenticated") {$niccat = "Domain"} #For some reason the Domain profile on the card is labeled 'DomainAuthenticated'
    $fwall_prof = Get-NetFirewallProfile | Where-Object Name -eq $niccat | Select-Object Name,Enabled
    if ($fwall_prof.Enabled)
    {
        $fwall_status = "OK: Enabled"
    }
    else
    {
        $fwall_status = "ERR: Disabled"
        $fwall_active = $false
    }
    Write-Host "$($fwall_status) Network adapter '$($nic.InterfaceAlias) $($nic.Name) ($($nic.IPv4Connectivity)) NetworkCategory $($nic.NetworkCategory)'"
}
if (-not($fwall_active))
{
    $ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 108 -ErrMsg "ERR: Some network cards have no firewall enabled" -SemFileToDelete $LockFile
}
else
{
    Write-Host "OK: Firewall is active"
}

### RDP Port test
$rdpport = "3389"
$regkey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$regpropname = "PortNumber"
$regtest="No RDP Port found in $($regkey)\$($regpropname)"
if((Test-Path -Path $regkey -PathType Container) )
{
    $regprop= Get-ItemProperty -Path $regkey -Name $regpropname
    if( $regprop )
    {
        $rdpport=$regprop.$regpropname
        $regtest="OK: RDP port is $($rdpport)"
    }
}
If ($regtest.StartsWith("OK"))
{
    Write-Host $regtest
}
Else
{
    $ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 102 -ErrMsg $regtest -SemFileToDelete $LockFile
}

### RDP Service test
If (Get-Service "TermService" | where-object {$_.Status -eq 'Running'})
{
    Write-Host "OK: RDP service is running"
}
Else
{
    $ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 104 -ErrMsg "No RDP service is running (termservice)" -SemFileToDelete $LockFile
}

if ($false)
{
	### RDP Reg test
	#Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
	$rdp_reg=RegGet "HKLM" "System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
	If ($rdp_reg -eq "0")
	{
		Write-Host "OK: RDP switched on"
	}
	else
	{
		$ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 105 -ErrMsg "RDP switched off (registry)" -SemFileToDelete $LockFile
	}
}

### DUO test
$regkey = "HKLM:\SOFTWARE\Duo Security\DuoCredProv"
$regpropname = "RDPOnly"
$regpropvalue = "1"
$mfatest="No MFA is enabled (DUO)"
if((Test-Path -Path $regkey -PathType Container) )
{
    $regprop= Get-ItemProperty -Path $regkey -Name $regpropname
    if( $regprop )
    {
        if ($regprop.$regpropname -eq $regpropvalue)
        {
            $mfatest="OK: DUO is enabled"
        }
    }
}
if ($mfatest.StartsWith("OK"))
{
    Write-Host $mfatest
}
else
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 201 -ErrMsg $mfatest
}
Write-Host "-------------------------------------------"
Write-Host "[Local admin accounts]"
<#
### Local Admins Test
#$locadmins = Get-LocalGroupMember -Group "Administrators" ## doesn't work if invalid SIDs
$locadmins =@(); $locadmins += ForEach ($group in Get-LocalGroup "Administrators") {
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$group"
    $group_members = @($group.Invoke('Members') | % {([adsi]$_).path})
    $group_members
    }
Write-Host "Local Admininstrators Group: $($locadmins.Count) members (groups or users)"
#>
## Vulnerable account names
$vuln_accounts=@()
$vuln_accounts+="Administrator"
$vuln_accounts+="Admin"
$vuln_accounts+="Admin1"
$vuln_accounts+="User"
$vuln_accounts+="User1"
$vuln_accounts+="Scanner"
## Show Local admins
$administratorsAccount = Get-WmiObject Win32_Group -filter "LocalAccount=True AND SID='S-1-5-32-544'" 
$administratorQuery = "GroupComponent = `"Win32_Group.Domain='" + $administratorsAccount.Domain + "',NAME='" + $administratorsAccount.Name + "'`"" 
$locadmins_wmi = Get-WmiObject Win32_GroupUser -filter $administratorQuery | Select-Object PartComponent
$locadmins = @()
$count = 0
$account_warnings = 0
$msg_accounts =""
foreach ($locadmin_wmi in $locadmins_wmi)
{
    $user1 = $locadmin_wmi.PartComponent.Split(".")[1]
    $user1 = $user1.Replace('"',"")
    $user1 = $user1.Replace('Domain=',"")
    $user1 = $user1.Replace(',Name=',"\")
    $Status = ""
    $accountname = $user1.Split("\")[1]
    $locadmin_info = Get-LocalUser $accountname -ErrorAction SilentlyContinue
    if ($locadmin_info)
    {
        if (-not ($locadmin_info.Enabled))
        {
            $Status = " [Disabled]"
        }
    }
    if ($Status -eq "")
    {
        if ($vuln_accounts -contains $accountname)
        {
            $Status = " [Vulnerable account name]"
            $account_warnings += 1
            $msg_accounts+=",$($accountname)"
        }
    }
    $count +=1
    $locadmins+="$($user1)$($Status)"
    Write-Host "  Admin $($count): $($user1)$($Status)"
}
if ($account_warnings -eq 0)
{
    Write-Host "OK: No vulnerable local admin accounts"
}
else
{
    $msg_accounts=$msg_accounts.Trim(",")
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 202 -ErrMsg "Vulnerable local admin accounts: $($msg_accounts)"
}
### Read Settings
$SettingsCSV = "RDP Protection Settings.csv"
if (Test-Path "$($FolderRDPProtect)\$($SettingsCSV)" -PathType Leaf)
{
    $Settings = @(Import-Csv "$($FolderRDPProtect)\$($SettingsCSV)")
}
Else
{   ### Create csv file
    $Settings=@()
    $Settings += [pscustomobject]@{
        "Name"    = "block_afterntries"
        "Value"   = 5
        "Comment" = "0=Block immediately. Block IP after N invalid attempts.3=Allow 3 tries in case user is struggling"}
    $Settings += [pscustomobject]@{
        "Name"    = "lookbacknmins"
        "Value"   = 1440
        "Comment" = "1440,1440=1 day. Lookback N minutes for block information (Checks event log plus block history in case event log is cleared or rolls over"}
    $Settings += [pscustomobject]@{
        "Name"    = "allowafternmins"
        "Value"   = 1440
        "Comment" = "1440,1440=1 day. Unblocks Ips after N minutes. Set to 15 if you think a user might attempt wrong password"}
    $Settings += [pscustomobject]@{
        "Name"    = "autoallow"
        "Value"   = "yes"
        "Comment" = "yes=Automatically add succesful logon Ips so they don't get blocked in future.  Only do this if you have MFA."}
    $Settings += [pscustomobject]@{
        "Name"    = "blocksubnet"
        "Value"   = "yes"
        "Comment" = "yes=blocks the entire /24 subnet [default]. no=just the single IP."}
    $Settings | Export-CSV "$($FolderRDPProtect)\$($SettingsCSV)" -NoTypeInformation
}
## Update Settings
if ($settingname -ne "")
{
    Write-Host "-------------------------------------------"
    Write-Host "[Settings Updated via parameter -settingname=$($settingname)]"
    Write-Host "$($settingname)=$($settingvalue)"
    Write-Host "-------------------------------------------"
    $Setting = $Settings | Where-Object -Property Name -eq $settingname
    if ($Setting)
    {
        $Setting.Value = $settingvalue
        $Settings | Export-CSV "$($FolderRDPProtect)\$($SettingsCSV)" -NoTypeInformation
    }
    else
    {
        $ErrCode,$ErrMsg=ErrorMsg -ErrCode 501 -ErrMsg "Couldn't find setting in '$($SettingsCSV)': $($settingname)"
    }
}

##
Try
{
    [int]    $block_afterntries = ($Settings | Where-Object -Property Name -eq "block_afterntries").Value
    [int]    $lookbacknmins = ($Settings | Where-Object -Property Name -eq "lookbacknmins").Value
    [int]    $allowafternmins  = ($Settings | Where-Object -Property Name -eq "allowafternmins").Value
    [string] $autoallow = ($Settings | Where-Object -Property Name -eq "autoallow").Value
    [string] $blocksubnet = ($Settings | Where-Object -Property Name -eq "blocksubnet").Value
}
Catch
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 109 -Fatal -ErrMsg "One of the settings is invalid in '$($SettingsCSV)' (Delete file to create one with default values, or use -Uninstall)" -SemFileToDelete $LockFile
}

# catch some invalid values
if (
    (($blocksubnet -ne "yes") -and ($blocksubnet -ne "no")) -or 
    (($autoallow -ne "yes")   -and ($autoallow -ne "no")) -or
    ($block_afterntries -lt 0) -or ($block_afterntries -gt 999999) -or
    ($lookbacknmins -lt 0)     -or ($lookbacknmins -gt 999999) -or
    ($allowafternmins -lt 0)   -or ($allowafternmins -gt 999999)
    )
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 110 -Fatal -ErrMsg "One of the settings is out of range in '$($SettingsCSV)' (Delete file to create one with default values, or use -Uninstall)" -SemFileToDelete $LockFile

}

Write-Host "-------------------------------------------"
Write-Host "[Program Settings] (from $($SettingsCSV))"
Write-Host "block_afterntries: $($block_afterntries)"
Write-Host "      blocksubnet: $($blocksubnet)"
Write-Host "    lookbacknmins: $($lookbacknmins) ($(TimeSpanToString -totalminutes $lookbacknmins))"
Write-Host "  allowafternmins: $($allowafternmins) ($(TimeSpanToString -totalminutes $allowafternmins))"
Write-Host "        autoallow: $($autoallow)"
##
########### Load From XML
$scriptXML="$($FolderRDPProtect)\LastRun.xml"
$Globals=@{}
$Globals=GlobalsLoad $Globals $scriptXML $false
$GlobalsChng=$false
# Note: these don't really work for booleans or blanks - if the default is false it's the same as not existing
if (-not $Globals.last_rundate)       {$GlobalsChng=$true;$Globals.Add("last_rundate",[DateTime]::Now.AddMinutes(-$lookbacknmins))}
####
if ($GlobalsChng) {GlobalsSave $Globals $scriptXML}
########### Load From XML
Write-Host "     last_rundate: $($Globals.last_rundate) ($(TimeSpanToString ((Get-Date) - $Globals.last_rundate)) ago)"
Write-Host "-------------------------------------------"
Write-Host "[Allows and Blocks]"
## Read Allows and blocks
$IPAllowsCSV = "IP_Allows.csv"
$IPBlocksCSV = "IP_Blocks.csv"
### allows
if (Test-Path "$($FolderRDPProtect)\$($IPAllowsCSV)" -PathType Leaf)
{
    $IPsAllowFile = @(Import-Csv "$($FolderRDPProtect)\$($IPAllowsCSV)")
}
else
{
    $IPsAllowFile = @()
}
### blocks
if (Test-Path "$($FolderRDPProtect)\$($IPBlocksCSV)" -PathType Leaf)
{
    $IPsBlockFile = @(Import-Csv "$($FolderRDPProtect)\$($IPBlocksCSV)")
}
else
{
    $IPsBlockFile = @()
}
Write-Host "$($IPBlocksCSV): $($IPsBlockFile.Count.ToString("#,##0"))"
Write-Host "$($IPAllowsCSV): $($IPsAllowFile.Count.ToString("#,##0"))"
## Get-EventLog vs Get-WinEvent
## Wanted to use the newer Get-WinEvent but Get-WinEvent ended up being way too slow (like by 10x)

## Look back in logs to whichever is later: last_rundate or now-lookback
If ((((Get-Date) - $Globals.last_rundate).TotalMinutes) -gt $lookbacknmins)
{ # last run is older than window, just use window
    $DateLookback = [DateTime]::Now.AddMinutes(-$lookbacknmins)
    $DateLookback_reason = "in last $(TimeSpanToString ((Get-Date) - $DateLookback)) (Lookback Window)"
}
Else
{ # last run is new, use it
    $DateLookback = $Globals.last_rundate
    $DateLookback_reason = "in last $(TimeSpanToString ((Get-Date) - $Globals.last_rundate)) (Last Run)"
}
$Globals.last_rundate = Get-Date
######################### Get Event Log data: Successes
$Events = @();$Events+= Get-EventLog -LogName 'Security' -after $DateLookback -ErrorAction SilentlyContinue -InstanceId 4624 |
    Select-Object EventID,MachineName,TimeGenerated,
    @{n='IPAddress'          ;e={$_.ReplacementStrings[18]}},
    @{n='Username'           ;e={$_.ReplacementStrings[5]}},
    @{n='LogonType'          ;e={$_.ReplacementStrings[8]}}|
    Where-Object {($_.LogonType -eq 3) -and ($_.IPAddress -ne '-')} #Where-Object -Property LogonType -eq 3
#########################

####
$IPsToAllow_ByIP=@();$IPsToAllow_ByIP += $Events | Group IPAddress |
ForEach-Object {[PSCustomObject]@{
     IPAddress = $_.Name
     Comment = ($_.Group | Sort-Object Username | select -First 1 -Property Username).Username
     AllowedDate = ($_.Group | Sort-Object TimeGenerated | select -Last 1 -Property TimeGenerated).TimeGenerated
}}

if ($blocksubnet -eq "yes")
{ #group by subnet
    $IPsToAllow   = @(); $IPsToAllow+=$IPsToAllow_ByIP | Select-Object *, @{n='IPSubnet';e={IPSubnet $_.IPAddress 24 }} | Group-Object -property IPSubnet | Select-Object `
      @{n='IPAddress';e={$_.Name  }} `
    , @{n='Comment'      ;e={(($_.Group | Sort-Object AllowedDate) | Select-Object -Last 1 -Property Comment).Comment}} `
    , @{n='AllowedDate'  ;e={(($_.Group | Sort-Object AllowedDate) | Select-Object -Last 1 -Property AllowedDate).AllowedDate}}
    $IPDescr = "unique IP Subnets"
} #group by subnet
else
{
    $IPsToAllow = @($IPsToAllow_ByIP)
    $IPDescr = "unique IPs"
}
##$IPsToAllow | Format-Table
#Write-Host "EventLog Logon Successes: $($IPsToAllow.Count.ToString("#,##0")) IPs in last $($(TimeSpanToString -totalminutes $lookbacknmins)) (Event ID 4624) [autoallow:$($autoallow)]"
Write-Host "EventLog Logon Successes: $($IPsToAllow.Count.ToString("#,##0")) $($IPDescr) $($DateLookback_reason) (Event ID 4624) [autoallow:$($autoallow)]"
####

### Add missing allows
$Added = 0
$Counter = 0
ForEach ($IPToAllow in $IPsToAllow)
{
    $Counter +=1
    $IPAllowFile = $IPsAllowFile | Where-Object -Property IPAddress -eq $IPToAllow.IPAddress
    if ($IPAllowFile)
    {
        $Action = "[Already Allowed - Comment:$($IPAllowFile.Comment)]"
    }
    else
    {
        if ($autoallow -eq "yes")
        {
            $IPsAllowFile += $IPToAllow
            $Added += 1
            $Action = "[Added]"
        }
        else
        {
            $Action = "[Use autoallow=yes to add allows]"
        }
    }
    Write-Host "  Success $($Counter): $($IPToAllow.IPAddress) $($IPToAllow.Comment) $($IPToAllow.AllowedDate) $($Action)"
}
###
if ($Added -gt 0)
{
    $IPsAllowFile | Export-CSV "$($FolderRDPProtect)\$($IPAllowsCSV)" -NoTypeInformation
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 203 -ErrMsg "$($Added) New succesful logons detected"
}
### Add missing allows

######################### Get Event Log data: Failures 4625
$Events = @();$Events+= Get-EventLog -LogName 'Security' -after $DateLookback -ErrorAction SilentlyContinue -InstanceId 4625 |
    Select-Object EventID,MachineName,TimeGenerated,
    @{n='IPAddress'          ;e={$_.ReplacementStrings[19]}},
    @{n='Username'           ;e={$_.ReplacementStrings[5]}},
    @{n='LogonType'          ;e={$_.ReplacementStrings[10]}},
    @{n='FailureReason'      ;e={$_.ReplacementStrings[8]}},
    @{n='FailureDescription' ;e={
        switch ($_.ReplacementStrings[8]){
        "%%2313" {"Unknown user name or bad password."; break}
        "%%2310" {"Account currently disabled.";break}
        default {"Unknown: $($_.ReplacementStrings[8])"; break}}
        }}|
    Where-Object {($_.LogonType -eq 3) -and ($_.IPAddress -ne '-')} #Where-Object -Property LogonType -eq 3
###########################
if ($Events.count -gt 0)
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 204 -ErrMsg "EventLog Logon Failures: $($Events.Count.ToString("#,##0")) $($DateLookback_reason) (Event ID 4625)"
}

### Group events by IPAddress
$IPHits   = @();$IPHits+= $Events | group-object -property IPAddress | Select-Object `
      @{n='IPAddress';e={$_.Name  }} `
    , @{n='Summary'  ;e={($_.Group | Sort-Object TimeGenerated) | Select-Object -Last 1 -Property TimeGenerated,Username}} `
    , @{n='Hits'     ;e={$_.Count }} `
    | Sort-Object Hits -Descending

### Group events by Username
$UserHits   = @();$UserHits+= $Events | group-object -property Username | Select-Object `
      @{n='Username';e={$_.Name  }} `
    , @{n='Summary'  ;e={($_.Group | Sort-Object TimeGenerated) | Select-Object -Last 1 -Property TimeGenerated,IPAddress}} `
    , @{n='Hits'     ;e={$_.Count }} `
    | Sort-Object Hits -Descending

Write-Host "-------------------------------------------"
Write-Host "[Candidates and Exceptions]"
##### Select Unique IPAddress and related summarized data
$BlockTime = Get-Date
$IPsBlockEvent_ByIP =@() ;$IPsBlockEvent_ByIP += $IPHits |
    ForEach-Object {[PSCustomObject]@{
         IPAddress     = $_.IPAddress
         LastUsername  = $_.Summary.Username
         Hits          = $_.Hits
         LastHitTime   = $_.Summary.TimeGenerated
         BlockTime     = $BlockTime
         InternetBlockList     = ""
         Action = ""
    }} | Sort-Object -Property Hits -Descending
##### 

if ($True)
{
    Write-Host "Checking public blocklist for each IP ($($IPsBlockEvent_ByIP.Count) unique IPs of $($Events.Count) Events)"
    $count = 0
    ForEach ($IP in $IPsBlockEvent_ByIP | Sort-Object IPAddress)
    {
        $ErrCodeBlockList, $ErrMsgBlockList = IsOnBlacklist $IP.IPAddress "abuseipdb.com"
        $IP.InternetBlockList = $ErrMsgBlockList
        $count +=1
        Write-Host "$($count) of $($IPsBlockEvent_ByIP.Count): $($ErrMsgBlockList)"
    }
}

if ($blocksubnet -eq "yes")
{ #group by subnet
    $IPsBlockEvent   = @(); $IPsBlockEvent+=$IPsBlockEvent_ByIP | Select-Object *, @{n='IPSubnet';e={IPSubnet $_.IPAddress 24 }} | Group-Object -property IPSubnet | Select-Object `
      @{n='IPAddress'    ;e={$_.Name  }} `
    , @{n='LastUsername' ;e={(($_.Group | Sort-Object LastHitTime) | Select-Object -Last 1 -Property LastUsername).LastUsername}} `
    , @{n='Hits'         ;e={ ($_.Group | Measure-Object -Property Hits -Sum).Sum}} `
    , @{n='LastHitTime'  ;e={(($_.Group | Sort-Object LastHitTime) | Select-Object -Last 1 -Property LastHitTime).LastHitTime}} `
    , @{n='BlockTime'    ;e={$BlockTime}} `
    , @{n='InternetBlockList'    ;e={(($_.Group | Sort-Object LastHitTime) | Select-Object -Last 1 -Property InternetBlockList).InternetBlockList}} `
    , @{n='Action'       ;e={""}} `
    | Sort-Object Hits -Descending
    $IPDescr = "unique IP Subnets"
} #group by subnet
else
{
    $IPsBlockEvent = @($IPsBlockEvent_ByIP)
    $IPDescr = "unique IPs"
}

SaveStatsToCSV -LogType "IPAddress" -LogItems $IPsBlockEvent -Logfolder "$($FolderRDPProtect)\Logs" -LookBackMins $lookbacknmins
Write-Host "Block Candidates: $($IPsBlockEvent.Count.ToString("#,##0")) $($IPDescr) (from $($IPsBlockEvent_ByIP.Count) IPs) in event log $($DateLookback_reason)"
$IPsBlockEvent | Select-Object IPAddress,LastUsername,Hits,LastHitTime,InternetBlockList | Format-Table | Out-String | Write-Host

##### Select Unique Usernames and related summarized data
$Usernames =@() ;$Usernames += $UserHits |
ForEach-Object {[PSCustomObject]@{
     Username  = $_.Username
     LastIPAddress = $_.Summary.IPAddress
     Hits          = $_.Hits
     LastHitTime   = $_.Summary.TimeGenerated
     BlockTime     = $BlockTime
     Action = ""
}} | Sort-Object -Property Hits -Descending
##### 
SaveStatsToCSV -LogType "Username" -LogItems $Usernames -Logfolder "$($FolderRDPProtect)\Logs" -LookBackMins $lookbacknmins

if ($verbose)
{
    Write-Host "(-verbose) Failure Events: $($Events.Count.ToString("#,##0"))"
    $Events | Out-GridView
    Write-Host "(-verbose) IPHits: $($IPHits.Count.ToString("#,##0"))"
    $IPHits | Out-GridView
    $Usernames = $Events | group-object -property Username |Select-Object @{n='Username';e={$_.Name}}, @{n='Hits';e={$_.Count}} |Sort-Object Hits -Descending
    Write-Host "(-verbose) Usernames: $($Usernames.Count.ToString("#,##0"))"
    $Usernames | Out-GridView
    Write-Host "(-verbose) Failure Events (Unique IPs): $($IPsBlockEvent.Count.ToString("#,##0"))"
    $IPsBlockEvent | Out-GridView
    #######################
    $ErrCode,$ErrMsg=ErrorMsg -Fatal -ErrCode 103 -ErrMsg "Verbose Mode" -SemFileToDelete $LockFile
}

## Add blocks from file that are missing from events
$origcount = $IPsBlockEvent.Count
$Added = 0
ForEach ($IPBlockFile in $IPsBlockFile)
{
    $IPBlockEvent = $IPsBlockEvent | Where-Object -Property IPAddress -eq $IPBlockFile.IPAddress
    if (-not ($IPBlockEvent))
    {
        $IPsBlockEvent += ($IpBlockFile | Select-Object *,@{n='Action';e={''}})
        $Added += 1
    }
    else #Update?
    {
        $IPBlockEvent.Hits = [int] $IPBlockEvent.Hits + [int] $IPBlockFile.Hits

    }
}
Write-Host "Block Candidates: $($origcount) unique from Event Log"
Write-Host "Block Candidates: + $($Added) merged (from $($IPsBlockFile.Count.ToString("#,##0")) in $($IPBlocksCSV))"
Write-Host "Block Candidates: = $($IPsBlockEvent.Count.ToString("#,##0")) subtotal"

## Remove blocks that are expired, or that are on the allow list
$IPsBlockEvent | ForEach-Object {$_.Action="Keep"} #Assume we keep all of them
$RemoveExpired = 0
$RemoveAllow = 0
$RemoveLowHits = 0
ForEach ($IPBlockEvent in $IPsBlockEvent)
{
    ## if ($IPBlockEvent.IPAddress -eq "185.99.1.122")
    ##    {Write-Host "debug"}
    if ($IPBlockEvent.Action -eq "Keep")
    {
        $IPAllowFile = $IPsAllowFile | Where-Object -Property IPAddress -eq $IPBlockEvent.IPAddress
        if ($IPAllowFile)
        {
            $IPBlockEvent.Action = "Delete (Allow list)"
            $RemoveAllow += 1
        }
    }
    if ($IPBlockEvent.Action -eq "Keep")
    {
        Try
        {
            $age = New-TimeSpan -Start $IPBlockEvent.LastHitTime -End (Get-Date) 
        }
        Catch
        {
            $age = New-TimeSpan -Minutes ($allowafternmins+1)  #Invalid date, assume it's expired
        }
        if ($age.TotalMinutes -gt $allowafternmins)
        {
            $IPBlockEvent.Action = "Delete (Expired)"
            $RemoveExpired += 1
        }
    }
    if ($IPBlockEvent.Action -eq "Keep")
    {
        if ($IPBlockEvent.Hits -lt $block_afterntries)
        {
            $IPBlockEvent.Action = "Keep (Too few hits)"
            $RemoveLowHits += 1
        }
    }
}
Write-Host " Block Exception: - $($RemoveAllow) of $($IPsAllowFile.Count.ToString("#,##0")) from $($IPAllowsCSV)"
Write-Host " Block Exception: - $($RemoveExpired) blocks expired (after $(TimeSpanToString -totalminutes $allowafternmins))"
Write-Host " Block Exception: - $($RemoveLowHits) were not blocked (due to $($block_afterntries) minimum hits requirement)"

#### Export Blocks to file for next run - unless they are expired or allowed
# Keep                      File these
# Keep (Too few hits)       File these
# Delete (Allow list)       remove
# Delete (Expired)          remove
####
$IPsBlockEvent = @($IPsBlockEvent | Where-Object {$_.Action -match "Keep"})

try
{
    $IPsBlockEvent | Select-Object IPAddress,LastUsername,Hits,LastHitTime,BlockTime | Export-CSV "$($FolderRDPProtect)\$($IPBlocksCSV)" -NoTypeInformation
}
catch
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 209 -ErrMsg "Problem writing file.  Is the $($IPBlocksCSV) open in Excel?"
}

### remove Action = Delete
$IPsBlockEvent = @($IPsBlockEvent | Where-Object {$_.Action -eq "Keep"})
#$IPsBlockEvent = @($IPsBlockEvent | Where-Object Action -EQ "Keep")

Write-Host "     Block these: = $($IPsBlockEvent.Count.ToString("#,##0")) total"
Write-Host "-------------------------------------------"
Write-Host "[Firewall Changes]"
if ($nofirewall)
{
    $ErrCode,$ErrMsg=ErrorMsg -ErrCode 205 -ErrMsg "No firewall changes will be made (-nofirewall)"
}
else
{
    ### create initial rule
    $fwallrulename = "RDP Protection Port $($rdpport)"
    $fwallrule = Get-NetFirewallRule -DisplayName $fwallrulename -ErrorAction SilentlyContinue
    if (-not($fwallrule))
    {
        $ErrCode,$ErrMsg=ErrorMsg -ErrCode 206 -ErrMsg "Creating new Firewall Rule: $($fwallrulename))"
        $fwallrule = New-NetFirewallRule -DisplayName $fwallrulename -RemoteAddress $dummyip -Direction Inbound -Protocol TCP -LocalPort $rdpport -Action Block -Description "Created by RDP Protection.ps1 to block bad IPs found in Event log - see Scheduled Task"
    }
    #####
    $IPsBlockFwallRemoves = @()
    $IPsBlockFwallAdds = @()

    $IPsBlockFwall = @()
    $IPsBlockFwall += ($fwallrule | Get-NetFirewallAddressFilter).RemoteAddress | Where-Object {$_ -ne $dummyip}
    $IPsBlockFwallNew = @($dummyip)
    
    # remove any expired
    ForEach ($IPBlockFwall_Entry in $IPsBlockFwall)
    {
        ###
        $IPBlockFwall_EntryArr=$IPBlockFwall_Entry.Split("/") # Determine if subnet or IP: 45.155.205.0/255.255.255.0 or 45.155.205.56
        If ($IPBlockFwall_EntryArr.count -eq 1)
        { # ip 45.155.205.56
            $IPBlockFwall=$IPBlockFwall_Entry
        }
        else
        { # subnet 45.155.205.0/255.255.255.0  --> 45.155.205.0/24
            $IPBlockFwall="$($IPBlockFwall_EntryArr[0])/$(NetMaskToCIDR $IPBlockFwall_EntryArr[1])"
        }
        ###
        $IPBlockEvent = $IPsBlockEvent | Where-Object -Property IPAddress -eq $IPBlockFwall
        if ($IPBlockEvent)
        {   #leave in on the 'new' firewall list
            $IPsBlockFwallNew+=$IPBlockFwall
        }
        else
        {
            Write-Host "[Removed] $($IPBlockFwall)"
            $IPsBlockFwallRemoves +=$IPBlockFwall #put it on the 'removes' posting
        }
    }
    Write-Host "IPs Removed from Fwall: $($IPsBlockFwallRemoves.Count.ToString("#,##0"))"
    # add any missing
    ForEach ($IPBlockEvent_Entry in $IPsBlockEvent)
    {
        ###
        $IPBlockEvent_EntryArr=$IPBlockEvent_Entry.IPAddress.Split("/") # Determine if subnet or IP: 45.155.205.0/24 or 45.155.205.56
        If ($IPBlockEvent_EntryArr.count -eq 1)
        { # ip 45.155.205.56
            $IPBlockEvent=$IPBlockEvent_Entry
        }
        else
        { # subnet 45.155.205.0/24  --> 45.155.205.0/255.255.255.0
            $IPBlockEvent="$($IPBlockEvent_EntryArr[0])/$(CIDRToNetMask $IPBlockEvent_EntryArr[1])"
        }
        ### Look for this IP in firewall list
        $IPBlockFwall = $IPsBlockFwall | Where-Object {$_ -eq $IPBlockEvent}
        if (-not($IPBlockFwall))
        { # not there
            #add to firewall
            $IPsBlockFwallAdds +=$IPBlockEvent_Entry.IPAddress #put it on the 'adds' posting
            $IPsBlockFwallNew  +=$IPBlockEvent_Entry.IPAddress #leave in on the 'new' firewall list
            Write-Host "[Added] $($IPBlockEvent_Entry.IPAddress) $($IPBlockEvent_Entry.Username) $($IPBlockEvent_Entry.Hits) hits"
        }
    }
    Write-Host "IPs Added to Fwall: $($IPsBlockFwallAdds.Count.ToString("#,##0"))"
    ## Make firewall changes
    ##Write-Host "-------------------------------------------"
    $Log =@()
    if (($IPsBlockFwallAdds.count -eq 0) -and ($IPsBlockFwallRemoves.count -eq 0))
    {
        Write-Host "Firewalled IPs: $($IPsBlockFwall.Count.ToString("#,##0")) (No change)"
    }
    else
    {
        #Write-Host "Fwall IPs (before): $($IPsBlockFwall.Count.ToString("#,##0"))"
        $IPsBlockFwallNew =$IPsBlockFwallNew | Select-Object -Unique
        #Write-Host "Fwall IPs (after): $($IPsBlockFwallNew.Count.ToString("#,##0"))"
        #if ($IPsBlockFwallNew.Count.ToString("#,##0") -eq 0) {$IPsBlockFwallNew += $dummyip} # have at least 1
        $fwallrule | Set-NetFirewallRule -RemoteAddress $IPsBlockFwallNew
        $ErrCode,$ErrMsg=ErrorMsg -ErrCode 208 -ErrMsg "Firewalled IPs: $($IPsBlockFwallNew.Count.ToString("#,##0")-1) (Changed from $($IPsBlockFwall.Count.ToString("#,##0")))"
    }
}
Write-Host "-------------------------------------------"
Write-Host "[Save Session]"
GlobalsSave $Globals $scriptXML
Write-Host " $($IPBlocksCSV): $($IPsBlockEvent.Count.ToString("#,##0"))"
Write-Host "-------------------------------------------"
Write-Host "Done"
Write-Host "Exit code:$($ErrCode) $($ErrMsg)"
Start-Sleep 3

### Schedule
$taskname = $scriptName
$task = $null
$task = Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue
if ($task)
{ ## Task Exists
    if (($mode -eq "Uninstall") -or ($nosched))
    { ### Delete existing task
        Write-Host "Task: $($taskname) [existing task removed]"
        Unregister-ScheduledTask -TaskName $taskname -Confirm:$false
    }
} ## Task Exists
else
{ ## Task doesn't exist

    ### Create new task
    $sched_every_n_hrs = 1
    $exe = "powershell.exe"
    $arg = "-ExecutionPolicy ByPass"
    $arg += " -File "+[char]34+"$($FolderRDPProtect)\$($scriptName)"+[char]34
    $arg += " -quiet "
    $taskactn = New-ScheduledTaskAction -Execute $exe -Argument $arg
    
    ### Run daily, every 2 hrs
    $taskrpt = (New-TimeSpan -Hours $sched_every_n_hrs)  ## every 2 hrs
    $taskdur = (New-TimeSpan -Hours 24) ## for up to 24 hrs Note: dur must be >= rpt
    $tasktrig = New-ScheduledTaskTrigger -Daily -At (Get-Date).Date ## start at midnight every day
    $tasktrig_rep = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $taskrpt -RepetitionDuration $taskdur
    $tasktrig.Repetition = $tasktrig_rep.Repetition #Can't do a rep interval on a daily sched in powershell, so use this trick
    
    ### Create Sched task
    Write-Host "Task: $($taskname) [Scheduling every $($sched_every_n_hrs) hrs...]"    
    $taskuser= "NT AUTHORITY\SYSTEM"
    $task = Register-ScheduledTask -TaskName $taskname -Trigger $tasktrig -User $taskuser -Action $taskactn -RunLevel Highest -Force 
} ## Task doesn't exist
###

#################### Transcript Save
if ($mode -ne "Uninstall")
{
    Stop-Transcript | Out-Null
}
#################### Transcript Save
Remove-Item $LockFile # Delete lock (semaphore) file
Exit ($ErrCode)