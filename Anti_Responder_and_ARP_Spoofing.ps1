Import-Module C:\folder\Biz\NetTCPIP\NetTCPIP.psd1
$Mac_vendor = import-csv 'C:\folder\Biz\MFU_MAC.csv' -Delimiter ';'

function Write-Event {
    [alias('Write-WinEvent', 'Write-Events')]
    [cmdletBinding()]
    param(
        [string[]] $Computer,
        [Parameter(Mandatory)][alias('EventLog')][string] $LogName,
        [Parameter(Mandatory)][alias('Provider', 'ProviderName')][string] $Source,
        [int] $Category,
        [alias('Level')][System.Diagnostics.EventLogEntryType] $EntryType = [System.Diagnostics.EventLogEntryType]::Information,
        [Parameter(Mandatory)][alias('EventID')][int] $ID,
        [Parameter(Mandatory)][string] $Message,
        [Array] $AdditionalFields
    )
    Begin {
        #Load the event source to the log if not already loaded.  This will fail if the event source is already assigned to a different log.
        <# This errors out when run not as Administrator on Security log, even thou was
        if ([System.Diagnostics.EventLog]::SourceExists($Source) -eq $false) {
            try {
                [System.Diagnostics.EventLog]::CreateEventSource($source, $evtlog)
            } catch {
                Write-Warning "New-WinEvent - Couldn't create new event log source - $($_.ExceptionMessage)"
                return
            }
        }
        #>
    }
    Process {
        if (-not $Computer) {
            $Computer = $Env:COMPUTERNAME
        }
        foreach ($Machine in $Computer) {
            <#
            System.Diagnostics.EventInstance new(long instanceId, int categoryId)
            System.Diagnostics.EventInstance new(long instanceId, int categoryId, System.Diagnostics.EventLogEntryType entryType)
            #>
            $EventInstance = [System.Diagnostics.EventInstance]::new($ID, $Category, $EntryType)
            $Event = [System.Diagnostics.EventLog]::new()
            $Event.Log = $LogName
            $Event.Source = $Source
            if ($Machine -ne $Env:COMPUTERNAME) {
                $Event.MachineName = $Machine
            }
            [Array] $JoinedMessage = @(
                $Message
                $AdditionalFields | ForEach-Object { $_ }
            )
            try {
                $Event.WriteEvent($EventInstance, $JoinedMessage)
            } catch {
                Write-Warning "Write-Event - Couldn't create new event - $($_.Exception.Message)"
            }
        }
    }
}
function Find-Items($Items, $char){
    foreach ($Item in $Items) {
    $Item | ? {$_ -like $char}
    }
}
function Check-ARP-Spoof{
param (
  $iplist,
  [string]$Event_sourse,
  $Networks_Exception = '127.0.0.1'
  )
#Игнорируется проверка доверия к ssl сертификату
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

  $all_mac_in_network = @()

    if ((Test-Path -Path C:\folder\Biz\Valid_MAC.txt) -eq $false) { New-Item -Path  C:\folder\Biz\Valid_MAC.txt -ItemType File  }
    if ((Test-Path -Path C:\folder\Biz\MAC_Black_List.txt) -eq $false) { New-Item -Path  C:\folder\Biz\MAC_Black_List.txt -ItemType File  }

    #Выявляем аномальное кол-во одинаковых mac адресов
    $Reachable_hosts = Get-NetNeighbor | where {$_.State -eq 'Reachable'}
    if ($Reachable_hosts.count -lt '15'){Write-Host "Minimal counts Reachable hosts"
		return}
    $Percentage_of_Original_MAC = (($Reachable_hosts | foreach LinkLayerAddress | select -Unique).count) / ($Reachable_hosts| foreach LinkLayerAddress).count * 100
    $Percentage_of_Original_MAC

	  if ($Percentage_of_Original_MAC -lt '3'){Write-Host "Abnormal number of identical mac addresses" 
     return }
    
    $Chcp = chcp 437 
    $gate_ip =  ipconfig | Select-String "Default Gateway" | % { $_.ToString().Split(':')[1].Trim()}
    if ($gate_ip -match $Networks_Exception ){Write-Host 'Host in VPN network. Stoping module Check-ARP-Spoof' -ForegroundColor Yellow 
        return }

    $gate_ip = $gate_ip -split "\s+"
	$gate_ip = $gate_ip | where {$_.Length -ne '0'}
    $gate_mac = arp -a $gate_ip | Select-String -Pattern 'Interface' -NotMatch | Select-String $gate_ip |  % { $_.ToString() -split "\s+" }
    $gate_mac = $gate_mac[2].ToUpper()
    $NetAdapter_ID = Get-NetNeighbor -IPAddress $gate_ip | foreach ifIndex  #((arp -a $gate_ip | Select-String 'Interface' |  % { $_.ToString() -split "\s+" })[3]) -replace '0X'
    $White_gate_MAC = if ((cat C:\folder\Biz\Valid_MAC.txt) -ne $null) { cat C:\folder\Biz\Valid_MAC.txt }
    $Black_list_MAC = if ((cat C:\folder\Biz\MAC_Black_List.txt) -ne $null) { cat C:\folder\Biz\MAC_Black_List.txt }

       if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ){
        $Event_sourse_count = $true
        Write-Host "`nARP-Module:Source for logs was previously created" -ForegroundColor Green}
       else{$Event_sourse_count = $false
        New-EventLog -LogName Application -Source $Event_sourse
        Write-Host "Created a Source for logs. it was not created before" -ForegroundColor Yellow
        if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ) {$Event_sourse_count = $true} }
    
    Write-Host "Gateway with ip: $gate_ip and mac: $gate_mac" -ForegroundColor Green
  

    for ($i = 0; $i -lt $iplist.Count; $i++) 
    {
        if ($iplist[$i] -ne $gate_ip)
        { 
            $ip = $iplist[$i]
            $arp_call = arp -a $ip | Select-String -Pattern 'Interface' -NotMatch | Select-String $ip
            if ($arp_call -ne $null)
            {
                  $call = $arp_call -split "\s+"
                  $mac = $call[2].ToUpper()
                  #Тут проверка MAC на предмет принтера.
                  $Found_MAC_Printer_or_phone = $Mac_vendor | where {$_.mac -eq ($mac -replace '-').Substring(0,6)}

                  if ($Found_MAC_Printer_or_phone -ne $null -and (Test-Connection $ip -Quiet -Count 1)){
                  #весы
                    [int]$Weigher = 0 
                    if ((testport -hostname $ip -port 515 -timeout 300).open -eq $true ) {$Weigher += 10 ;  Write-Host "Open port: $($ip):515"}
                    if ((testport -hostname $ip -port 631 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):631"}
					if ((testport -hostname $ip -port 3702 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):3702"}
					if ((testport -hostname $ip -port 5901 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):5901"}
					if ((testport -hostname $ip -port 8000 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):8000"}
                    if ((testport -hostname $ip -port 9100 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):9100"}
					if ((testport -hostname $ip -port 53202 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53202"}
					if ((testport -hostname $ip -port 53203 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53203"}
					if ((testport -hostname $ip -port 53204 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53204"}
                    if ((testport -hostname $ip -port 65003 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):65003"}
                    if ((testport -hostname $ip -port 65001 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):65001"}
                    try {if((Invoke-WebRequest -Uri $ip  -Method Get -UseBasicParsing).RawContent -match ($Found_MAC_Printer_or_phone.Vendor).Split(' ')[0]){
                        $Weigher += 10 ;  Write-Host "Web banner correct"}}
                    catch{}
					
                    if ((testport -hostname $ip -port 8888 -timeout 300).open -eq $true) {$Weigher -= 1000 ;  Write-Host "Open port: $($ip):8888"}
                    if ($Weigher -lt '10'){
                        #Ожидание выхода принтера из спящего режима
                        Start-Sleep -Seconds 300
                        #весы
                        [int]$Weigher = 0 

                        if ((testport -hostname $ip -port 515 -timeout 300).open -eq $true ) {$Weigher += 10 ;  Write-Host "Open port: $($ip):515"}
                        if ((testport -hostname $ip -port 631 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):631"}
						if ((testport -hostname $ip -port 3702 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):3702"}
						if ((testport -hostname $ip -port 5901 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):5901"}
						if ((testport -hostname $ip -port 8000 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):8000"}
                        if ((testport -hostname $ip -port 9100 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):9100"}
						if ((testport -hostname $ip -port 53202 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53202"}
						if ((testport -hostname $ip -port 53203 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53203"}
						if ((testport -hostname $ip -port 53204 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):53204"}
                        if ((testport -hostname $ip -port 65003 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):65003"}
                        if ((testport -hostname $ip -port 65001 -timeout 300).open -eq $true) {$Weigher += 10 ;  Write-Host "Open port: $($ip):65001"}
						try {if((Invoke-WebRequest -Uri $ip  -Method Get -UseBasicParsing).RawContent -match ($Found_MAC_Printer_or_phone.Vendor).Split(' ')[0]){
							$Weigher += 10 ;  Write-Host "Web banner correct"}}
						catch{}
						
                        if ((testport -hostname $ip -port 8888 -timeout 300).open -eq $true) {$Weigher -= 1000 ;  Write-Host "Open port: $($ip):8888"}
                        if ($Weigher -lt '10'){
							Write-Event -logname Application -source $Event_sourse -eventID 3004 -entrytype Warning  -AdditionalFields $ip, $mac, $($Found_MAC_Printer_or_phone.Vendor) -message "Fake printer MAC address detected: $ip; MAC=$mac; MAC-Address Vendor=$($Found_MAC_Printer_or_phone.Vendor)" 
							Write-Host "Active IP: $ip with MAC: $mac. Warning! It's fake MAC. Vendor MAC-Address:" $Found_MAC_Printer_or_phone.Vendor -ForegroundColor Green}

                        else{echo "It is printer: $ip with MAC: $mac"}
                        }

                    else{echo "It is printer: $ip with MAC: $mac"}
                  }

                  else{echo "Active IP: $ip with MAC: $mac"}
                 
                  $all_mac_in_network += $mac

                  if ($mac -eq $gate_mac -and [string]($gate_ip -split "\d{1,3}$") -eq  [string]($ip -split "\d{1,3}$") -and $White_gate_MAC -ne $null -and $mac -ne $White_gate_MAC){

                  #Не дописывать если дубилкат.
                  if ((Select-String -Path  C:\folder\Biz\MAC_Black_List.txt -Pattern $mac) -eq $null ) { 
                  $mac | Out-File  C:\folder\Biz\MAC_Black_List.txt -Append }

                  Write-Host "$mac add to MAC black list"

                  #Прописываем жестко шлюз

                  if($NetAdapter_ID -ne $null -and $gate_ip -ne $null -and $White_gate_MAC -ne $null){
					Write-Host "Setting valid MAC-address: $White_gate_MAC" -ForegroundColor Red
                    New-NetNeighbor -InterfaceIndex $NetAdapter_ID -IPAddress  $gate_ip  -LinkLayerAddress $White_gate_MAC -State Permanent 

                    Write-Host  "`n`nYou are being Spoofed a duplicate ARP value found. Ip = $ip " -ForegroundColor Red
                    write-Event -logname Application -source $Event_sourse -eventID 3002 -entrytype Warning -AdditionalFields $ip, $mac -message "Detected ARP Spoofing from IP:$ip, MAC:$mac "
                     return}
                  else {Write-Host "Error at the first start"
                     return}

                  }
                  
                  elseif ((Find-Items -Items $Black_list_MAC -Char $mac) -ne $null){
                  Write-Host "Found MAC from black list.$ip $mac " -ForegroundColor Yellow
                  $Fount_MAC_from_BL = 'Yes'
                  }


            }
        }
    }

        if ((cat C:\folder\Biz\Valid_MAC.txt) -eq $null -or (cat C:\folder\Biz\Valid_MAC.txt) -notmatch $gate_mac ) { $gate_mac > C:\folder\Biz\Valid_MAC.txt
    Write-Host "`nSave valid MAC to file" -ForegroundColor Yellow
    }
        

        if ($Fount_MAC_from_BL -ne 'Yes'){   
    
    Write-host "`n You are Safe, no duplicate ARP values found." -ForegroundColor Green
    #Удаляем прописанный жетско шлюз. 
    Remove-NetNeighbor -InterfaceIndex $NetAdapter_ID  -IPAddress $gate_ip  -Confirm:$false}
    }
function Check-DNS-Spoof {

param 
( 
  [string]$DC_Name,
  [string]$Domain_name,
  [string]$Event_sourse
) 
       if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ){
        $Event_sourse_count = $true
        Write-Host "`nDNS Module: Source for logs was previously created" -ForegroundColor Green}
       else{$Event_sourse_count = $false
        New-EventLog -LogName Application -Source $Event_sourse
        Write-Host "`nCreated a Source for logs. it was not created before" -ForegroundColor Yellow
        if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ) {$Event_sourse_count = $true} }


$Count_Numbers = 0
while ($Count_Numbers -le 5 ){
$Ping_Fake_PC_Name = ($DC_Name  + (80..100 | % {Get-Random -Minimum 81 -Maximum 100 } | select -First 1) + $Domain_name)
if((Test-Connection -ComputerName $Ping_Fake_PC_Name  -Count 1 -Quiet) -eq $true ) {
$Ping_Result = Test-Connection -ComputerName $Ping_Fake_PC_Name  -Count 1 
$DNS_Spoofing_IP =  $Ping_Result.IPV4Address.IPAddressToString
$Ping_Result_for_Сomparison  = ($Ping_Result.IPV4Address.IPAddressToString).Split('.')[0]+'.'+($Ping_Result.IPV4Address.IPAddressToString).Split('.')[1]+'.'+($Ping_Result.IPV4Address.IPAddressToString).Split('.')[2]
$i = 0

while($i -lt 3){
if ($Ping_Result_for_Сomparison -eq ( ($Network_Interfaces.IPv4Address.IPAddress).Split('.')[0]+'.'+($Network_Interfaces.IPv4Address.IPAddress).Split('.')[1]+'.'+((($Network_Interfaces.IPv4Address.IPAddress).Split('.')[2]) - 1 + $i)) ) {
        Write-Host "Host subnetwork $Ping_Result_for_Сomparison equivalent"`
        (($Network_Interfaces.IPv4Address.IPAddress).Split('.')[0]+'.'+($Network_Interfaces.IPv4Address.IPAddress).Split('.')[1]+'.'+((($Network_Interfaces.IPv4Address.IPAddress).Split('.')[2]) - 1 + $i))`
        -ForegroundColor Red
        Write-Event -LogName Application -Source $Event_sourse  -ID 3003 -EntryType Warning -AdditionalFields $DNS_Spoofing_IP -Message "Detected DNS Spoofing from IP:$DNS_Spoofing_IP" 
        Write-Host -ForegroundColor Red  "Detected DNS Spoofing from IP:"$Ping_Result.IPV4Address.IPAddressToString 
    
         
        }
$i++
}

return }

$Count_Numbers += 1 
}

}
function Get-IPrange {
<# 
  .SYNOPSIS  
    Get the IP addresses in a range 
  .EXAMPLE 
   Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.3 -cidr 24 
#> 
 
param 
( 
  [string]$start, 
  [string]$end, 
  [string]$ip, 
  [string]$mask, 
  [int]$cidr 
) 
 
function IP-toINT64 () { 
  param ($ip) 
 
  $octets = $ip.split(".") 
  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
} 
 
function INT64-toIP() { 
  param ([int64]$int) 

  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
} 
 
if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
if ($ip) { 
  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
} else { 
  $startaddr = IP-toINT64 -ip $start 
  $endaddr = IP-toINT64 -ip $end 
} 
 
 
for ($i = $startaddr; $i -le $endaddr; $i++) 
{ 
  INT64-toIP -int $i 
}

}
function testport {
 param 
 (
 [string]$hostname, 
 [string]$port, 
 [string]$timeout = '100'
 )
  $requestCallback = $state = $null
  $client = New-Object System.Net.Sockets.TcpClient
  $beginConnect = $client.BeginConnect($hostname,$port,$requestCallback,$state)
  Start-Sleep -milli $timeOut
  if ($client.Connected) { $open = $true } else { $open = $false }
  $client.Close()
  [pscustomobject]@{hostname=$hostname;port=$port;open=$open}
}
function SMB_logon {
 param 
 (
 [string]$ResponderIp, 
 [string]$User_for_SMB, 
 $User_domain =  (Get-WmiObject Win32_ComputerSystem).Domain  -replace  "\..+" , 
 [string]$P_for_SMB
 )


$Cred = New-Object System.Management.Automation.PSCredential "$User_domain\$User_for_SMB" , ($P_for_SMB | ConvertTo-SecureString -AsPlainText -Force)

New-PSDrive -Name Share -PSProvider FileSystem -Root \\$ResponderIp -Credential $Cred -EA SilentlyContinue
if ($Error[0].Exception.Message -match "Access is denied|Отказано в доступе" ) {$SMB_Request_status = $true}
else {$SMB_Request_status = $false}
$SMB_Request_status

}
function http_basic_auth {
 param 
 (
 [string]$ResponderIp, 
 [string]$User_for_http_auth, 
 [string]$P_for_http_auth
 )

$web_cred = New-Object System.Management.Automation.PSCredential $User_for_http_auth , ($P_for_http_auth | ConvertTo-SecureString -AsPlainText -Force)

 Invoke-WebRequest -Uri http:\\$ResponderIp/  -Credential $web_cred -UseBasicParsing | select statuscode, StatusDescription
}
function AntiResponder { 
param
(
#SMB cred
[string]$User_SMB,
[string]$Ps_user_SMB,
#HTTP auth cred
[string]$User_http_auth,
[string]$Ps_user_http_auth,
#
[string]$Event_sourse,
$Networks_Exception = '127.0.0.1',
$Pool_Ip_custom 

)

#Ports for scan
$Kerberos_port = '88'
$Ldap_port = '389'
$Imap_port = '143'
$DNS_port = '53'
$SMB_port = '445'
$FTP_port = '21'
$Http_port = '80'

if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ){
    $Event_sourse_count = $true
    Write-Host "Responder Module: Source for logs was previously created" -ForegroundColor Green}
else{$Event_sourse_count = $false
    New-EventLog -LogName Application -Source $Event_sourse
    Write-Host "Created Source for logs. It was not created before" -ForegroundColor Yellow
    if((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Event_sourse") -eq $true ) {$Event_sourse_count = $true} }

foreach($Network_and_prefix in $Networks_and_prefix) {
if ($Network_and_prefix  -match $Networks_Exception){Write-Host 'Host in VPN network. Stoping module AntiResponder' -ForegroundColor Yellow 
        return }
write-host "Started to scan" $Network_and_prefix -ForegroundColor Green
[int]$Global_Counter = '0'

foreach ($Ip in $Pool_Ip_custom) {

[int]$Counter = '0'


$Port_status = testport -hostname $Ip  -port $DNS_port

if($Port_status.open -eq $true){

$Counter += '1'
$Warning_ResponderIp =$Port_status.hostname 
Write-Host "Suspicious Responder:" $Warning_ResponderIp ";" $Counter -ForegroundColor Yellow
#Сканер портов
    if ((testport -hostname $Warning_ResponderIp  -port $Kerberos_port).open -eq $true) {$Counter += '1' ;   Write-Host $Kerberos_port open}
    if ((testport -hostname $Warning_ResponderIp  -port $Ldap_port).open -eq $true) {$Counter += '1' ;   Write-Host $Ldap_port open}
    if ((testport -hostname $Warning_ResponderIp  -port $Imap_port).open -eq $true) {$Counter += '1' ;   Write-Host $Imap_port open}
    if ((testport -hostname $Warning_ResponderIp  -port $DNS_port).open -eq $true) {$Counter += '1' ;   Write-Host $DNS_port open}
    if ((testport -hostname $Warning_ResponderIp  -port $SMB_port).open -eq $true) {$Counter += '1' ; $Smb_port_open = $true;  Write-Host $SMB_port open }
    else{$Smb_port_open = $false}
    if ((testport -hostname $Warning_ResponderIp  -port $FTP_port).open -eq $true) {$Counter += '1';  Write-Host $FTP_port open}
    if ((testport -hostname $Warning_ResponderIp  -port $Http_port).open -eq $true) {$Counter += '1' ; $http_port_open = $true;  Write-Host $Http_port open }
    else {$http_port_open = $false}
#Выборка через какой сервис будем аутентифицироваться
    #Аутентификация по SMB.
    if ($Counter -ge '6' -and $Smb_port_open -eq $true  ) {
        if((SMB_logon -ResponderIp $Warning_ResponderIp -User_for_SMB $User_SMB -P_for_SMB $Ps_user_SMB) -eq $true) {
        if ($Event_sourse_count -eq $true) {
        Write-Event -LogName Application -Source $Event_sourse  -ID 3001 -EntryType Warning -AdditionalFields $Warning_ResponderIp, $User_SMB  -Message "Responder address: $Warning_ResponderIp; User $User_SMB has sent hash by SMB; Counter: $Counter"
        Write-Host "Event created in Application log: Responder address:$Warning_ResponderIp; User hash sent $User_SMB by  SMB; Counter: $Counter " -ForegroundColor Yellow}
        else {Write-Host "Here is information that gave credits $User_SMB on SMB but could not write to the log." -ForegroundColor Red}
        }
        else{Write-Host "Error while passing hash over SMB" -ForegroundColor Yellow}
        }
    #Аутентификация по HTTP
    if ($Counter -ge '6' -and $http_port_open -eq $true -and $Smb_port_open -ne $true) {
$Http_basic_auth_Request = http_basic_auth -ResponderIp $Warning_ResponderIp -User_for_http_auth $User_http_auth -P_for_http_auth $Ps_user_http_auth 
        if($Http_basic_auth_Request.StatusCode -eq '200') {
        if ($Event_sourse_count -eq $true) {
        Write-Event -LogName Application -Source $Event_sourse  -ID 3001 -EntryType Warning -AdditionalFields $Warning_ResponderIp, $User_http_auth  -Message "Responder address: $Warning_ResponderIp; User $User_http_auth has sent hash by http basic authentication; Counter: $Counter"
        Write-Host "Event created in Application log: Responder address:$Warning_ResponderIp; user cleartext password $User_http_auth by  http basic authentication ; Counter: $Counter  " -ForegroundColor Yellow
        }
        else {Write-Host "Here is information that gave credits $User_http_auth on HTTP but could not write to the log." -ForegroundColor Red}
        }
        else {Write-Host "Error while passing hash over HTTP" -ForegroundColor Yellow}
}
    #Не отдал креды по SMB и HTTP 
    if ($Counter -ge '6' -and $http_port_open -eq $false -and $Smb_port_open -eq $false){
        Write-Event -LogName Application -Source $Event_sourse  -ID 3001 -EntryType Warning -AdditionalFields $Warning_ResponderIp, $User_SMB  -Message "Anti-responder didn't send credentials over SMB or HTTP. Responder address: $Warning_ResponderIp; Counter: $Counter"
        Write-Host "Didn't send credentials over SMB and HTTP.Responder address:$Warning_ResponderIp ; Counter: $Counter " -ForegroundColor Yellow}

#Обновляем глобал каунтер
    if($Counter -ge '6') {$Global_Counter += '1'}
}

}

if ($Global_Counter -eq '0') {Write-Host "No responder found on the network $Global_Counter" -ForegroundColor Yellow}
if ($Global_Counter -gt '0') {Write-Host "Responders found in quantity: $Global_Counter" -ForegroundColor Yellow}
}
}

#Определяю подсеть и формирую список хостов.
if ([Console]::OutputEncoding.EncodingName -match 'Криллица') {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
$Network_Interfaces = Get-NetIPConfiguration | where {$_.InterfaceDescription -notmatch 'VMware|VirtualBox|Hyper-V|Bluetooth|VPN' -and $_.IPv4Address -ne $null -and $_.NetAdapter.Status -ne 'Disconnected' -and $_.InterfaceAlias -notmatch 'VPN'} 
$Networks_and_prefix = foreach($Network_Interface in $Network_Interfaces) {

$Net_Address = Get-NetIPAddress | where {$_.InterfaceAlias -notmatch 'VMware|VirtualBox|Hyper-V' -and $_.IPAddress -eq $Network_Interface.IPv4Address }

if ($Net_Address.PrefixLength -le '24') {
$ip_range_start = $Net_Address.IPAddress+ ';' + '24'
$ip_range_start
}
elseif($Net_Address.PrefixLength -gt '24'){
$ip_range_start = $Net_Address.IPAddress+ ';' +$Net_Address.PrefixLength
$ip_range_start
}
}
$Pool_Ip =  foreach($Networks_and_prefix_one in $Networks_and_prefix) {Get-IPrange -ip (($Networks_and_prefix_one -split ';') | select -First 1 ) -cidr (($Networks_and_prefix_one -split ';') | select -Skip 1 )}


AntiResponder -User_SMB 'honeypot_smb_username' -Ps_user_SMB 'Password123' -User_http_auth 'honeypot_http_username' -Ps_user_http_auth 'Password123' -Event_sourse 'AntIResponder' -Pool_Ip_custom $Pool_Ip 
Check-DNS-Spoof -DC_Name 'non_existent_name_DC' -Domain_name 'domain.local' -Event_sourse 'AntIResponder'
Check-ARP-Spoof -iplist $Pool_Ip -Event_sourse 'AntIResponder' 
