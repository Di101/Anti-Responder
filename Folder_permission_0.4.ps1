$Folder = "C:\folder\Biz"
$Items = Get-ChildItem -Path $Folder -Recurse  |  foreach FullName
$Items = $Items + $Folder

foreach ($Item in $Items ) {
$ACL = Get-Acl -Path $Item 
$ACL.SetAccessRuleProtection($true, $false) 
$ACL.SetOwner([System.Security.Principal.NTAccount]"NT AUTHORITY\SYSTEM")###########
$ACL | Set-Acl -Path $Item 



$colRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$objType =[System.Security.AccessControl.AccessControlType]::Allow
$objUser = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
    ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
$objACL = Get-ACL $Item 
$objACL.AddAccessRule($objACE)

Set-ACL $Item  $objACL 
}


foreach ($Item in $Items){
Write-Host "Dir: $Item; Owner:"(Get-Acl -Path $Item).Owner 

}



