# run: => powershell -executionpolicy bypass -File .\priv_esc_sscan.ps1
echo "#######################"
echo "Operating System Check"
echo "######################`n"

echo "Sys Info"
echo "--------"
systeminfo | findstr /i "os"
echo "`n"

echo "Domain Controller"
echo "-----------------"
Get-ChildItem Env: | ft Key,Value | findstr /i "username"
echo "`n"

echo "Connected Drivers"
echo "-----------------"
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"} | ft Name,Root
echo "`n"


echo "#########"
echo "User Info"
echo "#########`n"

echo "Last Logon && List of Users"
echo "---------------------------"
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
echo "`n"

echo "Group Associated"
echo "----------------"
Get-LocalGroupMember Administrators | ft Name,PrincipleSource
echo "`n"

echo "Registry Autologon"
echo "------------------"
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
echo "`n"

echo "Credential Manager"
echo "------------------"
$USER = $env:UserName
Get-ChildItem -Hidden C:\Users\$USER\AppData\Local\Microsoft\Credentials\ | ft Mode,LastWriteTime,Length,Name
Get-ChildItem -Hidden C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
echo "`n"


echo "#################################"
echo "Programs, Processes, and Services"
echo "#################################`n"

echo "Installed Software?"
echo "------------------"
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
echo "`n"

echo "Folder Permissions"
echo "------------------"
icacls "C:\Program Files\*" | findstr "Everyone"
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try {
  Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN'}
} catch{}}
echo "`n"

echo "Running Services: (File System Drivers)"
echo "------------------"
echo "Process"
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
echo "Service"
Get-Service
Get-WmiObject -Query "Select * from Win32_Process" | where {
  $_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={
    $_.GetOwner().User}} | ft -AutoSize
echo "`n"
