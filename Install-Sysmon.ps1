# Licenca: GPL-3.0

[CmdletBinding()]
param (
    [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/proof-death/Sysmon/main/sysmon-config.xml"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

write-host "[+] Processo de Instalacao do Sysmon.."

$URL = "https://download.sysinternals.com/files/Sysmon.zip"
Resolve-DnsName download.sysinternals.com
Resolve-DnsName github.com
Resolve-DnsName raw.githubusercontent.com

$OutputFile = Split-Path $Url -leaf
$File = "C:\ProgramData\$OutputFile"

# Download File
write-Host "[+] baixando $OutputFile .."
$wc = new-object System.Net.WebClient
$wc.DownloadFile($Url, $File)
if (!(Test-Path $File)) { Write-Error "File $File arquivo nao existe" -ErrorAction Stop }

# Decompress if it is zip file
if ($File.ToLower().EndsWith(".zip"))
{
    # Unzip file
    write-Host "  [+] Descompactando $OutputFile ..."
    $UnpackName = (Get-Item $File).Basename
    $SysmonFolder = "C:\ProgramData\$UnpackName"
    $SysmonBinary = "$SysmonFolder\Sysmon.exe"
    expand-archive -path $File -DestinationPath $SysmonFolder
    if (!(Test-Path $SysmonFolder)) { Write-Error "$File nao foi descompactado com sucesso" -ErrorAction Stop }
}

# Downloading Sysmon Configuration
write-Host "[+] Baixando arquivo de configuracao do Sysmon..."
$SysmonFile = "C:\ProgramData\sysmon.xml"
$wc.DownloadFile($SysmonConfigUrl, $SysmonFile)
if (!(Test-Path $SysmonFile)) { Write-Error "File $SysmonFile nao existe" -ErrorAction Stop }

# Installing Sysmon
write-Host "[+] Instalando Sysmon.."
& $SysmonBinary -i C:\ProgramData\sysmon.xml -accepteula

write-Host "[+] Configurando sysmon para ini­cio automatico.."
& sc.exe config Sysmon start= auto

# Setting Sysmon Channel Access permissions
write-Host "[+] configurando as permissoes de acesso para Microsoft-Windows-Sysmon/Operational "
wevtutil set-log Microsoft-Windows-Sysmon/Operational /ca:'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)'
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational" -Name "ChannelAccess" -PropertyType String -Value "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)" -Force

write-Host "[+] Reiniciando Sysmon .."
Restart-Service -Name Sysmon -Force

write-Host "  [*] Verificado se o Sysmon esta sendo executado.."
$s = Get-Service -Name Sysmon
while ($s.Status -ne 'Running') { Start-Service Sysmon; Start-Sleep 3 }
Start-Sleep 5
write-Host "  [*] Sysmon esta sendo executado.."
Write-Host "
 ______   ______     ______     ______     ______      _____     ______     ______     ______   __  __    
/\  == \ /\  == \   /\  __ \   /\  __ \   /\  ___\    /\  __-.  /\  ___\   /\  __ \   /\__  _\ /\ \_\ \   
\ \  _-/ \ \  __<   \ \ \/\ \  \ \ \/\ \  \ \  __\    \ \ \/\ \ \ \  __\   \ \  __ \  \/_/\ \/ \ \  __ \  
 \ \_\    \ \_\ \_\  \ \_____\  \ \_____\  \ \_\       \ \____-  \ \_____\  \ \_\ \_\    \ \_\  \ \_\ \_\ 
  \/_/     \/_/ /_/   \/_____/   \/_____/   \/_/        \/____/   \/_____/   \/_/\/_/     \/_/   \/_/\/_/  TM"
