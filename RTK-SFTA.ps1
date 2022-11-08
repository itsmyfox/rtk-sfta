function Get-FTA {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $false)]
      [String]
      $Extension
    )
  
    
    if ($Extension) {
      Write-Verbose "Get File Type Association for $Extension"
      
      $assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice" -ErrorAction SilentlyContinue).ProgId
      Write-Output $assocFile
    }
    else {
      Write-Verbose "Get File Type Association List"
  
      $assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\* |
      ForEach-Object {
        $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
        if ($progId) {
          "$($_.PSChildName), $progId"
        }
      }
      Write-Output $assocList
    }
    
  }
  
  function Set-FTA {
  
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $ProgId,
  
      [Parameter(Mandatory = $true)]
      [Alias("Protocol")]
      [String]
      $Extension,
        
      [String]
      $Icon,
  
      [switch]
      $DomainSID
    )
    
    if (Test-Path -Path $ProgId) {
      $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
    }
  
    Write-Verbose "ProgId: $ProgId"
    Write-Verbose "Extension/Protocol: $Extension"
  
    function local:Write-RequiredApplicationAssociationToasts {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $ProgId,
  
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Extension
      )
      
      try {
        $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
        [Microsoft.Win32.Registry]::SetValue($keyPath, $ProgId + "_" + $Extension, 0x0) 
        Write-Verbose ("Write Reg ApplicationAssociationToasts OK: " + $ProgId + "_" + $Extension)
      }
      catch {
        Write-Verbose ("Write Reg ApplicationAssociationToasts FAILED: " + $ProgId + "_" + $Extension)
      }
      
      $allApplicationAssociationToasts = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithList\* -ErrorAction SilentlyContinue | 
      ForEach-Object {
        "Applications\$($_.PSChildName)"
      }
  
      $allApplicationAssociationToasts += @(
        ForEach ($item in (Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithProgids -ErrorAction SilentlyContinue).PSObject.Properties ) {
          if ([string]::IsNullOrEmpty($item.Value) -and $item -ne "(default)") {
            $item.Name
          }
        })
  
      
      $allApplicationAssociationToasts += Get-ChildItem -Path HKLM:SOFTWARE\Clients\StartMenuInternet\* , HKCU:SOFTWARE\Clients\StartMenuInternet\* -ErrorAction SilentlyContinue | 
      ForEach-Object {
      (Get-ItemProperty ("$($_.PSPath)\Capabilities\" + (@("URLAssociations", "FileAssociations") | Select-Object -Index $Extension.Contains("."))) -ErrorAction SilentlyContinue).$Extension
      }
      
      $allApplicationAssociationToasts | 
      ForEach-Object { if ($_) {
          if (Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts $_"_"$Extension -Value 0 -Type DWord -ErrorAction SilentlyContinue -PassThru) {
            Write-Verbose  ("Write Reg ApplicationAssociationToastsList OK: " + $_ + "_" + $Extension)
          }
          else {
            Write-Verbose  ("Write Reg ApplicationAssociationToastsList FAILED: " + $_ + "_" + $Extension)
          }
        } 
      }
  
    }
  
    function local:Update-RegistryChanges {
      $code = @'
      [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
      private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
      public static void Refresh() {
          SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
      }
'@ 
  
      try {
        Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
      }
      catch {}
  
      try {
        [SHChange.Notify]::Refresh()
      }
      catch {} 
    }
    
  
    function local:Set-Icon {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $ProgId,
  
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Icon
      )
  
      try {
        $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
        [Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon) 
        Write-Verbose "Write Reg Icon OK"
        Write-Verbose "Reg Icon: $keyPath"
      }
      catch {
        Write-Verbose "Write Reg Icon FAILED"
      }
    }
  
  
    function local:Write-ExtensionKeys {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $ProgId,
  
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Extension,
  
        [Parameter( Position = 2, Mandatory = $True )]
        [String]
        $ProgHash
      )
      
  
      function local:Remove-UserChoiceKey {
        param (
          [Parameter( Position = 0, Mandatory = $True )]
          [String]
          $Key
        )
  
        $code = @'
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Win32;
        
        namespace Registry {
          public class Utils {
            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
        
            [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
            private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);
    
            public static void DeleteKey(string key) {
              UIntPtr hKey = UIntPtr.Zero;
              RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
              RegDeleteKey((UIntPtr)0x80000001u, key);
            }
          }
        }
'@
    
        try {
          Add-Type -TypeDefinition $code
        }
        catch {}
  
        try {
          [Registry.Utils]::DeleteKey($Key)
        }
        catch {} 
      } 
  
      
      try {
        $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
        Remove-UserChoiceKey $keyPath
      }
      catch {
        Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
      }
    
  
      try {
        $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
        [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
        Write-Verbose "Write Reg Extension UserChoice OK"
      }
      catch {
        throw "Write Reg Extension UserChoice FAILED"
      }
    }
  
  
    function local:Write-ProtocolKeys {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $ProgId,
  
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Protocol,
  
        [Parameter( Position = 2, Mandatory = $True )]
        [String]
        $ProgHash
      )
        
  
      try {
        $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
        Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
        Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
      
      }
      catch {
        Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
      }
    
  
      try {
        $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
        [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
        [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
        Write-Verbose "Write Reg Protocol UserChoice OK"
      }
      catch {
        throw "Write Reg Protocol UserChoice FAILED"
      }
      
    }
  
    
    function local:Get-UserExperience {
      [OutputType([string])]
      $hardcodedExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
      $userExperienceSearch = "User Choice set via Windows User Experience"
      $userExperienceString = ""
      $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
      $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      $binaryReader = New-Object System.IO.BinaryReader($fileStream)
      [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
      $fileStream.Close()
      $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
      $position1 = $dataString.IndexOf($userExperienceSearch)
      $position2 = $dataString.IndexOf("}", $position1)
      try {
        $userExperienceString = $dataString.Substring($position1, $position2 - $position1 + 1)
      }
      catch {
        $userExperienceString = $hardcodedExperience
      }
      Write-Output $userExperienceString
    }
    
  
    function local:Get-UserSid {
      [OutputType([string])]
      $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
      Write-Output $userSid
    }
  
    function local:Get-UserSidDomain {
      if (-not ("System.DirectoryServices.AccountManagement" -as [type])) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
      }
      [OutputType([string])]
      $userSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.Value.ToLower()
      Write-Output $userSid
    }
  
    function local:Get-HexDateTime {
      [OutputType([string])]
  
      $now = [DateTime]::Now
      $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
      $fileTime = $dateTime.ToFileTime()
      $hi = ($fileTime -shr 32)
      $low = ($fileTime -band 0xFFFFFFFFL)
      $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
      Write-Output $dateTimeHex
    }
    
    function Get-Hash {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [string]
        $BaseInfo
      )
  
  
      function local:Get-ShiftRight {
        [CmdletBinding()]
        param (
          [Parameter( Position = 0, Mandatory = $true)]
          [long] $iValue, 
              
          [Parameter( Position = 1, Mandatory = $true)]
          [int] $iCount 
        )
      
        if ($iValue -band 0x80000000) {
          Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
        }
        else {
          Write-Output  ($iValue -shr $iCount)
        }
      }
      
  
      function local:Get-Long {
        [CmdletBinding()]
        param (
          [Parameter( Position = 0, Mandatory = $true)]
          [byte[]] $Bytes,
      
          [Parameter( Position = 1)]
          [int] $Index = 0
        )
      
        Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
      }
      
  
      function local:Convert-Int32 {
        param (
          [Parameter( Position = 0, Mandatory = $true)]
          [long] $Value
        )
      
        [byte[]] $bytes = [BitConverter]::GetBytes($Value)
        return [BitConverter]::ToInt32( $bytes, 0) 
      }
  
      [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
      $bytesBaseInfo += 0x00, 0x00  
      
      $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
      [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
      
      $lengthBase = ($baseInfo.Length * 2) + 2 
      $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
      $base64Hash = ""
  
      if ($length -gt 1) {
      
        $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
          R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
        }
      
        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1
      
        while ($map.COUNTER) {
          $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
          $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
          $map.PDATA = $map.PDATA + 8
          $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
          $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
          $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
          $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
          $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
          $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
          $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
          $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
          $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
          $map.CACHE = ([long]$map.OUTHASH2)
          $map.COUNTER = $map.COUNTER - 1
        }
  
        [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 0)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 4)
      
        $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
          R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
        }
      
        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1
  
        while ($map.COUNTER) {
          $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
          $map.PDATA = $map.PDATA + 8
          $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
          $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
          $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
          $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
          $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
          $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
          $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
          $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
          $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
          $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
          $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
          $map.CACHE = ([long]$map.OUTHASH2)
          $map.COUNTER = $map.COUNTER - 1
        }
      
        $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 8)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 12)
      
        [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
        $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
      
        $buffer = [BitConverter]::GetBytes($hashValue1)
        $buffer.CopyTo($outHashBase, 0)
        $buffer = [BitConverter]::GetBytes($hashValue2)
        $buffer.CopyTo($outHashBase, 4)
        $base64Hash = [Convert]::ToBase64String($outHashBase) 
      }
  
      Write-Output $base64Hash
    }
  
    Write-Verbose "Getting Hash For $ProgId   $Extension"
    If ($DomainSID.IsPresent) { Write-Verbose  "Use Get-UserSidDomain" } Else { Write-Verbose  "Use Get-UserSid" } 
    $userSid = If ($DomainSID.IsPresent) { Get-UserSidDomain } Else { Get-UserSid } 
    $userExperience = Get-UserExperience
    $userDateTime = Get-HexDateTime
    Write-Debug "UserDateTime: $userDateTime"
    Write-Debug "UserSid: $userSid"
    Write-Debug "UserExperience: $userExperience"
  
    $baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
    Write-Verbose "baseInfo: $baseInfo"
  
    $progHash = Get-Hash $baseInfo
    Write-Verbose "Hash: $progHash"
    
    Write-RequiredApplicationAssociationToasts $ProgId $Extension
  
    if ($Extension.Contains(".")) {
      Write-Verbose "Write Registry Extension: $Extension"
      Write-ExtensionKeys $ProgId $Extension $progHash
  
    }
    else {
      Write-Verbose "Write Registry Protocol: $Extension"
      Write-ProtocolKeys $ProgId $Extension $progHash
    }
  
     
    if ($Icon) {
      Write-Verbose  "Set Icon: $Icon"
      Set-Icon $ProgId $Icon
    }
  
    Update-RegistryChanges 
  
  }
  
  function Get-PTA {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $false)]
      [String]
      $Protocol
    )
  
    if ($Protocol) {
      Write-Verbose "Get Protocol Type Association for $Protocol"
  
      $assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice" -ErrorAction SilentlyContinue).ProgId
      Write-Output $assocFile
    }
    else {
      Write-Verbose "Get Protocol Type Association List"
  
      $assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\* |
      ForEach-Object {
        $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
        if ($progId) {
          "$($_.PSChildName), $progId"
        }
      }
      Write-Output $assocList
    }
  }
  
  function Set-PTA {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $ProgId,
  
      [Parameter(Mandatory = $true)]
      [String]
      $Protocol,
        
      [String]
      $Icon
    )
  
    Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon
  }
  # Если на открытие файлов .pdf стоит Edge, то меняется на Adobe Acrobat reader. В другом случае действия производиться не будут.
  
  $pdfReaderGet1 = Test-Path -Path 'C:\Program Fi*\Adobe\Acro*\Acro*\Acro*.exe'
  $pdfReaderGet2 = Test-Path -Path 'C:\Program Fi*\Adobe\Acro*\Read*\Acro*.exe'
  $pdfReaderGet3 = Test-Path -Path 'C:\Program Fi*\PDF24\pdf24*.exe'
  $calcTrue = "True"
  $msEdgePdf = "MSEdgePDF"
  $commandPdf = Get-FTA .pdf
  $s3 = "False"
  
       function Analyze( $p, $f) {
           Get-ItemProperty $p |ForEach-Object {
              if ($_.DisplayName -like "*Adobe acrobat*") {
                   [PSCustomObject]@{ 
                           Name = $_.DisplayName -like "*Adobe acrobat*";
                    }
              } 
           }
       }
          
       $s = @() 
       $s += Analyze 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' 64
       $s += Analyze 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' 32
       #$s | select-object -Property Name -ExpandProperty name
       if ($s.name) {
        if (($pdfReaderGet1 -eq $calcTrue) -or ($pdfReaderGet2 -eq $calcTrue)) {
          Write-Host "Acrobat found! Complete! - Test passed, Acrobat present."
          if ($s.name -eq $calcTrue) {
              Write-Host "Acrobat found! Complete! - Test passed, Acrobat present."
                  if ($commandPdf -eq $msEdgePdf) {
                          Write-Host "Changing to Acrobat.Document.DC"
                          $variable = Set-FTA 'Acrobat.Document.DC' '.pdf'
                          Return($choice);
              } else {
                          Write-Host "not Edge - I'm not doing anything"
              } 
            }
          }	 
        }
  
       function Analyze2( $p, $f) {
           Get-ItemProperty $p |ForEach-Object {
              if ($_.DisplayName -like "*PDF24*") {
                   [PSCustomObject]@{ 
                           Name = $_.DisplayName -like "*PDF24*";
                    }
              } 
           }
       }
          
       $s2 = @() 
       $s2 += Analyze2 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' 64
       $s2 += Analyze2 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' 32
       #$s2 | select-object -Property Name -ExpandProperty name
       if ($s2.name) {
          if ($pdfReaderGet3 -eq $calcTrue) {
            Write-Host "PDF24 found! Complete! - Verification passed, PDF24 present."
            if ($s2.name -eq $calcTrue) {
              Write-Host "PDF24 found! Complete! - Verification passed, PDF24 present."
                  if ($commandPdf -eq $msEdgePdf) {
                          Write-Host "Change to PDF24.Reader"
                          $variable2 = Set-FTA 'PDF24.Reader' '.pdf'
                          Return($choice);
                  } else {
                      Write-Host "not Edge - I'm not doing anything"
                  } 
                }
            }
        }
      
       if ($s.name -eq $s3) {
          Write-Host "There are programs installed"
          } elseif ($s2.name -eq $s3) {
           Write-Host "There are programs installed 2"
              } else {
              Write-Host "There are no Adobe Acrobat and PDF24 programs installed, I install the Yandex program by default"
              $variable3 = Set-FTA 'YandexPDF' '.pdf'
      }
      
  $choice

# Если на открытие файлов .htm .html .xhtml .url http https стоит Edge, то меняется на Yandex Браузер. В другом случае действия производиться не будут.
  
$htmYandex = Get-FTA .htm
$htmlYandex = Get-FTA .html
$xhtmlYandex = Get-FTA .xhtml
$urlYandex = Get-FTA .url
$httpYYandex = Get-PTA http
$httpYandex = Get-PTA http
$httpsYandex = Get-PTA https
$calcEdge = "MSEdgeHTM"
$http = "http"

Write-Host "$htmYandex"
Write-Host "$htmlYandex"
Write-Host "$xhtmlYandex"
Write-Host "$urlYandex"
Write-Host "$httpYYandex"
Write-Host "$httpYandex"
Write-Host "$httpsYandex"

if ($htmYandex -eq $calcEdge) {
	Write-Host "The .htm file has edge by default. Change to Yandex."
	$changeYandexHtm = Set-FTA 'YandexHTML' '.htm'
} elseif ($htmlYandex -eq $calcEdge) {
	Write-Host "The .html file has edge by default. Change to Yandex."
	$changeYandexHtml = Set-FTA 'YandexHTML' '.html'
} elseif ($xhtmlYandex -eq $calcEdge) {
	Write-Host "The .xhtml file has edge by default. Change to Yandex."
	$changeYandexXhtml = Set-FTA 'YandexHTML' '.xhtml'
} elseif ($urlYandex -eq $calcEdge) {
	Write-Host "The .url file has edge by default. Change to Yandex."
	$changeYandexUrl = Set-FTA 'YandexHTML' '.url'
} elseif ($httpYYandex -eq $http) {
	Write-Host "The http format has edge by default. Change to Yandex."
	$changeYandexHttp = Set-PTA 'YandexHTML' 'http'
} elseif ($httpYandex -eq $calcEdge) {
	Write-Host "The http format has edge by default. Change to Yandex."
	$changeYandexHttp2 = Set-PTA 'YandexHTML' 'http'
} elseif ($httpsYandex -eq $calcEdge) {
	Write-Host "The https format has edge by default. Change to Yandex."
	$changeYandexHttps = Set-PTA 'YandexHTML' 'https'
} else {
	Write-Host "No action required."
}

Write-Host "Complete"

  # SIG # Begin signature block
  # MIIPaAYJKoZIhvcNAQcCoIIPWTCCD1UCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
  # gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
  # AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlz9mJ3LVxP8aUDwZRZdwNMMF
  # bImgggzVMIIGTjCCBDagAwIBAgITTwAAB6r7HLyYxe8w1QABAAAHqjANBgkqhkiG
  # 9w0BAQsFADBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZ
  # FgNlcGsxFzAVBgNVBAMTDkVQSyBJc3N1aW5nIENBMB4XDTIyMDQyMjEzMTgzM1oX
  # DTI3MDQyMTEzMTgzM1owITEfMB0GA1UEAwwWaS5hLnpha2hhcm92QGVway5sb2Nh
  # bDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkjypb2uAt53tRZgjW0
  # 0p3w+ulu13GhMmGJHg43kcosEDYmJpNG7tx6PbnbXpFDMdvPTueYi9RN4z5C/aa6
  # EdE6g+TVMPPMwhD05oRqrm4gUZgz+kspSnm9YPaJwUpkmYmcVmrJr+6FEkM8DTxd
  # LMWtCy75H0q8Y/CPVACiwFmK2Wb9xEijU5cLQ/2yZW3iwVev4P4UUbKm3XEVqIsu
  # LxVcgxNUD8TkgDp8biJqkjtcTJ9sBWaWvTv7JO65KCDdR/I8Gj8hoPHtdS5mfPRi
  # uCurZgJblah7WCzgeeSP+z+E6LOnhwpHrl745e3GjeIOtIu4+hH3ao25ZZHJlrnE
  # dSUCAwEAAaOCAlkwggJVMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIHvqnKB
  # qqQLhuGND4TiiSmEo7MMgSaDlpR4hde4egIBZAIBCDATBgNVHSUEDDAKBggrBgEF
  # BQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcD
  # AzAdBgNVHQ4EFgQUEQAZVKzatfEanIsUcZdklsFkeZAwMQYDVR0RBCowKKAmBgor
  # BgEEAYI3FAIDoBgMFmkuYS56YWtoYXJvdkBlcGsubG9jYWwwHwYDVR0jBBgwFoAU
  # HCrTmSlz/z4rX2EaS/G+V6VwhVAwgYkGA1UdHwSBgTB/MH2ge6B5hkNodHRwOi8v
  # SVFEQy1WTS1DQS0wMi5lcGsubG9jYWwvQ2VydEVucm9sbC9FUEslMjBJc3N1aW5n
  # JTIwQ0EoMSkuY3JshjJodHRwOi8vY2RwLmVway5sb2NhbC9wa2kvRVBLJTIwSXNz
  # dWluZyUyMENBKDEpLmNybDCB0QYIKwYBBQUHAQEEgcQwgcEwZwYIKwYBBQUHMAKG
  # W2h0dHA6Ly9JUURDLVZNLUNBLTAyLmVway5sb2NhbC9DZXJ0RW5yb2xsL0lRREMt
  # Vk0tQ0EtMDIuZXBrLmxvY2FsX0VQSyUyMElzc3VpbmclMjBDQSgxKS5jcnQwVgYI
  # KwYBBQUHMAKGSmh0dHA6Ly9jZHAuZXBrLmxvY2FsL3BraS9JUURDLVZNLUNBLTAy
  # LmVway5sb2NhbF9FUEslMjBJc3N1aW5nJTIwQ0EoMSkuY3J0MA0GCSqGSIb3DQEB
  # CwUAA4ICAQBWHET+8Vd8jok20npiifrq3W6WCd8xkxo7qADnE6xfP7ZnlMj5+sXD
  # WqsXxG94f/aM05r+yW94EJSMMy58b909tJr6kSBBoGg8/ROdG/UhJb+TU1JVYDFO
  # e2NV59+TRhnwbBoNT7vm8vpix41qPk9+N8tC+Abp9BrNZpOQjUxtf8030US31SVJ
  # zhdzhkM5BwEU65kbctGZFHFX/8GnlkCV6/DDKnw2+OlVQOA3Yw9zhRslNBL42Yzp
  # agG/dx8ott+1cHzdgi56vSqfjHaij1e7rMGwclIIUnY5L3OAmuUfO3RI16GWqMev
  # 7XPaNd/j72jpALay2zimeCi+6015drPZ+2TfniX42Qxrh0CNmJ2hzVgW5697Ertq
  # FdCV/kLGtldMeR9s5YDY7mHrdsPrM6bGKYPTjQ6BAE9twcPUk5OryTUFIWMDxo7I
  # vtLsjdHBB2e6/1RCFqijZVdfJkrDLkQNqxBz+984aTeVUBxCKHdMEz9lFgC2SAik
  # ZBeXa36+HZ3V9mCLbda+LqHe7hZVXFP1vW95u8YPC2w+MTSIyBVjYybjy96WvHbU
  # QnCUGpCQuEmttT2aOFC2qKWA3njOir4R6U7nODoG7p3sid7N3l1Vd9TsUpaNQv2S
  # oWyzJ0DlRTMjcstG/pn4V5g8mwZ0lYi/P2iaIl1Hagf6HOdWI50LvjCCBn8wggRn
  # oAMCAQICE20AAAAEnTWjQIaVGfsAAAAAAAQwDQYJKoZIhvcNAQELBQAwFjEUMBIG
  # A1UEAxMLRVBLIFJvb3QgQ0EwHhcNMjEwMjI0MTIzMjE3WhcNMzYwMjI0MTAwODAy
  # WjBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNlcGsx
  # FzAVBgNVBAMTDkVQSyBJc3N1aW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
  # MIICCgKCAgEAyl14gp4L6Sdnuv/7rt/PFFFDVdpNqednuf56xW6pneQB615JjYfI
  # kc2i9VaXgoWkMcy7fDukDf6g7oy17JvWUKxEDGAeGyu02fM0if+dKe9PccxUkJDQ
  # BmLTDE6OxIHnOEHeYcuOBSnIGAxVaoB0QhMidtU0D6XXpXJvxxmM4JKXFPjvFga+
  # 3FClJkRj5KcXly69DHDJoLbJJ8+QRVM2xoXoRdddmeVYK8TCJnRUOMcDdlyiTYBG
  # VHVdd3d5GpKp5Y2259GtDP0ZIemlSLUVY7hxNnSjZT3IWwkATXAPWv3dfZw3XwUO
  # 4h5e4xjdP5VQbmHfN1J61GlHRc+HMtA3CnwwRLTYtrzd0sYfQH8ASBJJURrJlizQ
  # VjY3oZ9B3oLbjP96nM1AhJBcFzJpKwJdreujOESJR90jKxQnEOUcvGaVPLePpOi9
  # iQoY2pEFWhSuDBGZkbxHqyiCjKPUxmASP/cFYMZSneorJNc4GzSYmlO913LWVsFj
  # ni8O9UBXzP6XOPbR5/WVfWK11goBd7nMkyrgJlilj1cRBSIS7uCthKgvw1mH8WPN
  # jr8xrvACmGk2S5D3SDUOqhnK2hKKb2Wm9+qjMzKaXv8jsbpqh4yWbd4uvELt7xWE
  # je9sY708JH2DRrZdprlNNMB5OUA/bDVF60Qe5Jn2O9QIaoq34zNPjbcCAwEAAaOC
  # AZUwggGRMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFMmBY9dc
  # zTnZCFrXAxdQv5dApZv2MB0GA1UdDgQWBBQcKtOZKXP/PitfYRpL8b5XpXCFUDBG
  # BgNVHSAEPzA9MDsGBFUdIAAwMzAxBggrBgEFBQcCARYlaHR0cDovL2NkcC5lcGsu
  # bG9jYWwvcGtpL2Vway1jcHMuaHRtbDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
  # QTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQf0Xr/
  # XZ/Y1NJrTg9FsSGgXew6NTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY2RwLmVw
  # ay5sb2NhbC9wa2kvRVBLJTIwUm9vdCUyMENBLmNybDBWBggrBgEFBQcBAQRKMEgw
  # RgYIKwYBBQUHMAKGOmh0dHA6Ly9jZHAuZXBrLmxvY2FsL3BraS9JUURDLVZNLUNB
  # LTAxX0VQSyUyMFJvb3QlMjBDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAA32gS4k
  # eXKLEWPxtVULnJ9+iTfSyN/gTvFjdTSq5lsbdcXfNDuxjmJXEGJGhwy0uj5903fp
  # +wuiT0k9SjKJN86c+Qp6t/DtCNS+nddUiya8e1Lphrtb2AqujMAnNBPCSgfYE79r
  # g509zbn5FZxPor5ixmNDqnwwAjArkmDM3pjBoHaaRHx1GlRxlhIY7FSo+ivw1sQn
  # i64Pq2rkvxn8Z9Gj8lMk5lJMSjh8WVX6Mt9aRPp0rPpUdIN74yaCZXvHcO0lC2p/
  # /eda8VFLcXGFeJf3dqfMvZOp5/Vd062iOlMtXStpGvD5+D/x3jPNonfsTUmbJJMP
  # H51c9rIw0c5+BXkTcVsrm7AIBPmpdvtl8a7SDso4uEXJ6EznFtcNR53dLDhIh9zs
  # hZwLR8NAwbQsRHhEYDWZ9iQpIg6tPKSzczW455DE+t9lMsEyoObTqGrAoaKz+FtD
  # d2k8rrfDmju54Mtoq8Vc5Gjm8GzI9qGWpiwSM3mMM2nKMIRBCKFf/hI1OphDeNOw
  # brF2cBL6f53tXM1HACRHE0bT/w5eZGbZtWcx63FP/toqLjkY/dPO/2rNl6jtTwmi
  # GiER3DRFxSMnu6YdR6tcdptJzlqF3V1W5QhYhxZDJ1X7eRs6gd7XsUcsfKiTHxrF
  # uiHbjAHnspaPDhJ/5iYO/EZAYkgkblRQN7BIMYIB/TCCAfkCAQEwXDBFMRUwEwYK
  # CZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNlcGsxFzAVBgNVBAMT
  # DkVQSyBJc3N1aW5nIENBAhNPAAAHqvscvJjF7zDVAAEAAAeqMAkGBSsOAwIaBQCg
  # eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
  # AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
  # BDEWBBQWixcDjSFi4ejcVMbFY7Y2lRDEXDANBgkqhkiG9w0BAQEFAASCAQBWLH7N
  # XdYRi/aYpdn6iVkX3g2RG3F+b+NEkScQlpt2QKfk5s5NflBF7daNiPeYEq82S4ys
  # aFygRjG6IztYtaglXXWbcr4IcmrZ4PZUXNcpH/7/rTgYXxXsMOu5IeBdsvl/DUg+
  # Uyv486YlQD1QshDxYA6teWIS68I710r+vyo1j7l3mRt/IkJ90lakh6GGDfLmV638
  # HrUefhfTAXw3wv0z1Ftnl35ec3rq73s6wD2cyLUk28r/fAeakELEFj8wi9VT4DgD
  # epy5IEZucX919Fp8qMDZ182EKHV76zbVhSgbUxdxEgNUJXYwlvvoA9yybOrbNMia
  # 9uhMjQ90QFpKaFM6
  # SIG # End signature block
  