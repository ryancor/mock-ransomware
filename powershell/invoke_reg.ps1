$find_reg = Get-Item -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | findstr /i ransomware

if($find_reg -like '*pwn*') {
  $pos = $find_reg.IndexOf(":")
  $new_path_left = $find_reg.Substring(0, $pos)
  $new_path_right = $find_reg.Substring($pos+1)

  echo "Registry key as been added!"
  echo "Value: $new_path_left   Location: $new_path_right`n"
} else {
  echo "Something went wrong with adding keys`n"
}
