$w = New-Object -ComObject WScript.Shell
$lnkPath = "C:\Users\chris\OneDrive\Desktop\FileAnomalyScanner.lnk"
$s = $w.CreateShortcut($lnkPath)
Write-Output ("Old TargetPath: " + $s.TargetPath)
Write-Output ("Old IconLocation: " + $s.IconLocation)

$target = "C:\Users\chris\OneDrive\Desktop\Personal Projects\file-anomaly-scanner\FileAnomalyScanner.exe"
$s.TargetPath = $target
$s.WorkingDirectory = "C:\Users\chris\OneDrive\Desktop\Personal Projects\file-anomaly-scanner"
$s.IconLocation = "C:\Users\chris\OneDrive\Desktop\Personal Projects\file-anomaly-scanner\backend\app.ico,0"
$s.Save()

Write-Output "Shortcut updated successfully!"
Write-Output ("New IconLocation: " + $s.IconLocation)
