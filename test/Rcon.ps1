cd $PSScriptRoot

$goldsource = (Get-Content ../GoldSourceRcon.cs -raw)
$source = (Get-Content ../SourceRcon.cs -raw)

Add-Type -TypeDefinition $goldsource
Add-Type -TypeDefinition $source

# GoldSourceRcon
$rcon = New-Object GoldSourceRcon('127.0.0.1', 27015, 'password')
$rcon.Command('status')

# SourceRcon
$rcon = New-Object SourceRcon('127.0.0.1', 27015, 'password', 0)
$rcon.Command('status')
# $rcon.Command('stats')
# $rcon.Command('cvarlist')
