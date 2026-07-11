param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Output = ".\windows-events.json",

    [int[]]$EventId = @(4624, 4625, 4672, 4688, 4720, 7045)
)

$records = Get-WinEvent -Path $Path -ErrorAction Stop |
    Where-Object { $EventId -contains $_.Id } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) {
                $eventData[$node.Name] = [string]$node.'#text'
            }
        }

        [PSCustomObject]@{
            EventID    = $_.Id
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
            Computer   = $_.MachineName
            EventData  = $eventData
        }
    }

$records | ConvertTo-Json -Depth 6 | Set-Content -Path $Output -Encoding UTF8
Write-Host "Exported $($records.Count) event(s) to $Output"
