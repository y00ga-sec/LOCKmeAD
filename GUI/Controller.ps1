# ============================================================================
# Connection Dialog (shown at startup when the host is not domain-joined)
# ============================================================================

function Show-GUIConnectionDialog {
    <#
    .SYNOPSIS
        Prompts for a target domain controller and credential when the host running
        the GUI is not domain-joined (or a domain controller couldn't be located
        automatically).
    .PARAMETER DefaultServer
        Pre-fills the domain controller field, so a saved profile whose credential no longer
        authenticates does not also cost the operator the server name.
    .OUTPUTS
        PSCustomObject with Server/Credential (as Resolve-LOCKmeADConnection returns),
        or $null if the user cancelled.
    #>
    param([string]$DefaultServer = '')

    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Connect to Active Directory" Width="440" SizeToContent="Height"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="Connect to Active Directory" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,4"/>
        <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#666666" Margin="0,0,0,16"
                   Text="This host is not domain-joined (or no domain controller could be located automatically). Provide a target domain controller and domain credentials to continue."/>

        <TextBlock Text="Domain Controller (hostname or IP)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox Name="ConnServer" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <TextBlock Text="Username (DOMAIN\user or user@domain)" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="ConnUsername" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <TextBlock Text="Password" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <PasswordBox Name="ConnPassword" FontSize="13" Padding="8,6"/>

        <CheckBox Name="ConnRemember" Content="Remember this connection on this computer"
                   FontSize="12" Margin="0,14,0,0"/>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnConnect" Content="Connect" Width="100" Padding="0,8"
                    Background="#0078D4" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)

    $txtServer   = $dlg.FindName("ConnServer")
    $txtUsername = $dlg.FindName("ConnUsername")
    $txtPassword = $dlg.FindName("ConnPassword")
    $chkRemember = $dlg.FindName("ConnRemember")
    $btnConnect  = $dlg.FindName("BtnConnect")
    $btnCancel   = $dlg.FindName("BtnCancel")

    # Enter validates from any field, Esc cancels. IsDefault/IsCancel are WPF's own mechanism for
    # this, so it keeps working inside the PasswordBox, which swallows most key handlers.
    $btnConnect.IsDefault = $true
    $btnCancel.IsCancel   = $true

    $txtServer.Text = $DefaultServer
    # Focus lands on the first field still empty, so a pre-filled server is not in the way.
    $dlg.Add_Loaded({
        if ([string]::IsNullOrWhiteSpace($txtServer.Text))        { [void]$txtServer.Focus() }
        elseif ([string]::IsNullOrWhiteSpace($txtUsername.Text))  { [void]$txtUsername.Focus() }
        else                                                      { [void]$txtPassword.Focus() }
    }.GetNewClosure())

    $dlg.Tag = $null
    $btnConnect.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtServer.Text)) {
            [System.Windows.MessageBox]::Show("Domain controller is required.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtUsername.Text)) {
            [System.Windows.MessageBox]::Show("Username is required.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $secure = $txtPassword.SecurePassword
        $cred = [PSCredential]::new($txtUsername.Text, $secure)

        # Resolve-LOCKmeADConnection throws when the account is not a Domain Admin. Catching it
        # here keeps the dialog open so the operator can simply retype credentials, instead of
        # letting the exception unwind and kill the launcher.
        try {
            $conn = Resolve-LOCKmeADConnection -Server $txtServer.Text.Trim() -Credential $cred -Remember:$chkRemember.IsChecked
        }
        catch {
            [System.Windows.MessageBox]::Show($_.Exception.Message, "Connection refused",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
            $txtPassword.Clear()
            [void]$txtPassword.Focus()
            return
        }

        # Schema Admins is not raised here on purpose: it only matters to ExtendLAPSSchema, and
        # that task carries its own notice on the Hardening tab.
        $dlg.Tag = $conn
        $dlg.Close()
    }.GetNewClosure())
    $btnCancel.Add_Click({ $dlg.Close() }.GetNewClosure())

    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-WPFBrush([string]$hex) {
    [System.Windows.Media.BrushConverter]::new().ConvertFromString($hex)
}

function Write-Console {
    param([string]$Message, [string]$Level = "Info")
    $colorMap = @{ Info = "#58D68D"; Success = "#58D68D"; Warning = "#F4D03F"; Error = "#EC7063" }
    $color = $colorMap[$Level]
    if (-not $color) { $color = "#CCCCCC" }

    $script:Window.Dispatcher.Invoke([Action]{
        $doc = $UI.ConsoleOutput.Document
        $para = New-Object System.Windows.Documents.Paragraph
        $para.Margin = [System.Windows.Thickness]::new(0)
        $timestamp = Get-Date -Format "HH:mm:ss"
        $run = New-Object System.Windows.Documents.Run("[$timestamp] [$Level] $Message")
        $run.Foreground = Get-WPFBrush $color
        [void]$para.Inlines.Add($run)
        [void]$doc.Blocks.Add($para)
        $UI.ConsoleOutput.ScrollToEnd()
    })
}

function Write-ConsoleUI {
    param([string]$Message, [string]$Level = "Info")
    $doc = $UI.ConsoleOutput.Document
    $para = New-Object System.Windows.Documents.Paragraph
    $para.Margin = [System.Windows.Thickness]::new(0)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colorMap = @{ Info = "#87CEEB"; Success = "#58D68D"; Warning = "#F4D03F"; Error = "#EC7063" }
    $color = $colorMap[$Level]; if (-not $color) { $color = "#CCCCCC" }
    $run = New-Object System.Windows.Documents.Run("[$timestamp] [$Level] $Message")
    $run.Foreground = Get-WPFBrush $color
    $para.Inlines.Add($run)
    $doc.Blocks.Add($para)
    $UI.ConsoleOutput.ScrollToEnd()
}

function New-CopyDNButton([string]$dnText) {
    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = [char]0xE8C8  # Copy icon
    $btn.FontFamily = New-Object System.Windows.Media.FontFamily("Segoe MDL2 Assets")
    $btn.FontSize = 11
    $btn.Background = Get-WPFBrush "Transparent"
    $btn.BorderThickness = [System.Windows.Thickness]::new(0)
    $btn.Cursor = "Hand"
    $btn.Foreground = Get-WPFBrush "#999"
    $btn.ToolTip = "Copy DN to clipboard"
    $btn.Padding = [System.Windows.Thickness]::new(4, 0, 4, 0)
    $btn.VerticalAlignment = "Center"
    $btn.Margin = [System.Windows.Thickness]::new(6, 0, 0, 0)
    $btn.Tag = $dnText
    $btn.Add_Click({
        [System.Windows.Clipboard]::SetText($this.Tag)
    })
    return $btn
}

function Count-TieringOUs($nodes) {
    $count = 0
    foreach ($node in $nodes) {
        $count++
        if ($node.Children) { $count += Count-TieringOUs $node.Children }
    }
    return $count
}

# ============================================================================
# Config Management
# ============================================================================

function Load-AllConfigs {
    foreach ($module in @('Hardening', 'GPO', 'Tiering', 'RBAC', 'PSO', 'Silo', 'JIT')) {
        $path = $script:ConfigPaths[$module]
        if (Test-Path $path) {
            $script:Configs[$module] = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
        }
    }
}

function Save-AllConfigs {
    # Hardening: read toggle states and parameters back into config
    if ($script:Configs.Hardening) {
        for ($i = 0; $i -lt $script:HardeningToggles.Count; $i++) {
            $script:Configs.Hardening.Tasks[$i].Enabled = [bool]$script:HardeningToggles[$i].IsChecked
        }
        foreach ($key in $script:HardeningParamControls.Keys) {
            $parts = $key -split '\.'
            $taskIdx = [int]$parts[0]
            $paramName = $parts[1]
            $control = $script:HardeningParamControls[$key]
            $value = if ($control -is [System.Windows.Controls.CheckBox]) {
                [bool]$control.IsChecked
            } elseif ($control -is [System.Windows.Controls.TextBox]) {
                if ($control.Tag -eq "array") {
                    $t = $control.Text
                    if ([string]::IsNullOrWhiteSpace($t)) { ,@() }
                    else { ,@($t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) }
                } else {
                    $text = $control.Text
                    if ($text -match '^\d+$') { [int]$text } else { $text }
                }
            } else { $control.Text }
            $script:Configs.Hardening.Tasks[$taskIdx].Parameters.$paramName = $value
        }
        $script:Configs.Hardening | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.Hardening -Encoding UTF8
    }

    # GPO: read toggle states, link targets, and filtering OU back into config
    if ($script:Configs.GPO) {
        for ($i = 0; $i -lt $script:GPOToggles.Count; $i++) {
            $script:Configs.GPO.GPOs[$i].Enabled = [bool]$script:GPOToggles[$i].IsChecked
            if ($script:GPONameControls.ContainsKey($i)) {
                $newName = $script:GPONameControls[$i].Text.Trim()
                if (-not [string]::IsNullOrWhiteSpace($newName)) {
                    $script:Configs.GPO.GPOs[$i].Name = $newName
                }
            }
        }
        foreach ($key in $script:GPOLinkControls.Keys) {
            $idx = [int]$key
            $text = $script:GPOLinkControls[$key].Text
            $links = if ([string]::IsNullOrWhiteSpace($text)) { @() } else {
                @($text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            $script:Configs.GPO.GPOs[$idx].LinkTargets = $links
        }
        $script:Configs.GPO.Settings.FilteringGroupsOU = $UI.GPOFilteringGroupsOU.Text.Trim()

        # LAPS GPO: read dedicated editable controls and update RegistrySettings
        if ($script:GPOLAPSControls -and $script:GPOLAPSControls.Count -gt 0) {
            $lapsGPO = $script:Configs.GPO.GPOs | Where-Object { $_.RegistrySettings -and ($_.RegistrySettings | Where-Object { $_.Key -like "*LAPS*" }) } | Select-Object -First 1
            if ($lapsGPO) {
                $lapsTypeMap = @{
                    "BackupDirectory"                          = "DWord"
                    "AdministratorAccountName"                 = "String"
                    "PasswordAgeDays"                          = "DWord"
                    "PasswordLength"                           = "DWord"
                    "PassphraseLength"                         = "DWord"
                    "PasswordComplexity"                       = "DWord"
                    "PasswordExpirationProtectionEnabled"      = "DWord"
                    "PostAuthenticationResetDelay"             = "DWord"
                    "PostAuthenticationActions"                = "DWord"
                    "ADPasswordEncryptionEnabled"              = "DWord"
                    "ADPasswordEncryptionPrincipal"            = "String"
                    "ADEncryptedPasswordHistorySize"           = "DWord"
                    "ADBackupDSRMPassword"                     = "DWord"
                    "AutomaticAccountManagementEnabled"        = "DWord"
                    "AutomaticAccountManagementTarget"         = "DWord"
                    "AutomaticAccountManagementNameOrPrefix"   = "String"
                    "AutomaticAccountManagementEnableAccount"  = "DWord"
                    "AutomaticAccountManagementRandomizeName"  = "DWord"
                }
                foreach ($vn in $script:GPOLAPSControls.Keys) {
                    $lapsCtrl = $script:GPOLAPSControls[$vn]
                    $lapsValue = if ($lapsCtrl -is [System.Windows.Controls.ComboBox]) {
                        [int]([object[]]$lapsCtrl.Tag)[$lapsCtrl.SelectedIndex]
                    } elseif ($lapsCtrl -is [System.Windows.Controls.CheckBox]) {
                        if ($lapsCtrl.IsChecked) { 1 } else { 0 }
                    } else {
                        $t = $lapsCtrl.Text
                        if ($lapsTypeMap[$vn] -eq "DWord" -and $t -match '^\d+$') { [int]$t } else { $t }
                    }
                    $existingEntry = $lapsGPO.RegistrySettings | Where-Object { $_.ValueName -eq $vn }
                    if ($existingEntry) {
                        $existingEntry.Value = $lapsValue
                    } else {
                        $lapsGPO.RegistrySettings = @($lapsGPO.RegistrySettings) + @([PSCustomObject]@{
                            Key         = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS"
                            ValueName   = $vn
                            Value       = $lapsValue
                            Type        = $lapsTypeMap[$vn]
                            Description = ""
                        })
                    }
                }
            }
        }

        $script:Configs.GPO | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.GPO -Encoding UTF8
    }

    # PSO: read toggle states, parameters, and AppliesTo back into config
    if ($script:Configs.PSO) {
        for ($i = 0; $i -lt $script:PSOToggles.Count; $i++) {
            $script:Configs.PSO.Policies[$i].Enabled = [bool]$script:PSOToggles[$i].IsChecked
        }
        foreach ($key in $script:PSOParamControls.Keys) {
            $parts = $key -split '\.'
            $policyIdx = [int]$parts[0]
            $paramName = $parts[1]
            $control = $script:PSOParamControls[$key]
            $value = if ($control -is [System.Windows.Controls.CheckBox]) {
                [bool]$control.IsChecked
            } elseif ($control -is [System.Windows.Controls.TextBox]) {
                $text = $control.Text
                if ($text -match '^\d+$') { [int]$text } else { $text }
            } else { $control.Text }
            $script:Configs.PSO.Policies[$policyIdx].$paramName = $value
        }
        foreach ($key in $script:PSOAppliesToControls.Keys) {
            $idx = [int]$key
            $text = $script:PSOAppliesToControls[$key].Text
            $subjects = if ([string]::IsNullOrWhiteSpace($text)) { @() } else {
                @($text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            $script:Configs.PSO.Policies[$idx].AppliesTo = $subjects
        }
        $script:Configs.PSO | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.PSO -Encoding UTF8
    }

    # Silo: read toggle states, parameters, and account lists back into config
    if ($script:Configs.Silo) {
        for ($i = 0; $i -lt $script:SiloToggles.Count; $i++) {
            $script:Configs.Silo.Silos[$i].Enabled = [bool]$script:SiloToggles[$i].IsChecked
        }
        foreach ($key in $script:SiloParamControls.Keys) {
            $parts = $key -split '\.'
            $siloIdx = [int]$parts[0]
            $paramName = $parts[1]
            $control = $script:SiloParamControls[$key]
            $value = if ($control -is [System.Windows.Controls.CheckBox]) {
                [bool]$control.IsChecked
            } elseif ($control -is [System.Windows.Controls.TextBox]) {
                $text = $control.Text
                if ($text -match '^\d+$') { [int]$text } else { $text }
            } else { $control.Text }
            $script:Configs.Silo.Silos[$siloIdx].$paramName = $value
        }
        foreach ($key in $script:SiloComputerControls.Keys) {
            $idx = [int]$key
            $text = $script:SiloComputerControls[$key].Text
            $computers = if ([string]::IsNullOrWhiteSpace($text)) { @() } else {
                @($text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            $script:Configs.Silo.Silos[$idx].Computers = $computers
        }
        foreach ($key in $script:SiloServiceAccountControls.Keys) {
            $idx = [int]$key
            $text = $script:SiloServiceAccountControls[$key].Text
            $accounts = if ([string]::IsNullOrWhiteSpace($text)) { @() } else {
                @($text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
            $script:Configs.Silo.Silos[$idx].ServiceAccounts = $accounts
        }
        $script:Configs.Silo | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.Silo -Encoding UTF8
    }

    # JIT: read settings back into config
    if ($script:Configs.JIT) {
        $script:Configs.JIT.Settings.ToolsSharePath = $UI.JITToolsSharePath.Text.Trim()
        $script:Configs.JIT.Settings.InstallPath = $UI.JITInstallPath.Text.Trim()
        $script:Configs.JIT.Settings.FilteringGroupsOU = $UI.JITFilteringGroupsOU.Text.Trim()
        $script:Configs.JIT.Settings.GPO.Name = $UI.JITGPOName.Text.Trim()
        $script:Configs.JIT.Settings.GPO.Description = $UI.JITGPODescription.Text.Trim()
        $linkText = $UI.JITGPOLinkTargets.Text
        $script:Configs.JIT.Settings.GPO.LinkTargets = if ([string]::IsNullOrWhiteSpace($linkText)) { @() } else {
            @($linkText -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        $script:Configs.JIT | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.JIT -Encoding UTF8
    }

    # Tiering: rebuild from TreeView
    if ($script:Configs.Tiering) {
        $script:Configs.Tiering.Settings.BaseDN = $UI.TieringBaseDN.Text
        $script:Configs.Tiering.OUStructure = ConvertFrom-TreeView $UI.TieringTree.Items
        $script:Configs.Tiering | ConvertTo-Json -Depth 20 | Set-Content $script:ConfigPaths.Tiering -Encoding UTF8
    }

    # RBAC: already stored in config object (edits update it in-place)
    if ($script:Configs.RBAC) {
        $script:Configs.RBAC | ConvertTo-Json -Depth 20 | Set-Content $script:ConfigPaths.RBAC -Encoding UTF8
    }

    $script:UnsavedChanges = @{ Hardening = $false; GPO = $false; Tiering = $false; RBAC = $false; PSO = $false; Silo = $false; JIT = $false }
    Write-ConsoleUI "All configurations saved." "Success"
}

function ConvertFrom-TreeView($items) {
    $result = @()
    foreach ($item in $items) {
        $tag = $item.Tag
        $ou = [ordered]@{
            Name        = $tag.Name
            Description = $tag.Description
        }
        if ($null -ne $tag.Protected -and $tag.Protected -eq $false) {
            $ou.ProtectedFromAccidentalDeletion = $false
        }
        if ($item.Items.Count -gt 0) {
            $ou.Children = @(ConvertFrom-TreeView $item.Items)
        }
        $result += [PSCustomObject]$ou
    }
    return $result
}

# ============================================================================
# UI Population
# ============================================================================

function Populate-Dashboard {
    # Environment info (try/catch in case not on a DC)
    try {
        $connParam = New-LOCKmeADConnectionParam -Connection $script:Connection
        $domain = Get-ADDomain @connParam
        $forest = Get-ADForest @connParam
        $currentHost = if ($script:Connection -and $script:Connection.Server) { $script:Connection.Server } else { $env:COMPUTERNAME }
        $UI.DashEnvDC.Text        = "Current DC: $currentHost"
        $UI.DashEnvPDC.Text       = "PDC Emulator: $($domain.PDCEmulator)"
        $UI.DashEnvDomain.Text    = "Domain: $($domain.DNSRoot)"
        $UI.DashEnvForest.Text    = "Forest: $($forest.Name)"
        $UI.DashEnvFunctional.Text = "Functional levels: Domain=$($domain.DomainMode), Forest=$($forest.ForestMode)"
    } catch {
        $UI.DashEnvDC.Text = "Current DC: (not available - AD module may not be loaded)"
        $UI.DashEnvPDC.Text = ""; $UI.DashEnvDomain.Text = ""; $UI.DashEnvForest.Text = ""
        $UI.DashEnvFunctional.Text = ""
    }

    # Module summaries
    if ($script:Configs.Hardening) {
        $enabled = @($script:Configs.Hardening.Tasks | Where-Object { $_.Enabled }).Count
        $total = $script:Configs.Hardening.Tasks.Count
        $UI.DashHardeningSummary.Text = "$enabled / $total"
        $UI.DashHardeningDetail.Text = "tasks enabled"
    }
    if ($script:Configs.GPO) {
        $gpoEnabled = @($script:Configs.GPO.GPOs | Where-Object { $_.Enabled }).Count
        $gpoTotal = $script:Configs.GPO.GPOs.Count
        $UI.DashGPOSummary.Text = "$gpoEnabled / $gpoTotal"
        $UI.DashGPODetail.Text = "GPOs enabled"
    }
    if ($script:Configs.Tiering) {
        $ouCount = Count-TieringOUs $script:Configs.Tiering.OUStructure
        $UI.DashTieringSummary.Text = "$ouCount"
        $UI.DashTieringDetail.Text = "OUs defined"
    }
    if ($script:Configs.RBAC) {
        $roleCount = $script:Configs.RBAC.Roles.Count
        $UI.DashRBACSummary.Text = "$roleCount"
        $UI.DashRBACDetail.Text = "roles defined"
    }
    if ($script:Configs.PSO) {
        $psoEnabled = @($script:Configs.PSO.Policies | Where-Object { $_.Enabled }).Count
        $psoTotal = $script:Configs.PSO.Policies.Count
        $UI.DashPSOSummary.Text = "$psoEnabled / $psoTotal"
        $UI.DashPSODetail.Text = "policies enabled"
    }
    if ($script:Configs.Silo) {
        $siloEnabled = @($script:Configs.Silo.Silos | Where-Object { $_.Enabled }).Count
        $siloTotal = $script:Configs.Silo.Silos.Count
        $UI.DashSiloSummary.Text = "$siloEnabled / $siloTotal"
        $UI.DashSiloDetail.Text = "silos enabled"
    }
    if ($script:Configs.JIT) {
        $gpoName = $script:Configs.JIT.Settings.GPO.Name
        $linkCount = $script:Configs.JIT.Settings.GPO.LinkTargets.Count
        $UI.DashJITSummary.Text = if ($gpoName) { "1 GPO" } else { "---" }
        $UI.DashJITDetail.Text = "$linkCount link targets"
    }
}

function Populate-HardeningTab {
    $UI.HardeningTaskList.Children.Clear()
    $script:HardeningToggles = @()
    $script:HardeningParamControls = @{}
    $script:HardeningStatusBadges = @{}

    for ($i = 0; $i -lt $script:Configs.Hardening.Tasks.Count; $i++) {
        $task = $script:Configs.Hardening.Tasks[$i]
        $idx = $i

        # Card border
        $card = New-Object System.Windows.Controls.Border
        $card.Background = Get-WPFBrush "#FFFFFF"
        $card.CornerRadius = [System.Windows.CornerRadius]::new(8)
        $card.Padding = [System.Windows.Thickness]::new(16)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $card.BorderBrush = Get-WPFBrush "#E5E5E5"
        $card.BorderThickness = [System.Windows.Thickness]::new(1)

        $outerStack = New-Object System.Windows.Controls.StackPanel

        # Header row: toggle + text
        $headerDock = New-Object System.Windows.Controls.DockPanel

        $toggle = New-Object System.Windows.Controls.CheckBox
        $toggle.IsChecked = [bool]$task.Enabled
        $toggle.Style = $script:Window.FindResource("ToggleSwitch")
        $toggle.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($toggle, "Left")
        $script:HardeningToggles += $toggle

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.Margin = [System.Windows.Thickness]::new(14, 0, 0, 0)

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $task.Name
        $nameBlock.FontSize = 14
        $nameBlock.FontWeight = "SemiBold"

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $task.Description
        $descBlock.FontSize = 12
        $descBlock.Foreground = Get-WPFBrush "#666666"
        $descBlock.TextWrapping = "Wrap"

        [void]$textStack.Children.Add($nameBlock)
        [void]$textStack.Children.Add($descBlock)

        $statusBadge = New-Object System.Windows.Controls.Border
        $statusBadge.CornerRadius = [System.Windows.CornerRadius]::new(4)
        $statusBadge.Padding = [System.Windows.Thickness]::new(8, 2, 8, 2)
        $statusBadge.Background = Get-WPFBrush "#F0F0F0"
        $statusBadge.VerticalAlignment = "Center"
        $statusBadge.Margin = [System.Windows.Thickness]::new(8, 0, 0, 0)
        [System.Windows.Controls.DockPanel]::SetDock($statusBadge, "Right")

        $statusText = New-Object System.Windows.Controls.TextBlock
        $statusText.Text = "—"
        $statusText.FontSize = 11
        $statusText.Foreground = Get-WPFBrush "#999999"
        $statusText.VerticalAlignment = "Center"
        [void]$statusBadge.AddChild($statusText)

        $script:HardeningStatusBadges[$task.Name] = @{ Border = $statusBadge; Text = $statusText; Message = '' }

        $statusBadge.Cursor = [System.Windows.Input.Cursors]::Hand
        $badgeName = $task.Name
        $badgeDict = $script:HardeningStatusBadges[$task.Name]
        $statusBadge.Add_MouseLeftButtonDown({
            if (-not [string]::IsNullOrWhiteSpace($badgeDict.Message)) {
                [System.Windows.MessageBox]::Show(
                    $badgeDict.Message, $badgeName,
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)
            }
        }.GetNewClosure())

        [void]$headerDock.Children.Add($toggle)
        [void]$headerDock.Children.Add($statusBadge)
        [void]$headerDock.Children.Add($textStack)
        [void]$outerStack.Children.Add($headerDock)

        # Parameters expander
        if ($task.Parameters) {
            $expander = New-Object System.Windows.Controls.Expander
            $expander.Header = "Parameters"
            $expander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $expander.FontSize = 12

            $paramGrid = New-Object System.Windows.Controls.Grid
            $paramGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = [System.Windows.GridLength]::new(180)
            $col2 = New-Object System.Windows.Controls.ColumnDefinition
            $col2.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            [void]$paramGrid.ColumnDefinitions.Add($col1)
            [void]$paramGrid.ColumnDefinitions.Add($col2)

            $rowIdx = 0
            $task.Parameters.PSObject.Properties | ForEach-Object {
                $paramName = $_.Name
                $paramValue = $_.Value

                [void]$paramGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

                $label = New-Object System.Windows.Controls.TextBlock
                $label.Text = $paramName
                $label.VerticalAlignment = "Center"
                $label.Foreground = Get-WPFBrush "#555"
                $label.Margin = [System.Windows.Thickness]::new(0, 4, 10, 4)
                [System.Windows.Controls.Grid]::SetRow($label, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($label, 0)

                if ($paramValue -is [bool]) {
                    $ctrl = New-Object System.Windows.Controls.CheckBox
                    $ctrl.IsChecked = $paramValue
                    $ctrl.VerticalAlignment = "Center"
                } elseif ($paramValue -is [System.Array]) {
                    $ctrl = New-Object System.Windows.Controls.TextBox
                    $ctrl.AcceptsReturn = $true
                    $ctrl.TextWrapping = "Wrap"
                    $ctrl.MinLines = 2
                    $ctrl.MaxLines = 8
                    $ctrl.VerticalScrollBarVisibility = "Auto"
                    $ctrl.Text = ($paramValue -join "`r`n")
                    $ctrl.Tag = "array"
                    $ctrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                    $ctrl.BorderBrush = Get-WPFBrush "#DDD"
                } else {
                    $ctrl = New-Object System.Windows.Controls.TextBox
                    $ctrl.Text = [string]$paramValue
                    $ctrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                    $ctrl.BorderBrush = Get-WPFBrush "#DDD"
                }
                $ctrl.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
                [System.Windows.Controls.Grid]::SetRow($ctrl, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($ctrl, 1)

                [void]$paramGrid.Children.Add($label)
                [void]$paramGrid.Children.Add($ctrl)
                $script:HardeningParamControls["$idx.$paramName"] = $ctrl
                $rowIdx++
            }

            $expander.Content = $paramGrid
            [void]$outerStack.Children.Add($expander)
        }

        # Info note — ConfigureLAPSADPermissions
        if ($task.Name -eq 'ConfigureLAPSADPermissions') {
            $infoLink = New-Object System.Windows.Controls.TextBlock
            $infoLink.Text = "ⓘ  How OUs and groups interact"
            $infoLink.FontSize = 11
            $infoLink.Foreground = Get-WPFBrush "#0078D4"
            $infoLink.Margin = [System.Windows.Thickness]::new(62, 4, 0, 0)
            $infoLink.Cursor = [System.Windows.Input.Cursors]::Hand
            $infoLink.TextDecorations = [System.Windows.TextDecorations]::Underline
            $infoLink.Add_MouseLeftButtonDown({
                [System.Windows.MessageBox]::Show(
                    "Permissions are applied per OU, with all listed groups in a single operation:`n`n" +
                    "• Each OU is processed independently.`n" +
                    "• All groups in the principals field are applied at once to each OU.`n`n" +
                    "Example: 2 groups + 2 OUs → both groups receive the permission on OU1, then both on OU2.",
                    "How OUs and groups interact",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)
            })
            [void]$outerStack.Children.Add($infoLink)
        }

        # Schema Admins notice — ExtendLAPSSchema only.
        #
        # This is the single task in the whole tool that needs more than Domain Admins: extending
        # the schema is a forest-root operation reserved to Schema Admins. Rather than warning
        # every operator at connection time about something most of them will never run, the
        # notice sits on the one card it concerns, and only when the connected account actually
        # lacks the membership.
        if ($task.Name -eq 'ExtendLAPSSchema' -and $script:Privilege -and
            $script:Privilege.Determined -and -not $script:Privilege.IsSchemaAdmin) {
            $schemaNote = New-Object System.Windows.Controls.TextBlock
            $schemaNote.Text = [char]0x24D8 + "  $($script:Privilege.Identity) is not a Schema Admin - this task will fail"
            $schemaNote.FontSize = 11
            $schemaNote.Foreground = Get-WPFBrush "#D35400"
            $schemaNote.Margin = [System.Windows.Thickness]::new(62, 4, 0, 0)
            $schemaNote.Cursor = [System.Windows.Input.Cursors]::Hand
            $schemaNote.TextWrapping = "Wrap"
            $schemaNote.TextDecorations = [System.Windows.TextDecorations]::Underline
            $noteIdentity = [string]$script:Privilege.Identity
            $schemaNote.Add_MouseLeftButtonDown({
                [System.Windows.MessageBox]::Show(
                    "Extending the Active Directory schema for Windows LAPS is a forest-root operation reserved to the Schema Admins group. '$noteIdentity' is a Domain Admin but not a member of it, so this task will fail.`n`nEvery other task and module deploys normally.`n`nTwo ways forward:`n  - add the account to Schema Admins on the forest root, temporarily, for this one run;`n  - or leave the task disabled if the schema already carries the msLAPS-* attributes, in which case it is a no-op anyway. The Verify All button tells you which.",
                    "Schema Admins required",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information) | Out-Null
            }.GetNewClosure())
            [void]$outerStack.Children.Add($schemaNote)
        }

        # Prerequisites check button — for RaiseDomainFunctionalLevel and RaiseForestFunctionalLevel
        $prereqScope    = $null
        $prereqParamKey = $null
        if ($task.Name -eq 'RaiseDomainFunctionalLevel')  { $prereqScope = 'Domain'; $prereqParamKey = 'TargetDomainLevel' }
        elseif ($task.Name -eq 'RaiseForestFunctionalLevel') { $prereqScope = 'Forest'; $prereqParamKey = 'TargetForestLevel' }

        if ($prereqScope) {
            $prereqBtn = New-Object System.Windows.Controls.Button
            $prereqBtn.Content         = "Check Prerequisites"
            $prereqBtn.Margin          = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $prereqBtn.HorizontalAlignment = "Left"
            $prereqBtn.Padding         = [System.Windows.Thickness]::new(12, 6, 12, 6)
            $prereqBtn.FontSize        = 12
            $prereqBtn.Background      = Get-WPFBrush "#EBF5FB"
            $prereqBtn.Foreground      = Get-WPFBrush "#0078D4"
            $prereqBtn.BorderBrush     = Get-WPFBrush "#AED6F1"
            $prereqBtn.BorderThickness = [System.Windows.Thickness]::new(1)
            $prereqBtn.Cursor          = "Hand"
            $prereqBtn.Tag             = @{ Idx = $idx; Scope = $prereqScope; ParamKey = $prereqParamKey }
            $prereqBtn.Add_Click({
                $tag      = $this.Tag
                $paramKey = $tag.ParamKey
                $levelCtrl = $script:HardeningParamControls["$($tag.Idx).$paramKey"]
                $default  = if ($tag.Scope -eq 'Domain') { 'Windows2016Domain' } else { 'Windows2016Forest' }
                $level    = if ($levelCtrl) { $levelCtrl.Text } else { $default }
                Show-FunctionalLevelPrereqDialog -Scope $tag.Scope -TargetLevel $level
            })
            [void]$outerStack.Children.Add($prereqBtn)
        }

        $card.Child = $outerStack
        [void]$UI.HardeningTaskList.Children.Add($card)
    }
}

function Update-GPOFilteringOUWarning {
    $text = $UI.GPOFilteringGroupsOU.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        $UI.GPOFilteringOUWarning.Visibility = "Collapsed"
    }
    elseif ($text -notmatch '(?i)(tier|t)[-_. ]?(0|zero)') {
        $UI.GPOFilteringOUWarning.Text = "Warning: This OU does not reference a Tier 0 location. Filtering groups will still be deployed, but consider using a Tier 0 OU for proper security boundaries."
        $UI.GPOFilteringOUWarning.Foreground = Get-WPFBrush "#D35400"
        $UI.GPOFilteringOUWarning.Visibility = "Visible"
    }
    else {
        $UI.GPOFilteringOUWarning.Text = "OK: OU references a Tier 0 location."
        $UI.GPOFilteringOUWarning.Foreground = Get-WPFBrush "#1E8449"
        $UI.GPOFilteringOUWarning.Visibility = "Visible"
    }
}

function New-GPOGroupChipPanel {
    <#
    .SYNOPSIS
        Builds the editable "list of AD groups" block shared by the User Rights Assignments and
        Restricted Groups editors: one removable chip per group, plus an AD-backed add button.
    .DESCRIPTION
        Both editors manipulate the same thing -- a string array of group names hanging off an
        entry in GPO-Config.json -- so they share one builder rather than two near-identical
        copies. Edits mutate the configuration object in place, which is what makes them survive
        "Save configs" without any change to Save-AllConfigs.

        Removing the last entry is refused while the GPO is enabled: Import-GPOConfiguration
        rejects an enabled GPO whose assignment has no Groups (or whose restricted group has no
        Members), so allowing it here would only produce a configuration that fails at deployment
        with a message pointing at the JSON rather than at the click that caused it.
    .PARAMETER Owner
        The object holding the list -- a UserRightsAssignments entry or a RestrictedGroups entry.
    .PARAMETER Property
        Name of the string-array property on that object: 'Groups' or 'Members'.
    .PARAMETER Label
        Heading shown above the chips.
    .PARAMETER Accent
        Chip foreground colour, to keep the two editors visually distinct.
    .PARAMETER ChipBackground
        Chip background colour.
    .PARAMETER GpoEnabled
        Whether the owning GPO is enabled, which decides if the list may be emptied.
    #>
    param(
        [Parameter(Mandatory)] $Owner,
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][string]$Label,
        [string]$Accent         = "#4A235A",
        [string]$ChipBackground = "#EDE7F6",
        [bool]$GpoEnabled       = $true
    )

    $block = New-Object System.Windows.Controls.StackPanel
    $block.Margin = [System.Windows.Thickness]::new(0, 2, 0, 8)

    $heading = New-Object System.Windows.Controls.TextBlock
    $heading.Text       = $Label
    $heading.FontSize   = 11
    $heading.FontWeight = "SemiBold"
    $heading.Foreground = Get-WPFBrush "#6C3483"
    $heading.Margin     = [System.Windows.Thickness]::new(0, 0, 0, 4)
    [void]$block.Children.Add($heading)

    $wrap = New-Object System.Windows.Controls.WrapPanel

    $list = if ($Owner.$Property) { @($Owner.$Property) } else { @() }
    foreach ($groupName in $list) {
        $chip = New-Object System.Windows.Controls.Border
        $chip.Background   = Get-WPFBrush $ChipBackground
        $chip.CornerRadius = [System.Windows.CornerRadius]::new(3)
        $chip.Padding      = [System.Windows.Thickness]::new(7, 2, 4, 2)
        $chip.Margin       = [System.Windows.Thickness]::new(0, 0, 4, 4)

        $inner = New-Object System.Windows.Controls.StackPanel
        $inner.Orientation = "Horizontal"

        $text = New-Object System.Windows.Controls.TextBlock
        $text.Text              = $groupName
        $text.FontSize          = 11
        $text.Foreground        = Get-WPFBrush $Accent
        $text.VerticalAlignment = "Center"

        $remove = New-Object System.Windows.Controls.Button
        $remove.Content           = [char]0x00D7
        $remove.FontSize          = 11
        $remove.Background        = Get-WPFBrush "Transparent"
        $remove.BorderThickness   = [System.Windows.Thickness]::new(0)
        $remove.Foreground        = Get-WPFBrush "#A93226"
        $remove.Cursor            = "Hand"
        $remove.Padding           = [System.Windows.Thickness]::new(3, 0, 0, 0)
        $remove.VerticalAlignment = "Center"
        $remove.ToolTip           = "Remove '$groupName'"
        $remove.Tag = @{ Owner = $Owner; Property = $Property; GroupName = $groupName; Label = $Label; Enabled = $GpoEnabled }
        $remove.Add_Click({
            $ctx     = $this.Tag
            $current = @($ctx.Owner.($ctx.Property))
            if ($ctx.Enabled -and $current.Count -le 1) {
                [System.Windows.MessageBox]::Show(
                    "'$($ctx.Label)' must keep at least one group while the GPO is enabled.`n`nDisable the GPO first, or add a replacement before removing this one.",
                    "Cannot remove the last group",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Warning) | Out-Null
                return
            }
            $ctx.Owner.($ctx.Property) = @($current | Where-Object { $_ -ne $ctx.GroupName })
            $script:UnsavedChanges.GPO = $true
            Invoke-GPOTabRefresh
        })

        [void]$inner.Children.Add($text)
        [void]$inner.Children.Add($remove)
        $chip.Child = $inner
        [void]$wrap.Children.Add($chip)
    }

    $add = New-Object System.Windows.Controls.Button
    $add.Content         = "+ Add group"
    $add.Background      = Get-WPFBrush "Transparent"
    $add.BorderThickness = [System.Windows.Thickness]::new(0)
    $add.Foreground      = Get-WPFBrush "#0078D4"
    $add.FontSize        = 11
    $add.Cursor          = "Hand"
    $add.Padding         = [System.Windows.Thickness]::new(0, 2, 0, 2)
    $add.Margin          = [System.Windows.Thickness]::new(0, 0, 0, 4)
    $add.Tag = @{ Owner = $Owner; Property = $Property }
    $add.Add_Click({
        $ctx = $this.Tag
        $groupName = Show-ADGroupSearchDialog
        if (-not $groupName) { return }
        if (-not $ctx.Owner.PSObject.Properties[$ctx.Property]) {
            $ctx.Owner | Add-Member -NotePropertyName $ctx.Property -NotePropertyValue @() -Force
        }
        $current = @($ctx.Owner.($ctx.Property))
        if ($groupName -notin $current) {
            $ctx.Owner.($ctx.Property) = $current + @($groupName)
            $script:UnsavedChanges.GPO = $true
        }
        Invoke-GPOTabRefresh
    })
    [void]$wrap.Children.Add($add)

    [void]$block.Children.Add($wrap)
    return $block
}

function Populate-GPOTab {
    $UI.GPOTaskList.Children.Clear()
    $script:GPOToggles = @()
    $script:GPONameControls = @{}
    $script:GPOLinkControls = @{}
    $script:GPOLAPSControls = @{}

    # Populate Filtering Groups OU
    $filterOU = $script:Configs.GPO.Settings.FilteringGroupsOU
    $UI.GPOFilteringGroupsOU.Text = if ($filterOU) { $filterOU } else { "" }
    Update-GPOFilteringOUWarning

    for ($i = 0; $i -lt $script:Configs.GPO.GPOs.Count; $i++) {
        $gpo = $script:Configs.GPO.GPOs[$i]
        $idx = $i

        # Card border
        $card = New-Object System.Windows.Controls.Border
        $card.Background = Get-WPFBrush "#FFFFFF"
        $card.CornerRadius = [System.Windows.CornerRadius]::new(8)
        $card.Padding = [System.Windows.Thickness]::new(16)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $card.BorderBrush = Get-WPFBrush "#E5E5E5"
        $card.BorderThickness = [System.Windows.Thickness]::new(1)

        $outerStack = New-Object System.Windows.Controls.StackPanel

        # Header row: toggle + text + badge
        $headerDock = New-Object System.Windows.Controls.DockPanel

        $toggle = New-Object System.Windows.Controls.CheckBox
        $toggle.IsChecked = [bool]$gpo.Enabled
        $toggle.Style = $script:Window.FindResource("ToggleSwitch")
        $toggle.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($toggle, "Left")
        $script:GPOToggles += $toggle

        # Settings count badges
        $badgePanel = New-Object System.Windows.Controls.StackPanel
        $badgePanel.Orientation = "Horizontal"
        $badgePanel.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($badgePanel, "Right")

        $regCount = if ($gpo.RegistrySettings) { $gpo.RegistrySettings.Count } else { 0 }
        $regPrefCount = if ($gpo.RegistryPreferences) { $gpo.RegistryPreferences.Count } else { 0 }
        $secOptCount = if ($gpo.SecurityOptions) { $gpo.SecurityOptions.Count } else { 0 }
        $uraCount = if ($gpo.UserRightsAssignments) { $gpo.UserRightsAssignments.Count } else { 0 }
        $svcCount = if ($gpo.SystemServices) { $gpo.SystemServices.Count } else { 0 }
        $scriptCount = if ($gpo.Scripts) { $gpo.Scripts.Count } else { 0 }
        $rgCount = if ($gpo.RestrictedGroups) { $gpo.RestrictedGroups.Count } else { 0 }
        $isLapsGPO = [bool]($gpo.RegistrySettings | Where-Object { $_.Key -like "*LAPS*" })

        # Fill the badge strip. It was built and docked but never populated, so a GPO whose only
        # content is Restricted Groups looked completely empty on the card -- which is exactly the
        # policy type where knowing there is content matters most.
        $badgeSpecs = @(
            @{ N = $regCount;     T = 'reg';    F = "#0078D4"; B = "#E8F2FC" }
            @{ N = $regPrefCount; T = 'pref';   F = "#2471A3"; B = "#E8F2FC" }
            @{ N = $secOptCount;  T = 'SO';     F = "#B7950B"; B = "#FEF9E7" }
            @{ N = $uraCount;     T = 'URA';    F = "#6C3483"; B = "#F3E8FC" }
            @{ N = $rgCount;      T = 'RG';     F = "#A93226"; B = "#FDEDEC" }
            @{ N = $svcCount;     T = 'svc';    F = "#C0392B"; B = "#FDEDEC" }
            @{ N = $scriptCount;  T = 'script'; F = "#117A65"; B = "#E8F8F0" }
        )
        foreach ($spec in $badgeSpecs) {
            if ($spec.N -le 0) { continue }
            $badge = New-Object System.Windows.Controls.TextBlock
            $badge.Text              = "$($spec.N) $($spec.T)"
            $badge.FontSize          = 10
            $badge.Foreground        = Get-WPFBrush $spec.F
            $badge.Background        = Get-WPFBrush $spec.B
            $badge.Padding           = [System.Windows.Thickness]::new(6, 2, 6, 2)
            $badge.Margin            = [System.Windows.Thickness]::new(4, 0, 0, 0)
            $badge.VerticalAlignment = "Center"
            [void]$badgePanel.Children.Add($badge)
        }

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.Margin = [System.Windows.Thickness]::new(14, 0, 10, 0)

        $nameRow = New-Object System.Windows.Controls.StackPanel
        $nameRow.Orientation = "Horizontal"
        $nameRow.VerticalAlignment = "Center"

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $gpo.Name
        $nameBlock.FontSize = 14
        $nameBlock.FontWeight = "SemiBold"
        $nameBlock.VerticalAlignment = "Center"

        $nameBox = New-Object System.Windows.Controls.TextBox
        $nameBox.Text = $gpo.Name
        $nameBox.FontSize = 14
        $nameBox.FontWeight = "SemiBold"
        $nameBox.Padding = [System.Windows.Thickness]::new(2, 0, 2, 0)
        $nameBox.VerticalAlignment = "Center"
        $nameBox.Visibility = "Collapsed"
        $script:GPONameControls[$idx] = $nameBox

        $editNameBtn = New-Object System.Windows.Controls.Button
        $editNameBtn.Content = [char]0x270F
        $editNameBtn.FontSize = 11
        $editNameBtn.Background = Get-WPFBrush "Transparent"
        $editNameBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $editNameBtn.Foreground = Get-WPFBrush "#AAAAAA"
        $editNameBtn.Cursor = "Hand"
        $editNameBtn.Padding = [System.Windows.Thickness]::new(6, 0, 0, 0)
        $editNameBtn.VerticalAlignment = "Center"
        $editNameBtn.Tag = @{ Block = $nameBlock; Box = $nameBox }
        $editNameBtn.Add_Click({
            $ctx = $this.Tag
            $ctx.Block.Visibility = "Collapsed"
            $ctx.Box.Visibility = "Visible"
            [void]$ctx.Box.Focus()
            $ctx.Box.SelectAll()
            $this.Visibility = "Collapsed"
        })

        $nameBox.Tag = @{ Block = $nameBlock; Btn = $editNameBtn }
        $nameBox.Add_LostFocus({
            $ctx = $this.Tag
            $ctx.Block.Text = $this.Text
            $ctx.Block.Visibility = "Visible"
            $ctx.Btn.Visibility  = "Visible"
            $this.Visibility = "Collapsed"
        })
        $nameBox.Add_KeyDown({
            if ($_.Key -eq [System.Windows.Input.Key]::Return) {
                [System.Windows.Input.Keyboard]::ClearFocus()
            }
        })

        [void]$nameRow.Children.Add($nameBlock)
        [void]$nameRow.Children.Add($nameBox)
        [void]$nameRow.Children.Add($editNameBtn)

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $gpo.Description
        $descBlock.FontSize = 12
        $descBlock.Foreground = Get-WPFBrush "#666666"
        $descBlock.TextWrapping = "Wrap"

        [void]$textStack.Children.Add($nameRow)
        [void]$textStack.Children.Add($descBlock)

        [void]$headerDock.Children.Add($toggle)
        [void]$headerDock.Children.Add($badgePanel)
        [void]$headerDock.Children.Add($textStack)
        [void]$outerStack.Children.Add($headerDock)

        # Registry Settings expander (read-only, only if registry settings exist and not the LAPS GPO which has a dedicated UI)
        if ($regCount -gt 0 -and -not $isLapsGPO) {
            $regExpander = New-Object System.Windows.Controls.Expander
            $regExpander.Header = "Registry Settings"
            $regExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $regExpander.FontSize = 12

            $regGrid = New-Object System.Windows.Controls.Grid
            $regGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            $colKey = New-Object System.Windows.Controls.ColumnDefinition
            $colKey.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            $colVal = New-Object System.Windows.Controls.ColumnDefinition
            $colVal.Width = [System.Windows.GridLength]::new(80)
            $colType = New-Object System.Windows.Controls.ColumnDefinition
            $colType.Width = [System.Windows.GridLength]::new(60)
            [void]$regGrid.ColumnDefinitions.Add($colKey)
            [void]$regGrid.ColumnDefinitions.Add($colVal)
            [void]$regGrid.ColumnDefinitions.Add($colType)

            $rowIdx = 0
            foreach ($setting in $gpo.RegistrySettings) {
                [void]$regGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

                $keyLabel = New-Object System.Windows.Controls.TextBlock
                $shortKey = $setting.Key -replace '^HKLM\\', ''
                $keyLabel.Text = "$shortKey\$($setting.ValueName)"
                $keyLabel.FontSize = 11
                $keyLabel.Foreground = Get-WPFBrush "#555"
                $keyLabel.TextTrimming = "CharacterEllipsis"
                $keyLabel.ToolTip = if ($setting.Description) { $setting.Description } else { $setting.Key }
                $keyLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($keyLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($keyLabel, 0)

                $valLabel = New-Object System.Windows.Controls.TextBlock
                $valLabel.Text = [string]$setting.Value
                $valLabel.FontSize = 11
                $valLabel.FontWeight = "SemiBold"
                $valLabel.Foreground = Get-WPFBrush "#0078D4"
                $valLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($valLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($valLabel, 1)

                $typeLabel = New-Object System.Windows.Controls.TextBlock
                $typeLabel.Text = $setting.Type
                $typeLabel.FontSize = 10
                $typeLabel.Foreground = Get-WPFBrush "#999"
                $typeLabel.Margin = [System.Windows.Thickness]::new(0, 3, 0, 3)
                [System.Windows.Controls.Grid]::SetRow($typeLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($typeLabel, 2)

                [void]$regGrid.Children.Add($keyLabel)
                [void]$regGrid.Children.Add($valLabel)
                [void]$regGrid.Children.Add($typeLabel)
                $rowIdx++
            }

            $regExpander.Content = $regGrid
            [void]$outerStack.Children.Add($regExpander)
        }

        # Registry Preferences expander (read-only, only if registry preferences exist)
        if ($regPrefCount -gt 0) {
            $regPrefExpander = New-Object System.Windows.Controls.Expander
            $regPrefExpander.Header = "Registry Preferences"
            $regPrefExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $regPrefExpander.FontSize = 12

            $regPrefGrid = New-Object System.Windows.Controls.Grid
            $regPrefGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            $colKey = New-Object System.Windows.Controls.ColumnDefinition
            $colKey.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            $colVal = New-Object System.Windows.Controls.ColumnDefinition
            $colVal.Width = [System.Windows.GridLength]::new(80)
            $colType = New-Object System.Windows.Controls.ColumnDefinition
            $colType.Width = [System.Windows.GridLength]::new(60)
            [void]$regPrefGrid.ColumnDefinitions.Add($colKey)
            [void]$regPrefGrid.ColumnDefinitions.Add($colVal)
            [void]$regPrefGrid.ColumnDefinitions.Add($colType)

            $rowIdx = 0
            foreach ($setting in $gpo.RegistryPreferences) {
                [void]$regPrefGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

                $keyLabel = New-Object System.Windows.Controls.TextBlock
                $shortKey = $setting.Key -replace '^HKLM\\', ''
                $keyLabel.Text = "$shortKey\$($setting.ValueName)"
                $keyLabel.FontSize = 11
                $keyLabel.Foreground = Get-WPFBrush "#555"
                $keyLabel.TextTrimming = "CharacterEllipsis"
                $keyLabel.ToolTip = if ($setting.Description) { $setting.Description } else { $setting.Key }
                $keyLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($keyLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($keyLabel, 0)

                $valLabel = New-Object System.Windows.Controls.TextBlock
                $valLabel.Text = [string]$setting.Value
                $valLabel.FontSize = 11
                $valLabel.FontWeight = "SemiBold"
                $valLabel.Foreground = Get-WPFBrush "#2471A3"
                $valLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($valLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($valLabel, 1)

                $typeLabel = New-Object System.Windows.Controls.TextBlock
                $typeLabel.Text = $setting.Type
                $typeLabel.FontSize = 10
                $typeLabel.Foreground = Get-WPFBrush "#999"
                $typeLabel.Margin = [System.Windows.Thickness]::new(0, 3, 0, 3)
                [System.Windows.Controls.Grid]::SetRow($typeLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($typeLabel, 2)

                [void]$regPrefGrid.Children.Add($keyLabel)
                [void]$regPrefGrid.Children.Add($valLabel)
                [void]$regPrefGrid.Children.Add($typeLabel)
                $rowIdx++
            }

            $regPrefExpander.Content = $regPrefGrid
            [void]$outerStack.Children.Add($regPrefExpander)
        }

        # Security Options expander (read-only, only if security options exist)
        if ($secOptCount -gt 0) {
            $secOptExpander = New-Object System.Windows.Controls.Expander
            $secOptExpander.Header = "Security Options"
            $secOptExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $secOptExpander.FontSize = 12

            $secOptGrid = New-Object System.Windows.Controls.Grid
            $secOptGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            $colKey = New-Object System.Windows.Controls.ColumnDefinition
            $colKey.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            $colVal = New-Object System.Windows.Controls.ColumnDefinition
            $colVal.Width = [System.Windows.GridLength]::new(80)
            $colType = New-Object System.Windows.Controls.ColumnDefinition
            $colType.Width = [System.Windows.GridLength]::new(60)
            [void]$secOptGrid.ColumnDefinitions.Add($colKey)
            [void]$secOptGrid.ColumnDefinitions.Add($colVal)
            [void]$secOptGrid.ColumnDefinitions.Add($colType)

            $rowIdx = 0
            foreach ($opt in $gpo.SecurityOptions) {
                [void]$secOptGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

                $keyLabel = New-Object System.Windows.Controls.TextBlock
                $shortKey = $opt.Key -replace '^MACHINE\\', ''
                $keyLabel.Text = "$shortKey\$($opt.ValueName)"
                $keyLabel.FontSize = 11
                $keyLabel.Foreground = Get-WPFBrush "#555"
                $keyLabel.TextTrimming = "CharacterEllipsis"
                $keyLabel.ToolTip = if ($opt.Description) { $opt.Description } else { $opt.Key }
                $keyLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($keyLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($keyLabel, 0)

                $valLabel = New-Object System.Windows.Controls.TextBlock
                $valLabel.Text = [string]$opt.Value
                $valLabel.FontSize = 11
                $valLabel.FontWeight = "SemiBold"
                $valLabel.Foreground = Get-WPFBrush "#B7950B"
                $valLabel.Margin = [System.Windows.Thickness]::new(0, 3, 8, 3)
                [System.Windows.Controls.Grid]::SetRow($valLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($valLabel, 1)

                $typeLabel = New-Object System.Windows.Controls.TextBlock
                $typeLabel.Text = $opt.Type
                $typeLabel.FontSize = 10
                $typeLabel.Foreground = Get-WPFBrush "#999"
                $typeLabel.Margin = [System.Windows.Thickness]::new(0, 3, 0, 3)
                [System.Windows.Controls.Grid]::SetRow($typeLabel, $rowIdx)
                [System.Windows.Controls.Grid]::SetColumn($typeLabel, 2)

                [void]$secOptGrid.Children.Add($keyLabel)
                [void]$secOptGrid.Children.Add($valLabel)
                [void]$secOptGrid.Children.Add($typeLabel)
                $rowIdx++
            }

            $secOptExpander.Content = $secOptGrid
            [void]$outerStack.Children.Add($secOptExpander)
        }

        # System Services expander (read-only, only if system services exist)
        if ($svcCount -gt 0) {
            $svcExpander = New-Object System.Windows.Controls.Expander
            $svcExpander.Header = "System Services"
            $svcExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $svcExpander.FontSize = 12

            $svcStack = New-Object System.Windows.Controls.StackPanel
            $svcStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            $startupLabels = @{ 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }

            foreach ($svc in $gpo.SystemServices) {
                $svcRow = New-Object System.Windows.Controls.DockPanel
                $svcRow.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)

                $nameLabel = New-Object System.Windows.Controls.TextBlock
                $nameLabel.Text = $svc.Name
                $nameLabel.FontSize = 11
                $nameLabel.FontWeight = "SemiBold"
                $nameLabel.Foreground = Get-WPFBrush "#C0392B"
                $nameLabel.MinWidth = 180
                $nameLabel.ToolTip = if ($svc.Description) { $svc.Description } else { $svc.Name }
                [System.Windows.Controls.DockPanel]::SetDock($nameLabel, "Left")

                $typeLabel = New-Object System.Windows.Controls.TextBlock
                $typeLabel.Text = $startupLabels[[int]$svc.StartupType]
                $typeLabel.FontSize = 11
                $typeLabel.Foreground = Get-WPFBrush "#555"

                [void]$svcRow.Children.Add($nameLabel)
                [void]$svcRow.Children.Add($typeLabel)
                [void]$svcStack.Children.Add($svcRow)
            }

            $svcExpander.Content = $svcStack
            [void]$outerStack.Children.Add($svcExpander)
        }

        # Scripts expander (read-only, Startup/Shutdown)
        if ($scriptCount -gt 0) {
            $scriptsExpander = New-Object System.Windows.Controls.Expander
            $scriptsExpander.Header = "Scripts (Startup/Shutdown)"
            $scriptsExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $scriptsExpander.FontSize = 12

            $scriptsStack = New-Object System.Windows.Controls.StackPanel
            $scriptsStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            foreach ($s in $gpo.Scripts) {
                $scriptRow = New-Object System.Windows.Controls.DockPanel
                $scriptRow.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)

                $typeLabel = New-Object System.Windows.Controls.TextBlock
                $typeLabel.Text = "[$($s.Type)]"
                $typeLabel.FontSize = 11
                $typeLabel.FontWeight = "SemiBold"
                $typeLabel.Foreground = Get-WPFBrush "#1A5276"
                $typeLabel.MinWidth = 80
                [System.Windows.Controls.DockPanel]::SetDock($typeLabel, "Left")

                $nameLabel = New-Object System.Windows.Controls.TextBlock
                $nameLabel.Text = $s.ScriptName
                $nameLabel.FontSize = 11
                $nameLabel.FontWeight = "SemiBold"
                $nameLabel.Foreground = Get-WPFBrush "#117A65"
                $nameLabel.MinWidth = 160
                $nameLabel.ToolTip = if ($s.Description) { $s.Description } else { $s.ScriptName }
                [System.Windows.Controls.DockPanel]::SetDock($nameLabel, "Left")

                $descLabel = New-Object System.Windows.Controls.TextBlock
                $descLabel.Text = if ($s.Description) { $s.Description } else { "" }
                $descLabel.FontSize = 11
                $descLabel.Foreground = Get-WPFBrush "#666"
                $descLabel.TextTrimming = "CharacterEllipsis"

                [void]$scriptRow.Children.Add($typeLabel)
                [void]$scriptRow.Children.Add($nameLabel)
                [void]$scriptRow.Children.Add($descLabel)
                [void]$scriptsStack.Children.Add($scriptRow)
            }

            $scriptsExpander.Content = $scriptsStack
            [void]$outerStack.Children.Add($scriptsExpander)
        }

        # User Rights Assignments expander (editable) -- deny-logon GPOs live here.
        if ($uraCount -gt 0) {
            $uraExpander = New-Object System.Windows.Controls.Expander
            $uraExpander.Header = "User Rights Assignments"
            $uraExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $uraExpander.FontSize = 12

            $uraStack = New-Object System.Windows.Controls.StackPanel
            $uraStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            foreach ($assignment in $gpo.UserRightsAssignments) {
                $label = if ($assignment.Description) { $assignment.Description } else { $assignment.Right }
                $panel = New-GPOGroupChipPanel -Owner $assignment -Property 'Groups' -Label $label `
                            -Accent "#4A235A" -ChipBackground "#EDE7F6" -GpoEnabled ([bool]$gpo.Enabled)
                $panel.Children[0].ToolTip = $assignment.Right
                [void]$uraStack.Children.Add($panel)
            }

            $uraExpander.Content = $uraStack
            [void]$outerStack.Children.Add($uraExpander)
        }

        # Restricted Groups expander (editable) -- local Administrators enforcement.
        #
        # This section had no UI at all: the four SEC-Tiering-*-LocalAdmins GPOs carry nothing
        # else, so their cards showed an interrupteur, a name and a description and nothing more.
        # An operator could enable and link a policy that REPLACES the entire local Administrators
        # membership without ever seeing whose membership it enforces.
        if ($rgCount -gt 0) {
            $rgExpander = New-Object System.Windows.Controls.Expander
            $rgExpander.Header = "Restricted Groups (local membership)"
            $rgExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $rgExpander.FontSize = 12

            $rgStack = New-Object System.Windows.Controls.StackPanel
            $rgStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            $rgHint = New-Object System.Windows.Controls.TextBlock
            $rgHint.Text = "Membership is REPLACED, not added to: anyone not listed here is removed from the local group on every targeted machine."
            $rgHint.FontSize = 10
            $rgHint.Foreground = Get-WPFBrush "#D35400"
            $rgHint.TextWrapping = "Wrap"
            $rgHint.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)
            [void]$rgStack.Children.Add($rgHint)

            foreach ($rg in $gpo.RestrictedGroups) {
                $label = if ($rg.Description) { "$($rg.Group)  -  $($rg.Description)" } else { $rg.Group }
                $panel = New-GPOGroupChipPanel -Owner $rg -Property 'Members' -Label $label `
                            -Accent "#7B241C" -ChipBackground "#FDEDEC" -GpoEnabled ([bool]$gpo.Enabled)
                [void]$rgStack.Children.Add($panel)
            }

            $rgExpander.Content = $rgStack
            [void]$outerStack.Children.Add($rgExpander)
        }

        # Windows LAPS dedicated configuration panel
        if ($isLapsGPO) {
            $lapsExpander = New-Object System.Windows.Controls.Expander
            $lapsExpander.Header = "Configuration Windows LAPS"
            $lapsExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $lapsExpander.FontSize = 12

            $lapsGrid = New-Object System.Windows.Controls.Grid
            $lapsGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
            $colLbl = New-Object System.Windows.Controls.ColumnDefinition
            $colLbl.Width = [System.Windows.GridLength]::new(250)
            $colCtrl = New-Object System.Windows.Controls.ColumnDefinition
            $colCtrl.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            [void]$lapsGrid.ColumnDefinitions.Add($colLbl)
            [void]$lapsGrid.ColumnDefinitions.Add($colCtrl)

            $lapsParamDefs = @(
                @{ VN = "BackupDirectory";                        Label = "Password backup directory";                        Type = "combo";  Options = @("0 - Disabled","1 - Microsoft Entra ID only","2 - Active Directory only"); Values = @(0,1,2) }
                @{ VN = "AdministratorAccountName";               Label = "Managed administrator account name";               Type = "string"; Hint = "Empty = the built-in Administrator, identified by its well-known RID" }
                @{ VN = "PasswordAgeDays";                        Label = "Maximum password age (days, 1-365)";               Type = "int" }
                @{ VN = "PasswordLength";                         Label = "Password length (8-64)";                           Type = "int" }
                @{ VN = "PassphraseLength";                       Label = "Passphrase length (words, 3-10)";                  Type = "int" }
                @{ VN = "PasswordComplexity";                     Label = "Password complexity";                              Type = "combo";  Options = @("1 - Large letters only","2 - Large + small letters","3 - Large + small + digits","4 - Large + small + digits + specials (default)","5 - Same as 4, improved readability *","6 - Passphrase, long words *","7 - Passphrase, short words *","8 - Passphrase, short words with unique prefixes *"); Values = @(1,2,3,4,5,6,7,8) }
                @{ VN = "PasswordExpirationProtectionEnabled";    Label = "Enforce maximum password age";                     Type = "bool" }
                @{ VN = "PostAuthenticationResetDelay";           Label = "Post-authentication grace period (hours, 0-24)";   Type = "int" }
                @{ VN = "PostAuthenticationActions";              Label = "Post-authentication actions";                      Type = "combo";  Options = @("1 - Reset the password","3 - Reset + sign out interactive sessions (default)","5 - Reset + reboot","11 - Reset + sign out + terminate remaining processes *"); Values = @(1,3,5,11) }
                @{ VN = "ADPasswordEncryptionEnabled";            Label = "Encrypt the password in Active Directory";         Type = "bool" }
                @{ VN = "ADPasswordEncryptionPrincipal";          Label = "Principal allowed to decrypt";                     Type = "string"; Hint = "Leave empty so only Domain Admins can decrypt. Accepted formats: DOMAIN\Group  -  user@domain.com  -  S-1-5-21-..." }
                @{ VN = "ADEncryptedPasswordHistorySize";         Label = "Encrypted password history size (0-12)";           Type = "int" }
                @{ VN = "ADBackupDSRMPassword";                   Label = "Back up the DSRM password (domain controllers)";   Type = "bool" }
                @{ VN = "AutomaticAccountManagementEnabled";      Label = "Automatic account management (Win 11 24H2+) *";    Type = "bool" }
                @{ VN = "AutomaticAccountManagementTarget";       Label = "Account to manage automatically *";                Type = "combo";  Options = @("0 - Built-in Administrator","1 - New custom account (default)"); Values = @(0,1) }
                @{ VN = "AutomaticAccountManagementNameOrPrefix"; Label = "Automatic account name or prefix *";               Type = "string"; Hint = "Max 14 characters when RandomizeName is enabled (default: WLapsAdmin)" }
                @{ VN = "AutomaticAccountManagementEnableAccount"; Label = "Enable the automatic account *";                  Type = "bool" }
                @{ VN = "AutomaticAccountManagementRandomizeName"; Label = "Randomise the automatic account name *";          Type = "bool" }
            )

            $lapsRowIdx = 0
            foreach ($pd in $lapsParamDefs) {
                [void]$lapsGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

                $existingSetting = $gpo.RegistrySettings | Where-Object { $_.ValueName -eq $pd.VN }
                $currentValue = if ($null -ne $existingSetting) { $existingSetting.Value } else { $null }

                $lapsLabel = New-Object System.Windows.Controls.TextBlock
                $lapsLabel.Text = $pd.Label
                $lapsLabel.VerticalAlignment = "Center"
                $lapsLabel.Foreground = Get-WPFBrush "#555"
                $lapsLabel.Margin = [System.Windows.Thickness]::new(0, 4, 10, 4)
                [System.Windows.Controls.Grid]::SetRow($lapsLabel, $lapsRowIdx)
                [System.Windows.Controls.Grid]::SetColumn($lapsLabel, 0)

                if ($pd.Type -eq "combo") {
                    $lapsCtrl = New-Object System.Windows.Controls.ComboBox
                    $lapsCtrl.FontSize = 12
                    $lapsCtrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                    $lapsCtrl.Tag = $pd.Values
                    foreach ($opt in $pd.Options) {
                        $cbItem = New-Object System.Windows.Controls.ComboBoxItem
                        $cbItem.Content = $opt
                        [void]$lapsCtrl.Items.Add($cbItem)
                    }
                    $selIdx = 0
                    if ($null -ne $currentValue) {
                        $fi = [Array]::IndexOf([int[]]$pd.Values, [int]$currentValue)
                        if ($fi -ge 0) { $selIdx = $fi }
                    }
                    $lapsCtrl.SelectedIndex = $selIdx
                } elseif ($pd.Type -eq "bool") {
                    $lapsCtrl = New-Object System.Windows.Controls.CheckBox
                    $lapsCtrl.IsChecked = if ($null -ne $currentValue) { [int]$currentValue -ne 0 } else { $false }
                    $lapsCtrl.VerticalAlignment = "Center"
                } elseif ($pd.Type -eq "string") {
                    $lapsCtrl = New-Object System.Windows.Controls.TextBox
                    $lapsCtrl.Text = if ($null -ne $currentValue) { [string]$currentValue } else { "" }
                    $lapsCtrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                    $lapsCtrl.BorderBrush = Get-WPFBrush "#DDD"
                    $lapsCtrl.FontSize = 12
                } else {
                    $lapsCtrl = New-Object System.Windows.Controls.TextBox
                    $lapsCtrl.Text = if ($null -ne $currentValue) { [string][int]$currentValue } else { "0" }
                    $lapsCtrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                    $lapsCtrl.BorderBrush = Get-WPFBrush "#DDD"
                    $lapsCtrl.FontSize = 12
                }
                # Wrap control + optional hint TextBlock in a StackPanel when a hint is defined
                if ($pd.ContainsKey('Hint')) {
                    $lapsCtrl.Margin = [System.Windows.Thickness]::new(0, 4, 0, 2)

                    # For the encryption principal field, add an AD group search button
                    $lapsInner = if ($pd.VN -eq 'ADPasswordEncryptionPrincipal') {
                        $lapsSrchBtn = New-Object System.Windows.Controls.Button
                        $lapsSrchBtn.Content = "Search AD"
                        $lapsSrchBtn.Padding = [System.Windows.Thickness]::new(10, 4, 10, 4)
                        $lapsSrchBtn.Margin = [System.Windows.Thickness]::new(6, 0, 0, 0)
                        $lapsSrchBtn.FontSize = 11
                        $lapsSrchBtn.Background = Get-WPFBrush "#EBF5FB"
                        $lapsSrchBtn.Foreground = Get-WPFBrush "#0078D4"
                        $lapsSrchBtn.BorderBrush = Get-WPFBrush "#AED6F1"
                        $lapsSrchBtn.BorderThickness = [System.Windows.Thickness]::new(1)
                        $lapsSrchBtn.Cursor = "Hand"
                        $lapsSrchBtn.VerticalAlignment = "Center"
                        $lapsSrchBtn.Tag = $lapsCtrl
                        [System.Windows.Controls.DockPanel]::SetDock($lapsSrchBtn, "Right")
                        $lapsSrchBtn.Add_Click({
                            $tb = $this.Tag
                            $result = Show-ADGroupSearchDialog
                            if ($result) { $tb.Text = $result }
                        })
                        $lapsDock = New-Object System.Windows.Controls.DockPanel
                        [void]$lapsDock.Children.Add($lapsSrchBtn)
                        [void]$lapsDock.Children.Add($lapsCtrl)
                        $lapsDock
                    } else {
                        $lapsCtrl
                    }

                    $lapsHintBlock = New-Object System.Windows.Controls.TextBlock
                    $lapsHintBlock.Text = $pd.Hint
                    $lapsHintBlock.FontSize = 10
                    $lapsHintBlock.Foreground = Get-WPFBrush "#999"
                    $lapsHintBlock.TextWrapping = "Wrap"
                    $lapsHintBlock.Margin = [System.Windows.Thickness]::new(1, 0, 0, 4)
                    $lapsWrapper = New-Object System.Windows.Controls.StackPanel
                    [void]$lapsWrapper.Children.Add($lapsInner)
                    [void]$lapsWrapper.Children.Add($lapsHintBlock)
                    $lapsGridChild = $lapsWrapper
                } else {
                    $lapsCtrl.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
                    $lapsGridChild = $lapsCtrl
                }
                [System.Windows.Controls.Grid]::SetRow($lapsGridChild, $lapsRowIdx)
                [System.Windows.Controls.Grid]::SetColumn($lapsGridChild, 1)

                [void]$lapsGrid.Children.Add($lapsLabel)
                [void]$lapsGrid.Children.Add($lapsGridChild)
                $script:GPOLAPSControls[$pd.VN] = $lapsCtrl
                $lapsRowIdx++
            }

            $lapsExpander.Content = $lapsGrid
            [void]$outerStack.Children.Add($lapsExpander)
        }

        # Optional explanatory note, driven by the optional "Note"/"NoteSummary" fields on a
        # GPO in Config\GPO-Config.json rather than by a hardcoded test on the GPO name, so
        # any GPO needing a rationale gets one for free. NoteSummary stays visible on the
        # card (the takeaway), Note opens on click -- same idiom as the Hardening tab's
        # "How OUs and groups interact" link, which keeps a long rationale from bloating
        # the card.
        if ($gpo.Note) {
            $noteSummary = if ($gpo.NoteSummary) { $gpo.NoteSummary } else { "Deployment note" }

            $noteLink = New-Object System.Windows.Controls.TextBlock
            $noteLink.Text = [char]0x24D8 + "  $noteSummary"
            $noteLink.FontSize = 11
            $noteLink.Foreground = Get-WPFBrush "#0078D4"
            $noteLink.Margin = [System.Windows.Thickness]::new(58, 6, 0, 0)
            $noteLink.Cursor = [System.Windows.Input.Cursors]::Hand
            $noteLink.TextWrapping = "Wrap"
            $noteLink.TextDecorations = [System.Windows.TextDecorations]::Underline

            # GetNewClosure captures this iteration's values. A plain scriptblock would
            # resolve $gpo at click time and every card would show the last GPO's note.
            $noteTitle = [string]$gpo.Name
            $noteBody  = [string]$gpo.Note
            $noteLink.Add_MouseLeftButtonDown({
                [System.Windows.MessageBox]::Show(
                    $noteBody, $noteTitle,
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)
            }.GetNewClosure())

            [void]$outerStack.Children.Add($noteLink)
        }

        # Link Targets expander
        $linkExpander = New-Object System.Windows.Controls.Expander
        $linkExpander.Header = "Link Targets (OUs)"
        $linkExpander.Margin = [System.Windows.Thickness]::new(58, 4, 0, 0)
        $linkExpander.FontSize = 12

        $linkStack = New-Object System.Windows.Controls.StackPanel
        $linkStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

        $linkHint = New-Object System.Windows.Controls.TextBlock
        $linkHint.Text = "One Distinguished Name per line (e.g. OU=Workstations,DC=corp,DC=local)"
        $linkHint.FontSize = 10
        $linkHint.Foreground = Get-WPFBrush "#999"
        $linkHint.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        [void]$linkStack.Children.Add($linkHint)

        $linkTextBox = New-Object System.Windows.Controls.TextBox
        $linkTextBox.AcceptsReturn = $true
        $linkTextBox.TextWrapping = "Wrap"
        $linkTextBox.MinLines = 2
        $linkTextBox.MaxLines = 6
        $linkTextBox.FontSize = 12
        $linkTextBox.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
        $linkTextBox.BorderBrush = Get-WPFBrush "#DDD"
        $linkTextBox.VerticalScrollBarVisibility = "Auto"
        if ($gpo.LinkTargets -and $gpo.LinkTargets.Count -gt 0) {
            $linkTextBox.Text = ($gpo.LinkTargets -join "`r`n")
        }
        $script:GPOLinkControls["$idx"] = $linkTextBox
        [void]$linkStack.Children.Add($linkTextBox)

        $linkExpander.Content = $linkStack
        [void]$outerStack.Children.Add($linkExpander)

        $card.Child = $outerStack
        [void]$UI.GPOTaskList.Children.Add($card)
    }
}

function Invoke-GPOTabRefresh {
    # Save expanded state of every Expander in every GPO card, keyed by card index + header text.
    $expanderStates = @{}
    for ($i = 0; $i -lt $UI.GPOTaskList.Children.Count; $i++) {
        $outerStack = $UI.GPOTaskList.Children[$i].Child
        $cardStates = @{}
        foreach ($child in $outerStack.Children) {
            if ($child -is [System.Windows.Controls.Expander]) {
                $cardStates[$child.Header] = $child.IsExpanded
            }
        }
        $expanderStates[$i] = $cardStates
    }

    $searchText = $UI.SearchBox.Text

    Populate-GPOTab

    # Restore expander states
    for ($i = 0; $i -lt $UI.GPOTaskList.Children.Count; $i++) {
        if (-not $expanderStates.ContainsKey($i)) { continue }
        $outerStack = $UI.GPOTaskList.Children[$i].Child
        foreach ($child in $outerStack.Children) {
            if ($child -is [System.Windows.Controls.Expander] -and $expanderStates[$i].ContainsKey($child.Header)) {
                $child.IsExpanded = $expanderStates[$i][$child.Header]
            }
        }
    }

    # Re-apply the search filter if the user had typed something
    if (-not [string]::IsNullOrWhiteSpace($searchText)) {
        Invoke-Search $searchText
    }
}

function New-TieringTreeItem {
    param($OU, [string]$ParentDN)

    $item = New-Object System.Windows.Controls.TreeViewItem
    $item.Header = $OU.Name
    $item.IsExpanded = $true
    $item.FontSize = 13
    $item.Padding = [System.Windows.Thickness]::new(2)

    $dn = "OU=$($OU.Name),$ParentDN"
    $item.Tag = @{
        Name        = $OU.Name
        Description = if ($OU.Description) { $OU.Description } else { "" }
        Protected   = if ($null -ne $OU.ProtectedFromAccidentalDeletion) { [bool]$OU.ProtectedFromAccidentalDeletion } else { $true }
        DN          = $dn
    }

    if ($OU.Children) {
        foreach ($child in $OU.Children) {
            $childItem = New-TieringTreeItem -OU $child -ParentDN $dn
            $item.Items.Add($childItem) | Out-Null
        }
    }

    return $item
}

function Update-TreeItemDN($item) {
    $parent = $item.Parent
    if ($parent -is [System.Windows.Controls.TreeView]) {
        $parentDN = $UI.TieringBaseDN.Text
    } else {
        $parentDN = $parent.Tag.DN
    }
    $item.Tag.DN = "OU=$($item.Tag.Name),$parentDN"

    # Recursively update children
    foreach ($child in $item.Items) {
        Update-TreeItemDN $child
    }
}

function Populate-TieringTab {
    $UI.TieringTree.Items.Clear()
    $baseDN = $script:Configs.Tiering.Settings.BaseDN
    $UI.TieringBaseDN.Text = $baseDN

    foreach ($ou in $script:Configs.Tiering.OUStructure) {
        $item = New-TieringTreeItem -OU $ou -ParentDN $baseDN
        $UI.TieringTree.Items.Add($item) | Out-Null
    }
}

function Populate-RBACTab {
    $UI.RBACRoleList.Items.Clear()

    foreach ($role in $script:Configs.RBAC.Roles) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Tag = $role

        $stack = New-Object System.Windows.Controls.StackPanel
        $stack.Margin = [System.Windows.Thickness]::new(4, 6, 4, 6)

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $role.Name
        $nameBlock.FontWeight = "SemiBold"
        $nameBlock.FontSize = 13

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $role.Description
        $descBlock.FontSize = 11
        $descBlock.Foreground = Get-WPFBrush "#888"
        $descBlock.TextWrapping = "Wrap"

        $badgeStack = New-Object System.Windows.Controls.StackPanel
        $badgeStack.Orientation = "Horizontal"
        $badgeStack.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0)

        $dlCount = $role.DomainLocalGroups.Count
        $badge = New-Object System.Windows.Controls.TextBlock
        $badge.Text = "$dlCount DL groups"
        $badge.FontSize = 10
        $badge.Foreground = Get-WPFBrush "#0078D4"
        $badge.Background = Get-WPFBrush "#E8F2FC"
        $badge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        [void]$badgeStack.Children.Add($badge)

        $permCount = ($role.DomainLocalGroups | ForEach-Object { $_.Permissions.Count } | Measure-Object -Sum).Sum
        $permBadge = New-Object System.Windows.Controls.TextBlock
        $permBadge.Text = "$permCount perms"
        $permBadge.FontSize = 10
        $permBadge.Foreground = Get-WPFBrush "#6C3483"
        $permBadge.Background = Get-WPFBrush "#F3E8FC"
        $permBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        $permBadge.Margin = [System.Windows.Thickness]::new(6, 0, 0, 0)
        [void]$badgeStack.Children.Add($permBadge)

        [void]$stack.Children.Add($nameBlock)
        [void]$stack.Children.Add($descBlock)
        [void]$stack.Children.Add($badgeStack)

        $item.Content = $stack
        $UI.RBACRoleList.Items.Add($item) | Out-Null
    }
}

function Populate-PSOTab {
    $UI.PSOPolicyList.Children.Clear()
    $script:PSOToggles = @()
    $script:PSOParamControls = @{}
    $script:PSOAppliesToControls = @{}

    for ($i = 0; $i -lt $script:Configs.PSO.Policies.Count; $i++) {
        $policy = $script:Configs.PSO.Policies[$i]
        $idx = $i

        # Card border
        $card = New-Object System.Windows.Controls.Border
        $card.Background = Get-WPFBrush "#FFFFFF"
        $card.CornerRadius = [System.Windows.CornerRadius]::new(8)
        $card.Padding = [System.Windows.Thickness]::new(16)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $card.BorderBrush = Get-WPFBrush "#E5E5E5"
        $card.BorderThickness = [System.Windows.Thickness]::new(1)

        $outerStack = New-Object System.Windows.Controls.StackPanel

        # Header row: toggle + text + precedence badge
        $headerDock = New-Object System.Windows.Controls.DockPanel

        $toggle = New-Object System.Windows.Controls.CheckBox
        $toggle.IsChecked = [bool]$policy.Enabled
        $toggle.Style = $script:Window.FindResource("ToggleSwitch")
        $toggle.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($toggle, "Left")
        $script:PSOToggles += $toggle

        # Precedence badge (updated live)
        $precBadge = New-Object System.Windows.Controls.TextBlock
        $precBadge.Text = "P: $($policy.Precedence)"
        $precBadge.FontSize = 10
        $precBadge.Foreground = Get-WPFBrush "#6C3483"
        $precBadge.Background = Get-WPFBrush "#F3E8FC"
        $precBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        $precBadge.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($precBadge, "Right")

        # Subjects count badge (updated live)
        $subjectCount = if ($policy.AppliesTo) { $policy.AppliesTo.Count } else { 0 }
        $subBadge = New-Object System.Windows.Controls.TextBlock
        $subBadge.Text = "$subjectCount subjects"
        $subBadge.FontSize = 10
        $subBadge.Foreground = Get-WPFBrush "#1E8449"
        $subBadge.Background = Get-WPFBrush "#E8F8F0"
        $subBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        $subBadge.Margin = [System.Windows.Thickness]::new(0, 0, 4, 0)
        $subBadge.VerticalAlignment = "Center"
        $subBadge.Visibility = if ($subjectCount -gt 0) { "Visible" } else { "Collapsed" }
        [System.Windows.Controls.DockPanel]::SetDock($subBadge, "Right")
        [void]$headerDock.Children.Add($subBadge)

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.Margin = [System.Windows.Thickness]::new(14, 0, 10, 0)

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $policy.Name
        $nameBlock.FontSize = 14
        $nameBlock.FontWeight = "SemiBold"

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $policy.Description
        $descBlock.FontSize = 12
        $descBlock.Foreground = Get-WPFBrush "#666666"
        $descBlock.TextWrapping = "Wrap"

        [void]$textStack.Children.Add($nameBlock)
        [void]$textStack.Children.Add($descBlock)

        [void]$headerDock.Children.Add($toggle)
        [void]$headerDock.Children.Add($precBadge)
        [void]$headerDock.Children.Add($textStack)
        [void]$outerStack.Children.Add($headerDock)

        # Policy Settings expander
        $expander = New-Object System.Windows.Controls.Expander
        $expander.Header = "Policy Settings"
        $expander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
        $expander.FontSize = 12

        $paramGrid = New-Object System.Windows.Controls.Grid
        $paramGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
        $col1 = New-Object System.Windows.Controls.ColumnDefinition
        $col1.Width = [System.Windows.GridLength]::new(220)
        $col2 = New-Object System.Windows.Controls.ColumnDefinition
        $col2.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        [void]$paramGrid.ColumnDefinitions.Add($col1)
        [void]$paramGrid.ColumnDefinitions.Add($col2)

        $paramDefs = @(
            @{ Name = "Precedence"; Type = "int" }
            @{ Name = "ComplexityEnabled"; Type = "bool" }
            @{ Name = "MinPasswordLength"; Type = "int" }
            @{ Name = "MinPasswordAgeDays"; Type = "int" }
            @{ Name = "MaxPasswordAgeDays"; Type = "int" }
            @{ Name = "PasswordHistoryCount"; Type = "int" }
            @{ Name = "LockoutThreshold"; Type = "int" }
            @{ Name = "LockoutDurationMinutes"; Type = "int" }
            @{ Name = "LockoutObservationWindowMinutes"; Type = "int" }
            @{ Name = "ReversibleEncryptionEnabled"; Type = "bool" }
            @{ Name = "ProtectedFromAccidentalDeletion"; Type = "bool" }
        )

        $rowIdx = 0
        foreach ($paramDef in $paramDefs) {
            [void]$paramGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

            $label = New-Object System.Windows.Controls.TextBlock
            $label.Text = $paramDef.Name
            $label.VerticalAlignment = "Center"
            $label.Foreground = Get-WPFBrush "#555"
            $label.Margin = [System.Windows.Thickness]::new(0, 4, 10, 4)
            [System.Windows.Controls.Grid]::SetRow($label, $rowIdx)
            [System.Windows.Controls.Grid]::SetColumn($label, 0)

            $paramValue = $policy.($paramDef.Name)
            if ($paramDef.Type -eq "bool") {
                $ctrl = New-Object System.Windows.Controls.CheckBox
                $ctrl.IsChecked = [bool]$paramValue
                $ctrl.VerticalAlignment = "Center"
            } else {
                $ctrl = New-Object System.Windows.Controls.TextBox
                $ctrl.Text = [string]$paramValue
                $ctrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                $ctrl.BorderBrush = Get-WPFBrush "#DDD"
            }
            $ctrl.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
            [System.Windows.Controls.Grid]::SetRow($ctrl, $rowIdx)
            [System.Windows.Controls.Grid]::SetColumn($ctrl, 1)

            [void]$paramGrid.Children.Add($label)
            [void]$paramGrid.Children.Add($ctrl)
            $script:PSOParamControls["$idx.$($paramDef.Name)"] = $ctrl
            $rowIdx++
        }

        # "Lock until admin unlocks" checkbox row (sets LockoutDurationMinutes to 0)
        [void]$paramGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        $lockForeverCheck = New-Object System.Windows.Controls.CheckBox
        $lockForeverCheck.Content = "Until an administrator manually unlocks the account"
        $lockForeverCheck.FontSize = 11
        $lockForeverCheck.Foreground = Get-WPFBrush "#555"
        $lockForeverCheck.VerticalAlignment = "Center"
        $lockForeverCheck.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
        [System.Windows.Controls.Grid]::SetRow($lockForeverCheck, $rowIdx)
        [System.Windows.Controls.Grid]::SetColumn($lockForeverCheck, 0)
        [System.Windows.Controls.Grid]::SetColumnSpan($lockForeverCheck, 2)

        $durationCtrl = $script:PSOParamControls["$idx.LockoutDurationMinutes"]
        $isLockForever = [int]$policy.LockoutDurationMinutes -eq 0 -and [int]$policy.LockoutThreshold -gt 0
        $lockForeverCheck.IsChecked = $isLockForever
        if ($isLockForever) { $durationCtrl.IsEnabled = $false }

        $lockForeverCheck.Tag = $durationCtrl
        $lockForeverCheck.Add_Checked({
            $this.Tag.Text = "0"
            $this.Tag.IsEnabled = $false
        })
        $lockForeverCheck.Add_Unchecked({
            $this.Tag.IsEnabled = $true
            if ($this.Tag.Text -eq "0") { $this.Tag.Text = "30" }
        })

        [void]$paramGrid.Children.Add($lockForeverCheck)

        $expander.Content = $paramGrid
        [void]$outerStack.Children.Add($expander)

        # AppliesTo expander
        $appliesToExpander = New-Object System.Windows.Controls.Expander
        $appliesToExpander.Header = "Applies To (Groups / Users)"
        $appliesToExpander.Margin = [System.Windows.Thickness]::new(58, 4, 0, 0)
        $appliesToExpander.FontSize = 12

        $appliesToStack = New-Object System.Windows.Controls.StackPanel
        $appliesToStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

        $appliesToBtnRow = New-Object System.Windows.Controls.StackPanel
        $appliesToBtnRow.Orientation = "Horizontal"
        $appliesToBtnRow.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)

        $searchGroupBtn = New-Object System.Windows.Controls.Button
        $searchGroupBtn.Content = "+ Add Group"
        $searchGroupBtn.Background = Get-WPFBrush "Transparent"
        $searchGroupBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $searchGroupBtn.Foreground = Get-WPFBrush "#0078D4"
        $searchGroupBtn.FontSize = 11
        $searchGroupBtn.Cursor = "Hand"
        $searchGroupBtn.Padding = [System.Windows.Thickness]::new(0, 2, 10, 2)

        $searchUserBtn = New-Object System.Windows.Controls.Button
        $searchUserBtn.Content = "+ Add User"
        $searchUserBtn.Background = Get-WPFBrush "Transparent"
        $searchUserBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $searchUserBtn.Foreground = Get-WPFBrush "#0078D4"
        $searchUserBtn.FontSize = 11
        $searchUserBtn.Cursor = "Hand"
        $searchUserBtn.Padding = [System.Windows.Thickness]::new(0, 2, 0, 2)

        [void]$appliesToBtnRow.Children.Add($searchGroupBtn)
        [void]$appliesToBtnRow.Children.Add($searchUserBtn)
        [void]$appliesToStack.Children.Add($appliesToBtnRow)

        $appliesToTextBox = New-Object System.Windows.Controls.TextBox
        $appliesToTextBox.AcceptsReturn = $true
        $appliesToTextBox.TextWrapping = "Wrap"
        $appliesToTextBox.MinLines = 2
        $appliesToTextBox.MaxLines = 6
        $appliesToTextBox.FontSize = 12
        $appliesToTextBox.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
        $appliesToTextBox.BorderBrush = Get-WPFBrush "#DDD"
        $appliesToTextBox.VerticalScrollBarVisibility = "Auto"
        if ($policy.AppliesTo -and $policy.AppliesTo.Count -gt 0) {
            $appliesToTextBox.Text = ($policy.AppliesTo -join "`r`n")
        }
        $script:PSOAppliesToControls["$idx"] = $appliesToTextBox

        $searchGroupBtn.Tag = $appliesToTextBox
        $searchGroupBtn.Add_Click({
            $result = Show-ADObjectSearchDialog -SearchType "Group"
            if ($result) {
                $tb = $this.Tag
                $existing = @($tb.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                if ($result -notin $existing) {
                    $tb.Text = (($existing + @($result)) -join "`r`n")
                }
            }
        })

        $searchUserBtn.Tag = $appliesToTextBox
        $searchUserBtn.Add_Click({
            $result = Show-ADObjectSearchDialog -SearchType "User"
            if ($result) {
                $tb = $this.Tag
                $existing = @($tb.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                if ($result -notin $existing) {
                    $tb.Text = (($existing + @($result)) -join "`r`n")
                }
            }
        })

        [void]$appliesToStack.Children.Add($appliesToTextBox)

        $appliesToExpander.Content = $appliesToStack
        [void]$outerStack.Children.Add($appliesToExpander)

        # Wire live badge updates
        $precControl = $script:PSOParamControls["$idx.Precedence"]
        $precControl.Tag = $precBadge
        $precControl.Add_TextChanged({
            $this.Tag.Text = "P: $($this.Text)"
        })

        $appliesToTextBox.Tag = $subBadge
        $appliesToTextBox.Add_TextChanged({
            $lines = @($this.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            $count = $lines.Count
            $this.Tag.Text = "$count subjects"
            $this.Tag.Visibility = if ($count -gt 0) { "Visible" } else { "Collapsed" }
        })

        $card.Child = $outerStack
        [void]$UI.PSOPolicyList.Children.Add($card)
    }
}

function Populate-SiloTab {
    $UI.SiloTaskList.Children.Clear()
    $script:SiloToggles = @()
    $script:SiloParamControls = @{}
    $script:SiloComputerControls = @{}
    $script:SiloServiceAccountControls = @{}

    for ($i = 0; $i -lt $script:Configs.Silo.Silos.Count; $i++) {
        $silo = $script:Configs.Silo.Silos[$i]
        $idx = $i

        # Card border
        $card = New-Object System.Windows.Controls.Border
        $card.Background = Get-WPFBrush "#FFFFFF"
        $card.CornerRadius = [System.Windows.CornerRadius]::new(8)
        $card.Padding = [System.Windows.Thickness]::new(16)
        $card.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $card.BorderBrush = Get-WPFBrush "#E5E5E5"
        $card.BorderThickness = [System.Windows.Thickness]::new(1)

        $outerStack = New-Object System.Windows.Controls.StackPanel

        # Header row: toggle + text + badges
        $headerDock = New-Object System.Windows.Controls.DockPanel

        $toggle = New-Object System.Windows.Controls.CheckBox
        $toggle.IsChecked = [bool]$silo.Enabled
        $toggle.Style = $script:Window.FindResource("ToggleSwitch")
        $toggle.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($toggle, "Left")
        $script:SiloToggles += $toggle

        # Enforce/Audit badge
        $enforceLabel = if ($silo.Enforce) { "Enforce" } else { "Audit" }
        $enforceBadge = New-Object System.Windows.Controls.TextBlock
        $enforceBadge.Text = $enforceLabel
        $enforceBadge.FontSize = 10
        $enforceBadge.Foreground = Get-WPFBrush $(if ($silo.Enforce) { "#922B21" } else { "#1E8449" })
        $enforceBadge.Background = Get-WPFBrush $(if ($silo.Enforce) { "#FDEDEC" } else { "#E8F8F0" })
        $enforceBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        $enforceBadge.VerticalAlignment = "Center"
        [System.Windows.Controls.DockPanel]::SetDock($enforceBadge, "Right")

        # Account count badge
        $compCount = if ($silo.Computers) { $silo.Computers.Count } else { 0 }
        $svcCount = if ($silo.ServiceAccounts) { $silo.ServiceAccounts.Count } else { 0 }
        $totalAccounts = $compCount + $svcCount
        $accountBadge = New-Object System.Windows.Controls.TextBlock
        $accountBadge.Text = "$totalAccounts accounts"
        $accountBadge.FontSize = 10
        $accountBadge.Foreground = Get-WPFBrush "#6C3483"
        $accountBadge.Background = Get-WPFBrush "#F3E8FC"
        $accountBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
        $accountBadge.Margin = [System.Windows.Thickness]::new(0, 0, 4, 0)
        $accountBadge.VerticalAlignment = "Center"
        $accountBadge.Visibility = if ($totalAccounts -gt 0) { "Visible" } else { "Collapsed" }
        [System.Windows.Controls.DockPanel]::SetDock($accountBadge, "Right")
        [void]$headerDock.Children.Add($accountBadge)

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.Margin = [System.Windows.Thickness]::new(14, 0, 10, 0)

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $silo.Name
        $nameBlock.FontSize = 14
        $nameBlock.FontWeight = "SemiBold"

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $silo.Description
        $descBlock.FontSize = 12
        $descBlock.Foreground = Get-WPFBrush "#666666"
        $descBlock.TextWrapping = "Wrap"

        [void]$textStack.Children.Add($nameBlock)
        [void]$textStack.Children.Add($descBlock)

        [void]$headerDock.Children.Add($toggle)
        [void]$headerDock.Children.Add($enforceBadge)
        [void]$headerDock.Children.Add($textStack)
        [void]$outerStack.Children.Add($headerDock)

        # Silo Settings expander
        $expander = New-Object System.Windows.Controls.Expander
        $expander.Header = "Silo Settings"
        $expander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
        $expander.FontSize = 12

        $paramGrid = New-Object System.Windows.Controls.Grid
        $paramGrid.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)
        $col1 = New-Object System.Windows.Controls.ColumnDefinition
        $col1.Width = [System.Windows.GridLength]::new(220)
        $col2 = New-Object System.Windows.Controls.ColumnDefinition
        $col2.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        [void]$paramGrid.ColumnDefinitions.Add($col1)
        [void]$paramGrid.ColumnDefinitions.Add($col2)

        $paramDefs = @(
            @{ Name = "TGTLifetimeMinutes"; Type = "int" }
            @{ Name = "Enforce"; Type = "bool" }
        )

        $rowIdx = 0
        foreach ($paramDef in $paramDefs) {
            [void]$paramGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

            $label = New-Object System.Windows.Controls.TextBlock
            $label.Text = $paramDef.Name
            $label.VerticalAlignment = "Center"
            $label.Foreground = Get-WPFBrush "#555"
            $label.Margin = [System.Windows.Thickness]::new(0, 4, 10, 4)
            [System.Windows.Controls.Grid]::SetRow($label, $rowIdx)
            [System.Windows.Controls.Grid]::SetColumn($label, 0)

            $paramValue = $silo.($paramDef.Name)
            if ($paramDef.Type -eq "bool") {
                $ctrl = New-Object System.Windows.Controls.CheckBox
                $ctrl.IsChecked = [bool]$paramValue
                $ctrl.VerticalAlignment = "Center"
            } else {
                $ctrl = New-Object System.Windows.Controls.TextBox
                $ctrl.Text = [string]$paramValue
                $ctrl.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
                $ctrl.BorderBrush = Get-WPFBrush "#DDD"
            }
            $ctrl.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
            [System.Windows.Controls.Grid]::SetRow($ctrl, $rowIdx)
            [System.Windows.Controls.Grid]::SetColumn($ctrl, 1)

            [void]$paramGrid.Children.Add($label)
            [void]$paramGrid.Children.Add($ctrl)
            $script:SiloParamControls["$idx.$($paramDef.Name)"] = $ctrl
            $rowIdx++
        }

        # Wire enforce badge to live-update
        $enforceCtrl = $script:SiloParamControls["$idx.Enforce"]
        $enforceCtrl.Tag = $enforceBadge
        $enforceCtrl.Add_Checked({
            $this.Tag.Text = "Enforce"
            $this.Tag.Foreground = Get-WPFBrush "#922B21"
            $this.Tag.Background = Get-WPFBrush "#FDEDEC"
        })
        $enforceCtrl.Add_Unchecked({
            $this.Tag.Text = "Audit"
            $this.Tag.Foreground = Get-WPFBrush "#1E8449"
            $this.Tag.Background = Get-WPFBrush "#E8F8F0"
        })

        $expander.Content = $paramGrid
        [void]$outerStack.Children.Add($expander)

        # Computers expander
        $computersExpander = New-Object System.Windows.Controls.Expander
        $computersExpander.Header = "Computers"
        $computersExpander.Margin = [System.Windows.Thickness]::new(58, 4, 0, 0)
        $computersExpander.FontSize = 12

        $computersStack = New-Object System.Windows.Controls.StackPanel
        $computersStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

        $computersHint = New-Object System.Windows.Controls.TextBlock
        $computersHint.Text = "One computer SAM name per line, with trailing $ (e.g. WEB01$)"
        $computersHint.FontSize = 10
        $computersHint.Foreground = Get-WPFBrush "#999"
        $computersHint.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        [void]$computersStack.Children.Add($computersHint)

        $computersTextBox = New-Object System.Windows.Controls.TextBox
        $computersTextBox.AcceptsReturn = $true
        $computersTextBox.TextWrapping = "Wrap"
        $computersTextBox.MinLines = 2
        $computersTextBox.MaxLines = 6
        $computersTextBox.FontSize = 12
        $computersTextBox.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
        $computersTextBox.BorderBrush = Get-WPFBrush "#DDD"
        $computersTextBox.VerticalScrollBarVisibility = "Auto"
        if ($silo.Computers -and $silo.Computers.Count -gt 0) {
            $computersTextBox.Text = ($silo.Computers -join "`r`n")
        }
        $script:SiloComputerControls["$idx"] = $computersTextBox
        [void]$computersStack.Children.Add($computersTextBox)

        $computersExpander.Content = $computersStack
        [void]$outerStack.Children.Add($computersExpander)

        # Service Accounts expander
        $svcExpander = New-Object System.Windows.Controls.Expander
        $svcExpander.Header = "Service Accounts"
        $svcExpander.Margin = [System.Windows.Thickness]::new(58, 4, 0, 0)
        $svcExpander.FontSize = 12

        $svcStack = New-Object System.Windows.Controls.StackPanel
        $svcStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

        $svcHint = New-Object System.Windows.Controls.TextBlock
        $svcHint.Text = "One service account SAM name per line (e.g. svc-monitoring-web)"
        $svcHint.FontSize = 10
        $svcHint.Foreground = Get-WPFBrush "#999"
        $svcHint.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        [void]$svcStack.Children.Add($svcHint)

        $svcTextBox = New-Object System.Windows.Controls.TextBox
        $svcTextBox.AcceptsReturn = $true
        $svcTextBox.TextWrapping = "Wrap"
        $svcTextBox.MinLines = 2
        $svcTextBox.MaxLines = 6
        $svcTextBox.FontSize = 12
        $svcTextBox.Padding = [System.Windows.Thickness]::new(6, 4, 6, 4)
        $svcTextBox.BorderBrush = Get-WPFBrush "#DDD"
        $svcTextBox.VerticalScrollBarVisibility = "Auto"
        if ($silo.ServiceAccounts -and $silo.ServiceAccounts.Count -gt 0) {
            $svcTextBox.Text = ($silo.ServiceAccounts -join "`r`n")
        }
        $script:SiloServiceAccountControls["$idx"] = $svcTextBox
        [void]$svcStack.Children.Add($svcTextBox)

        $svcExpander.Content = $svcStack
        [void]$outerStack.Children.Add($svcExpander)

        # Wire live account badge updates
        $computersTextBox.Tag = $accountBadge
        $svcTextBox.Tag = $accountBadge
        # Store both textboxes in a shared tag for counting
        $badgeState = @{ CompBox = $computersTextBox; SvcBox = $svcTextBox; Badge = $accountBadge }
        $computersTextBox.Add_TextChanged({
            $state = $this.Tag
            if ($state -is [hashtable]) { $state = $state } else { return }
        }.GetNewClosure())
        # Use a simpler approach: each textbox updates the badge by recounting both
        $updateBadge = {
            param($compBox, $svcBox, $badge)
            $compLines = @($compBox.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            $svcLines = @($svcBox.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            $total = $compLines.Count + $svcLines.Count
            $badge.Text = "$total accounts"
            $badge.Visibility = if ($total -gt 0) { "Visible" } else { "Collapsed" }
        }

        $computersTextBox.Tag = @{ CompBox = $computersTextBox; SvcBox = $svcTextBox; Badge = $accountBadge; Update = $updateBadge }
        $computersTextBox.Add_TextChanged({
            $s = $this.Tag
            & $s.Update $s.CompBox $s.SvcBox $s.Badge
        })
        $svcTextBox.Tag = @{ CompBox = $computersTextBox; SvcBox = $svcTextBox; Badge = $accountBadge; Update = $updateBadge }
        $svcTextBox.Add_TextChanged({
            $s = $this.Tag
            & $s.Update $s.CompBox $s.SvcBox $s.Badge
        })

        $card.Child = $outerStack
        [void]$UI.SiloTaskList.Children.Add($card)
    }
}

function Populate-JITTab {
    $cfg = $script:Configs.JIT
    $s = $cfg.Settings
    $UI.JITToolsSharePath.Text = $s.ToolsSharePath
    $UI.JITInstallPath.Text = $s.InstallPath
    $UI.JITFilteringGroupsOU.Text = $s.FilteringGroupsOU
    $UI.JITGPOName.Text = $s.GPO.Name
    $UI.JITGPODescription.Text = $s.GPO.Description
    $UI.JITGPOLinkTargets.Text = ($s.GPO.LinkTargets -join "`n")
}

function Show-FunctionalLevelPrereqDialog {
    param(
        [ValidateSet('Domain', 'Forest')]
        [string]$Scope,
        [string]$TargetLevel
    )

    # Import the module to access the prerequisite check functions
    $appRoot    = Split-Path (Split-Path $script:ScriptPaths.Hardening)
    $modulePath = Join-Path $appRoot "Modules\Hardening\Hardening.psm1"
    $checks  = @()
    $subtitle = "$Scope`: $TargetLevel"
    try {
        Import-Module $modulePath -Force -ErrorAction Stop
        if ($Scope -eq 'Domain') {
            $checks = @(Test-HardeningDomainFunctionalLevelPrerequisites -TargetDomainLevel $TargetLevel `
                -Server $script:Connection.Server -Credential $script:Connection.Credential)
        }
        else {
            $checks = @(Test-HardeningForestFunctionalLevelPrerequisites -TargetForestLevel $TargetLevel `
                -Server $script:Connection.Server -Credential $script:Connection.Credential)
        }
    }
    catch {
        $checks = @([PSCustomObject]@{
            Name    = "Module initialization"
            Passed  = $false
            Message = "Failed to load or run prerequisite checks: $_"
        })
    }

    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Prerequisite Check — Raise Functional Level" Width="600" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="Prerequisite Check" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,4"/>
        <TextBlock Name="SubTitle" FontSize="12" Foreground="#666666" Margin="0,0,0,16" TextWrapping="Wrap"/>
        <StackPanel Name="ResultsList" Margin="0,0,0,8"/>
        <Border Name="SummaryBorder" CornerRadius="6" Padding="12,10" Margin="0,8,0,16" BorderThickness="1">
            <TextBlock Name="SummaryText" FontSize="13" FontWeight="SemiBold" TextWrapping="Wrap"/>
        </Border>
        <Button Name="BtnClose" Content="Close" HorizontalAlignment="Right"
                Padding="16,8" FontSize="13" Background="#E0E0E0" BorderThickness="0" Cursor="Hand"/>
    </StackPanel>
</Window>
"@
    [xml]$xDoc = $dialogXaml
    $xReader  = [System.Xml.XmlNodeReader]::new($xDoc)
    $dialog   = [System.Windows.Markup.XamlReader]::Load($xReader)
    $dialog.Owner = $script:Window

    $dSubTitle  = $dialog.FindName("SubTitle")
    $dResults   = $dialog.FindName("ResultsList")
    $dSumBorder = $dialog.FindName("SummaryBorder")
    $dSummary   = $dialog.FindName("SummaryText")
    $dBtnClose  = $dialog.FindName("BtnClose")

    $dSubTitle.Text = $subtitle

    foreach ($check in $checks) {
        $row = New-Object System.Windows.Controls.Border
        $row.Margin           = [System.Windows.Thickness]::new(0, 0, 0, 4)
        $row.Padding          = [System.Windows.Thickness]::new(10, 8, 10, 8)
        $row.CornerRadius     = [System.Windows.CornerRadius]::new(4)
        $row.BorderThickness  = [System.Windows.Thickness]::new(1)
        $row.Background       = if ($check.Passed) { Get-WPFBrush "#F0FFF4" } else { Get-WPFBrush "#FFF5F5" }
        $row.BorderBrush      = if ($check.Passed) { Get-WPFBrush "#B2DFDB" } else { Get-WPFBrush "#FFCDD2" }

        $rowDock = New-Object System.Windows.Controls.DockPanel

        $icon = New-Object System.Windows.Controls.TextBlock
        $icon.Text             = if ($check.Passed) { [char]0x2714 } else { [char]0x2718 }
        $icon.FontSize         = 14
        $icon.FontWeight       = "Bold"
        $icon.Foreground       = if ($check.Passed) { Get-WPFBrush "#27AE60" } else { Get-WPFBrush "#E53935" }
        $icon.VerticalAlignment = "Top"
        $icon.Margin           = [System.Windows.Thickness]::new(0, 1, 10, 0)
        [System.Windows.Controls.DockPanel]::SetDock($icon, "Left")

        $textStack = New-Object System.Windows.Controls.StackPanel

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text       = $check.Name
        $nameBlock.FontSize   = 13
        $nameBlock.FontWeight = "SemiBold"
        $nameBlock.Foreground = if ($check.Passed) { Get-WPFBrush "#1B4F72" } else { Get-WPFBrush "#922B21" }

        $msgBlock = New-Object System.Windows.Controls.TextBlock
        $msgBlock.Text        = $check.Message
        $msgBlock.FontSize    = 11
        $msgBlock.Foreground  = Get-WPFBrush "#555555"
        $msgBlock.TextWrapping = "Wrap"
        $msgBlock.Margin      = [System.Windows.Thickness]::new(0, 2, 0, 0)

        [void]$textStack.Children.Add($nameBlock)
        [void]$textStack.Children.Add($msgBlock)
        [void]$rowDock.Children.Add($icon)
        [void]$rowDock.Children.Add($textStack)
        $row.Child = $rowDock
        [void]$dResults.Children.Add($row)
    }

    $failCount = @($checks | Where-Object { -not $_.Passed }).Count
    if ($failCount -eq 0) {
        $dSumBorder.Background  = Get-WPFBrush "#E8F5E9"
        $dSumBorder.BorderBrush = Get-WPFBrush "#A5D6A7"
        $dSummary.Foreground    = Get-WPFBrush "#1B5E20"
        $dSummary.Text          = "All prerequisites are met. The task is ready to deploy."
    }
    else {
        $dSumBorder.Background  = Get-WPFBrush "#FFEBEE"
        $dSumBorder.BorderBrush = Get-WPFBrush "#EF9A9A"
        $dSummary.Foreground    = Get-WPFBrush "#B71C1C"
        $dSummary.Text          = "$failCount prerequisite check(s) failed. The task will be aborted at deployment time."
    }

    $dBtnClose.Add_Click({ $dialog.Close() })
    $dialog.ShowDialog() | Out-Null
}

function Show-AddSiloDialog {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Authentication Policy Silo" Width="520" SizeToContent="Height" WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize" Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="New Authentication Policy Silo" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,20"/>

        <TextBlock Text="Silo Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox Name="SiloName" FontSize="13" Padding="6,4" Margin="0,0,0,12"/>

        <TextBlock Text="Description" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox Name="SiloDesc" FontSize="13" Padding="6,4" Margin="0,0,0,12"/>

        <Border Background="#E8F4FD" CornerRadius="6" Padding="14" Margin="0,0,0,12">
            <StackPanel>
                <TextBlock Text="Policy Settings" FontSize="13" FontWeight="SemiBold" Foreground="#0078D4" Margin="0,0,0,8"/>
                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="TGT Lifetime (minutes)" FontSize="12" Foreground="#555" Width="180" VerticalAlignment="Center"/>
                    <TextBox Name="TGTLifetime" Text="240" FontSize="12" Padding="6,4" Width="100"/>
                </StackPanel>
                <CheckBox Name="EnforceCheck" Content="Enforce (uncheck for Audit mode)" FontSize="12" Margin="0,4,0,0"/>
            </StackPanel>
        </Border>

        <Border Background="#FEF9E7" CornerRadius="6" Padding="14" Margin="0,0,0,12">
            <StackPanel>
                <TextBlock Text="Computers" FontSize="13" FontWeight="SemiBold" Foreground="#7D6608" Margin="0,0,0,4"/>
                <TextBlock Text="One computer SAM name per line, with trailing $ (e.g. WEB01$)" FontSize="10" Foreground="#999" Margin="0,0,0,4"/>
                <TextBox Name="Computers" AcceptsReturn="True" TextWrapping="Wrap" MinLines="2" MaxLines="4"
                         FontSize="12" Padding="6,4" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
        </Border>

        <Border Background="#F5F5F5" CornerRadius="6" Padding="14" Margin="0,0,0,16">
            <StackPanel>
                <TextBlock Text="Service Accounts" FontSize="13" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
                <TextBlock Text="One service account SAM name per line (e.g. svc-monitoring-web)" FontSize="10" Foreground="#999" Margin="0,0,0,4"/>
                <TextBox Name="ServiceAccounts" AcceptsReturn="True" TextWrapping="Wrap" MinLines="2" MaxLines="4"
                         FontSize="12" Padding="6,4" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
        </Border>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="BtnCancel" Content="Cancel" Padding="16,8" FontSize="13" Margin="0,0,8,0"
                    Background="#E0E0E0" BorderThickness="0" Cursor="Hand"/>
            <Button Name="BtnOK" Content="Add Silo" Padding="16,8" FontSize="13"
                    Background="#0078D4" Foreground="White" BorderThickness="0" Cursor="Hand" FontWeight="SemiBold"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$xDoc = $dialogXaml
    $xReader = [System.Xml.XmlNodeReader]::new($xDoc)
    $dialog = [System.Windows.Markup.XamlReader]::Load($xReader)
    $dialog.Owner = $script:Window

    $dUI = @{}
    foreach ($name in @('SiloName','SiloDesc','TGTLifetime','EnforceCheck','Computers','ServiceAccounts','BtnCancel','BtnOK')) {
        $dUI[$name] = $dialog.FindName($name)
    }

    $script:dialogResult = $null
    $dUI.BtnCancel.Add_Click({ $dialog.Close() })
    $dUI.BtnOK.Add_Click({
        $name = $dUI.SiloName.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($name)) {
            [System.Windows.MessageBox]::Show("Silo name is required.", "Validation", "OK", "Warning")
            return
        }
        $tgt = if ($dUI.TGTLifetime.Text -match '^\d+$') { [int]$dUI.TGTLifetime.Text } else { 240 }
        if ($tgt -lt 45) {
            [System.Windows.MessageBox]::Show("TGT lifetime must be >= 45 minutes.", "Validation", "OK", "Warning")
            return
        }
        $computers = if ([string]::IsNullOrWhiteSpace($dUI.Computers.Text)) { @() } else {
            @($dUI.Computers.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        $svcAccounts = if ([string]::IsNullOrWhiteSpace($dUI.ServiceAccounts.Text)) { @() } else {
            @($dUI.ServiceAccounts.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        $script:dialogResult = [PSCustomObject]@{
            Name               = $name
            Description        = $dUI.SiloDesc.Text.Trim()
            Enabled            = $true
            Enforce            = [bool]$dUI.EnforceCheck.IsChecked
            TGTLifetimeMinutes = $tgt
            ServiceAccounts    = $svcAccounts
            Computers          = $computers
        }
        $dialog.Close()
    })

    $dialog.ShowDialog() | Out-Null
    return $script:dialogResult
}

function Show-DeleteSiloDialog([string[]]$names) {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Delete Silo" Width="400" SizeToContent="Height" WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize" Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="Select silo to delete:" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,12"/>
        <ListBox Name="SiloList" FontSize="13" MaxHeight="200" Margin="0,0,0,16"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="BtnCancel" Content="Cancel" Padding="16,8" FontSize="13" Margin="0,0,8,0"
                    Background="#E0E0E0" BorderThickness="0" Cursor="Hand"/>
            <Button Name="BtnOK" Content="Delete" Padding="16,8" FontSize="13"
                    Background="#E74C3C" Foreground="White" BorderThickness="0" Cursor="Hand" FontWeight="SemiBold"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$xDoc = $dialogXaml
    $xReader = [System.Xml.XmlNodeReader]::new($xDoc)
    $dialog = [System.Windows.Markup.XamlReader]::Load($xReader)
    $dialog.Owner = $script:Window

    $list = $dialog.FindName("SiloList")
    foreach ($n in $names) { [void]$list.Items.Add($n) }

    $script:dialogResult = $null
    $dialog.FindName("BtnCancel").Add_Click({ $dialog.Close() })
    $dialog.FindName("BtnOK").Add_Click({
        if ($list.SelectedItem) {
            $script:dialogResult = $list.SelectedItem.ToString()
            $dialog.Close()
        }
    })

    $dialog.ShowDialog() | Out-Null
    return $script:dialogResult
}

function Show-RBACRoleDetail($role) {
    $UI.RBACDetailTitle.Text = $role.Name
    $UI.RBACDetailDesc.Text = $role.Description
    $UI.RBACGGPanel.Visibility = "Visible"
    $UI.RBACDLHeader.Visibility = "Visible"
    $UI.RBACGGName.Text = $role.GlobalGroup.Name
    $UI.RBACGGDesc.Text = $role.GlobalGroup.Description
    $UI.RBACGGOU.Text   = $role.GlobalGroup.OU

    $UI.RBACGGMemberOfList.Children.Clear()
    $moList = if ($role.GlobalGroup.MemberOf) { @($role.GlobalGroup.MemberOf) } else { @() }
    foreach ($groupName in $moList) {
        $row = New-Object System.Windows.Controls.DockPanel
        $row.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)

        $removeBtn = New-Object System.Windows.Controls.Button
        $removeBtn.Content = [char]0x00D7
        $removeBtn.FontSize = 12
        $removeBtn.Background = Get-WPFBrush "Transparent"
        $removeBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $removeBtn.Foreground = Get-WPFBrush "#A93226"
        $removeBtn.Cursor = "Hand"
        $removeBtn.Padding = [System.Windows.Thickness]::new(4, 0, 4, 0)
        $removeBtn.VerticalAlignment = "Center"
        $removeBtn.Tag = @{ Role = $role; Group = $groupName }
        $removeBtn.Add_Click({
            $ctx = $this.Tag
            $ctx.Role.GlobalGroup.MemberOf = @($ctx.Role.GlobalGroup.MemberOf | Where-Object { $_ -ne $ctx.Group })
            $script:UnsavedChanges.RBAC = $true
            Refresh-RBACRole $ctx.Role.Name
        })
        [System.Windows.Controls.DockPanel]::SetDock($removeBtn, "Right")
        [void]$row.Children.Add($removeBtn)

        $label = New-Object System.Windows.Controls.TextBlock
        $label.Text = $groupName
        $label.FontSize = 12
        $label.VerticalAlignment = "Center"
        $label.Foreground = Get-WPFBrush "#333333"
        [void]$row.Children.Add($label)

        [void]$UI.RBACGGMemberOfList.Children.Add($row)
    }

    $UI.RBACDLList.Children.Clear()

    # Infer tier from role name
    $tier = if ($role.Name -match '^(T\d)') { $Matches[1] } else { "T0" }

    # DL Group action buttons
    $dlBtnPanel = New-Object System.Windows.Controls.StackPanel
    $dlBtnPanel.Orientation = "Horizontal"
    $dlBtnPanel.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)

    $createDLBtn = New-Object System.Windows.Controls.Button
    $createDLBtn.Content = "+ Create DL Group"
    $createDLBtn.Background = Get-WPFBrush "#E8E8E8"
    $createDLBtn.BorderThickness = [System.Windows.Thickness]::new(0)
    $createDLBtn.Padding = [System.Windows.Thickness]::new(12, 6, 12, 6)
    $createDLBtn.FontSize = 12
    $createDLBtn.Cursor = "Hand"
    $createDLBtn.Margin = [System.Windows.Thickness]::new(0, 0, 6, 0)
    $createDLBtn.Tag = @{ Role = $role; Tier = $tier }
    $createDLBtn.Add_Click({
        $ctx = $this.Tag
        $newDL = Show-AddDLGroupDialog $ctx.Tier
        if ($newDL) {
            $ctx.Role.DomainLocalGroups = @($ctx.Role.DomainLocalGroups) + @($newDL)
            Refresh-RBACRole $ctx.Role.Name
        }
    })
    [void]$dlBtnPanel.Children.Add($createDLBtn)

    $addExistingDLBtn = New-Object System.Windows.Controls.Button
    $addExistingDLBtn.Content = "+ Add Existing DL"
    $addExistingDLBtn.Background = Get-WPFBrush "#E8F2FC"
    $addExistingDLBtn.Foreground = Get-WPFBrush "#0078D4"
    $addExistingDLBtn.BorderThickness = [System.Windows.Thickness]::new(0)
    $addExistingDLBtn.Padding = [System.Windows.Thickness]::new(12, 6, 12, 6)
    $addExistingDLBtn.FontSize = 12
    $addExistingDLBtn.Cursor = "Hand"
    $addExistingDLBtn.Tag = @{ Role = $role; Tier = $tier }
    $addExistingDLBtn.Add_Click({
        $ctx = $this.Tag
        $picked = Show-PickExistingDLDialog $ctx.Role
        if ($picked -and $picked.Count -gt 0) {
            $ctx.Role.DomainLocalGroups = @($ctx.Role.DomainLocalGroups) + @($picked)
            Refresh-RBACRole $ctx.Role.Name
        }
    })
    [void]$dlBtnPanel.Children.Add($addExistingDLBtn)

    [void]$UI.RBACDLList.Children.Add($dlBtnPanel)

    for ($dlIdx = 0; $dlIdx -lt $role.DomainLocalGroups.Count; $dlIdx++) {
        $dl = $role.DomainLocalGroups[$dlIdx]

        $dlCard = New-Object System.Windows.Controls.Border
        $dlCard.Background = Get-WPFBrush "#F8F8F8"
        $dlCard.CornerRadius = [System.Windows.CornerRadius]::new(6)
        $dlCard.Padding = [System.Windows.Thickness]::new(14)
        $dlCard.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)

        $dlStack = New-Object System.Windows.Controls.StackPanel

        # DL header row with name + delete button
        $dlHeaderDock = New-Object System.Windows.Controls.DockPanel
        $dlHeaderDock.Margin = [System.Windows.Thickness]::new(0, 0, 0, 2)

        $delDLBtn = New-Object System.Windows.Controls.Button
        $delDLBtn.Content = "Remove"
        $delDLBtn.Background = Get-WPFBrush "#FCE8E8"
        $delDLBtn.Foreground = Get-WPFBrush "#A93226"
        $delDLBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $delDLBtn.Padding = [System.Windows.Thickness]::new(8, 3, 8, 3)
        $delDLBtn.FontSize = 11
        $delDLBtn.Cursor = "Hand"
        $delDLBtn.Tag = @{ Role = $role; DLIndex = $dlIdx }
        [System.Windows.Controls.DockPanel]::SetDock($delDLBtn, "Right")
        $delDLBtn.Add_Click({
            $ctx = $this.Tag
            $result = [System.Windows.MessageBox]::Show(
                "Remove this DL group from the role?", "Confirm",
                [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
            if ($result -eq "Yes") {
                $removed = $ctx.Role.DomainLocalGroups[$ctx.DLIndex]
                $script:RemovedDLGroups += @{
                    Name        = [string]$removed.Name
                    Description = [string]$removed.Description
                    OU          = [string]$removed.OU
                }
                $list = [System.Collections.ArrayList]@($ctx.Role.DomainLocalGroups)
                $list.RemoveAt($ctx.DLIndex)
                $ctx.Role.DomainLocalGroups = @($list)
                Refresh-RBACRole $ctx.Role.Name
            }
        })

        $dlName = New-Object System.Windows.Controls.TextBlock
        $dlName.Text = $dl.Name
        $dlName.FontWeight = "SemiBold"
        $dlName.FontSize = 13
        $dlName.VerticalAlignment = "Center"

        [void]$dlHeaderDock.Children.Add($delDLBtn)
        [void]$dlHeaderDock.Children.Add($dlName)
        [void]$dlStack.Children.Add($dlHeaderDock)

        $dlDesc = New-Object System.Windows.Controls.TextBlock
        $dlDesc.Text = $dl.Description
        $dlDesc.FontSize = 11
        $dlDesc.Foreground = Get-WPFBrush "#666"
        $dlDesc.TextWrapping = "Wrap"
        $dlDesc.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        [void]$dlStack.Children.Add($dlDesc)

        $dlOUPanel = New-Object System.Windows.Controls.DockPanel
        $dlOUPanel.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $dlOUCopyBtn = New-CopyDNButton $dl.OU
        [System.Windows.Controls.DockPanel]::SetDock($dlOUCopyBtn, "Right")
        [void]$dlOUPanel.Children.Add($dlOUCopyBtn)
        $dlOUBox = New-Object System.Windows.Controls.TextBox
        $dlOUBox.Text = $dl.OU
        $dlOUBox.FontSize = 10
        $dlOUBox.Foreground = Get-WPFBrush "#555"
        $dlOUBox.BorderBrush = Get-WPFBrush "#DDD"
        $dlOUBox.BorderThickness = [System.Windows.Thickness]::new(1)
        $dlOUBox.Padding = [System.Windows.Thickness]::new(4, 3, 4, 3)
        $dlOUBox.Background = Get-WPFBrush "#FAFAFA"
        $dlOUBox.TextWrapping = "Wrap"
        $dlOUBox.Tag = @{ DL = $dl; CopyBtn = $dlOUCopyBtn }
        $dlOUBox.Add_TextChanged({
            $ctx = $this.Tag
            $ctx.DL.OU = $this.Text
            $ctx.CopyBtn.Tag = $this.Text
            $script:UnsavedChanges.RBAC = $true
        })
        [void]$dlOUPanel.Children.Add($dlOUBox)
        [void]$dlStack.Children.Add($dlOUPanel)

        # Determine if this DL group is a reference (empty Permissions) with actual perms defined in another role
        $isReference = (-not $dl.Permissions -or $dl.Permissions.Count -eq 0)
        $resolvedPerms = $dl.Permissions
        $sourceRoleName = $null
        if ($isReference) {
            foreach ($otherRole in $script:Configs.RBAC.Roles) {
                if ($otherRole.Name -eq $role.Name) { continue }
                foreach ($otherDL in $otherRole.DomainLocalGroups) {
                    if ($otherDL.Name -eq $dl.Name -and $otherDL.Permissions -and $otherDL.Permissions.Count -gt 0) {
                        $resolvedPerms = $otherDL.Permissions
                        $sourceRoleName = $otherRole.Name
                        break
                    }
                }
                if ($sourceRoleName) { break }
            }
        }

        # Show inherited label if permissions come from another role
        if ($sourceRoleName) {
            $inheritLabel = New-Object System.Windows.Controls.TextBlock
            $inheritLabel.Text = "Permissions inherited from role $sourceRoleName (membership only)"
            $inheritLabel.FontSize = 11
            $inheritLabel.FontStyle = "Italic"
            $inheritLabel.Foreground = Get-WPFBrush "#888"
            $inheritLabel.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
            [void]$dlStack.Children.Add($inheritLabel)
        }

        # Permissions
        for ($pIdx = 0; $pIdx -lt $resolvedPerms.Count; $pIdx++) {
            $perm = $resolvedPerms[$pIdx]

            $permBorder = New-Object System.Windows.Controls.Border
            $permBorder.Background = if ($sourceRoleName) { Get-WPFBrush "#FAFAFA" } else { Get-WPFBrush "#FFFFFF" }
            $permBorder.CornerRadius = [System.Windows.CornerRadius]::new(4)
            $permBorder.Padding = [System.Windows.Thickness]::new(10, 6, 10, 6)
            $permBorder.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
            $permBorder.BorderBrush = if ($sourceRoleName) { Get-WPFBrush "#E8E8E8" } else { Get-WPFBrush "#EEE" }
            $permBorder.BorderThickness = [System.Windows.Thickness]::new(1)

            $permDock = New-Object System.Windows.Controls.DockPanel

            if (-not $sourceRoleName) {
                # Delete perm button (only for own permissions)
                $delPermBtn = New-Object System.Windows.Controls.Button
                $delPermBtn.Content = "X"
                $delPermBtn.Background = Get-WPFBrush "Transparent"
                $delPermBtn.Foreground = Get-WPFBrush "#CC0000"
                $delPermBtn.BorderThickness = [System.Windows.Thickness]::new(0)
                $delPermBtn.FontSize = 10
                $delPermBtn.FontWeight = "Bold"
                $delPermBtn.Cursor = "Hand"
                $delPermBtn.Padding = [System.Windows.Thickness]::new(4, 0, 4, 0)
                $delPermBtn.VerticalAlignment = "Center"
                $delPermBtn.Tag = @{ Role = $role; DLIndex = $dlIdx; PermIndex = $pIdx }
                [System.Windows.Controls.DockPanel]::SetDock($delPermBtn, "Right")
                $delPermBtn.Add_Click({
                    $ctx = $this.Tag
                    $dlObj = $ctx.Role.DomainLocalGroups[$ctx.DLIndex]
                    $list = [System.Collections.ArrayList]@($dlObj.Permissions)
                    $list.RemoveAt($ctx.PermIndex)
                    $dlObj.Permissions = @($list)
                    Refresh-RBACRole $ctx.Role.Name
                })

                # Edit perm button (only for own permissions)
                $editPermBtn = New-Object System.Windows.Controls.Button
                $editPermBtn.Content = "Edit"
                $editPermBtn.Background = Get-WPFBrush "Transparent"
                $editPermBtn.Foreground = Get-WPFBrush "#0078D4"
                $editPermBtn.BorderThickness = [System.Windows.Thickness]::new(0)
                $editPermBtn.FontSize = 10
                $editPermBtn.Cursor = "Hand"
                $editPermBtn.Padding = [System.Windows.Thickness]::new(4, 0, 8, 0)
                $editPermBtn.VerticalAlignment = "Center"
                $editPermBtn.Tag = @{ Role = $role; DLIndex = $dlIdx; PermIndex = $pIdx; Perm = $perm }
                [System.Windows.Controls.DockPanel]::SetDock($editPermBtn, "Right")
                $editPermBtn.Add_Click({
                    $ctx = $this.Tag
                    $edited = Show-PermissionDialog $ctx.Perm
                    if ($edited) {
                        $ctx.Role.DomainLocalGroups[$ctx.DLIndex].Permissions[$ctx.PermIndex] = $edited
                        Refresh-RBACRole $ctx.Role.Name
                    }
                })
            }

            # Type badge
            $typeBadge = New-Object System.Windows.Controls.TextBlock
            $typeBadge.Text = $perm.Type
            $typeBadge.FontSize = 10
            $typeBadge.FontWeight = "Bold"
            $typeBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
            $typeBadge.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
            $typeBadge.VerticalAlignment = "Center"
            switch ($perm.Type) {
                "NTFS"  { $typeBadge.Foreground = Get-WPFBrush "#1E8449"; $typeBadge.Background = Get-WPFBrush "#E8F8F0" }
                "AD"    { $typeBadge.Foreground = Get-WPFBrush "#2E86C1"; $typeBadge.Background = Get-WPFBrush "#E8F2FC" }
                "ADCS"  { $typeBadge.Foreground = Get-WPFBrush "#A93226"; $typeBadge.Background = Get-WPFBrush "#FCE8E8" }
                "Share" { $typeBadge.Foreground = Get-WPFBrush "#6C3483"; $typeBadge.Background = Get-WPFBrush "#F4ECF7" }
            }
            if ($sourceRoleName) { $typeBadge.Opacity = 0.6 }
            [System.Windows.Controls.DockPanel]::SetDock($typeBadge, "Left")

            $permInfo = New-Object System.Windows.Controls.TextBlock
            $permInfo.FontSize = 11
            $permInfo.VerticalAlignment = "Center"
            $permInfo.TextWrapping = "Wrap"
            if ($sourceRoleName) { $permInfo.Foreground = Get-WPFBrush "#888" }
            switch ($perm.Type) {
                "NTFS" {
                    $shareInfo = if ($perm.ShareName) { " + Share $($perm.ShareRight) on $($perm.ShareName)" } else { "" }
                    $permInfo.Text = "$($perm.Rights) on $($perm.Path)$shareInfo"
                }
                "AD"    { $permInfo.Text = "$($perm.ADRights) on $($perm.TargetOU)" }
                "ADCS"  { $permInfo.Text = "$($perm.Right) on $($perm.CAName) ($($perm.CAHostname))" }
                "Share" { $permInfo.Text = "$($perm.ShareRight) on \\$($perm.ShareServer)\$($perm.ShareName)" }
            }

            # Copy DN button for AD/NTFS permissions
            $permDN = switch ($perm.Type) {
                "AD"   { $perm.TargetOU }
                "NTFS" { $perm.Path }
                default { $null }
            }
            if ($permDN) {
                $permCopyBtn = New-CopyDNButton $permDN
                [System.Windows.Controls.DockPanel]::SetDock($permCopyBtn, "Right")
                [void]$permDock.Children.Add($permCopyBtn)
            }

            if (-not $sourceRoleName) {
                [void]$permDock.Children.Add($delPermBtn)
                [void]$permDock.Children.Add($editPermBtn)
            }
            [void]$permDock.Children.Add($typeBadge)
            [void]$permDock.Children.Add($permInfo)
            $permBorder.Child = $permDock
            [void]$dlStack.Children.Add($permBorder)
        }

        # "+ Add Permission" button per DL group (only for own DL groups, not inherited references)
        if (-not $sourceRoleName) {
            $addPermBtn = New-Object System.Windows.Controls.Button
            $addPermBtn.Content = "+ Add Permission"
            $addPermBtn.Background = Get-WPFBrush "#E8F2FC"
            $addPermBtn.Foreground = Get-WPFBrush "#0078D4"
            $addPermBtn.BorderThickness = [System.Windows.Thickness]::new(0)
            $addPermBtn.Padding = [System.Windows.Thickness]::new(10, 4, 10, 4)
            $addPermBtn.FontSize = 11
            $addPermBtn.Cursor = "Hand"
            $addPermBtn.HorizontalAlignment = "Left"
            $addPermBtn.Margin = [System.Windows.Thickness]::new(0, 4, 0, 0)
            $addPermBtn.Tag = @{ Role = $role; DLIndex = $dlIdx }
            $addPermBtn.Add_Click({
                $ctx = $this.Tag
                $newPerm = Show-PermissionDialog $null
                if ($newPerm) {
                    $dlObj = $ctx.Role.DomainLocalGroups[$ctx.DLIndex]
                    $dlObj.Permissions = @($dlObj.Permissions) + @($newPerm)
                    Refresh-RBACRole $ctx.Role.Name
                }
            })
            [void]$dlStack.Children.Add($addPermBtn)
        }

        $dlCard.Child = $dlStack
        [void]$UI.RBACDLList.Children.Add($dlCard)
    }
}

# ============================================================================
# Navigation
# ============================================================================

function Set-ActiveTab([int]$index) {
    $UI.MainTabs.SelectedIndex = $index
    $navButtons = @($UI.NavDashboard, $UI.NavHardening, $UI.NavGPO, $UI.NavTiering, $UI.NavRBAC, $UI.NavPSO, $UI.NavSilo, $UI.NavJIT)
    $activeStyle = $script:Window.FindResource("NavBtnActive")
    $normalStyle = $script:Window.FindResource("NavBtn")
    for ($i = 0; $i -lt $navButtons.Count; $i++) {
        $navButtons[$i].Style = if ($i -eq $index) { $activeStyle } else { $normalStyle }
    }
    # Search bar visible on Hardening, GPO, PSO, and Silo tabs
    $UI.SearchBarPanel.Visibility = if ($index -in @(1, 2, 5, 6)) { "Visible" } else { "Collapsed" }
    if ($index -eq 1) { $UI.SearchPlaceholder.Text = "Search hardening tasks..." }
    elseif ($index -eq 2) { $UI.SearchPlaceholder.Text = "Search GPO templates..." }
    elseif ($index -eq 5) { $UI.SearchPlaceholder.Text = "Search password policies..." }
    elseif ($index -eq 6) { $UI.SearchPlaceholder.Text = "Search authentication silos..." }
    # Clear search when switching tabs
    if ($index -in @(1, 2, 5, 6)) { $UI.SearchBox.Text = "" }
}

# ============================================================================
# Search
# ============================================================================

function Invoke-Search([string]$query) {
    $activeTab = $UI.MainTabs.SelectedIndex

    if ([string]::IsNullOrWhiteSpace($query)) {
        $UI.SearchPlaceholder.Visibility = "Visible"
        if ($activeTab -eq 1) {
            foreach ($child in $UI.HardeningTaskList.Children) { $child.Visibility = "Visible" }
        } elseif ($activeTab -eq 2) {
            foreach ($child in $UI.GPOTaskList.Children) { $child.Visibility = "Visible" }
        } elseif ($activeTab -eq 5) {
            foreach ($child in $UI.PSOPolicyList.Children) { $child.Visibility = "Visible" }
        } elseif ($activeTab -eq 6) {
            foreach ($child in $UI.SiloTaskList.Children) { $child.Visibility = "Visible" }
        }
        return
    }

    $UI.SearchPlaceholder.Visibility = "Collapsed"
    $q = $query.ToLower()

    if ($activeTab -eq 1) {
        for ($i = 0; $i -lt $UI.HardeningTaskList.Children.Count; $i++) {
            $task = $script:Configs.Hardening.Tasks[$i]
            $match = $task.Name.ToLower().Contains($q) -or $task.Description.ToLower().Contains($q)
            $UI.HardeningTaskList.Children[$i].Visibility = if ($match) { "Visible" } else { "Collapsed" }
        }
    } elseif ($activeTab -eq 2) {
        for ($i = 0; $i -lt $UI.GPOTaskList.Children.Count; $i++) {
            $gpo = $script:Configs.GPO.GPOs[$i]
            $match = $gpo.Name.ToLower().Contains($q) -or $gpo.Description.ToLower().Contains($q)
            $UI.GPOTaskList.Children[$i].Visibility = if ($match) { "Visible" } else { "Collapsed" }
        }
    } elseif ($activeTab -eq 5) {
        for ($i = 0; $i -lt $UI.PSOPolicyList.Children.Count; $i++) {
            $policy = $script:Configs.PSO.Policies[$i]
            $match = $policy.Name.ToLower().Contains($q) -or $policy.Description.ToLower().Contains($q)
            $UI.PSOPolicyList.Children[$i].Visibility = if ($match) { "Visible" } else { "Collapsed" }
        }
    } elseif ($activeTab -eq 6) {
        for ($i = 0; $i -lt $UI.SiloTaskList.Children.Count; $i++) {
            $silo = $script:Configs.Silo.Silos[$i]
            $match = $silo.Name.ToLower().Contains($q) -or $silo.Description.ToLower().Contains($q)
            $UI.SiloTaskList.Children[$i].Visibility = if ($match) { "Visible" } else { "Collapsed" }
        }
    }
}

# ============================================================================
# Deploy
# ============================================================================

# Canonical safe execution order
$script:DeploySafeOrder = @("Hardening", "Tiering", "RBAC", "PSO", "Silo", "GPO", "JIT")

# Spinner frames for the per-module progress line. Deliberately plain ASCII: the console
# panel renders in Cascadia Mono/Consolas, which have no Braille or spinner glyphs and
# would show tofu boxes instead.
$script:SpinnerFrames = @('|', '/', '-', '\')

$script:VerdictColors = @{
    SUCCESS = "#58D68D"   # green
    PARTIAL = "#E67E22"   # orange
    FAIL    = "#EC7063"   # red
}

function New-ConsoleStatusLine {
    <#
    .SYNOPSIS
        Appends a console line and hands back its Run, so the caller can rewrite that same
        line in place instead of appending a new one.
    .DESCRIPTION
        This is what lets one line spin while a module deploys and then turn into that
        module's verdict, rather than scrolling the panel with hundreds of log lines.
    #>
    param([string]$Text, [string]$Color = "#CCCCCC")

    $para = New-Object System.Windows.Documents.Paragraph
    $para.Margin = [System.Windows.Thickness]::new(0)
    $run = New-Object System.Windows.Documents.Run($Text)
    $run.Foreground = Get-WPFBrush $Color
    $para.Inlines.Add($run)
    $UI.ConsoleOutput.Document.Blocks.Add($para)
    $UI.ConsoleOutput.ScrollToEnd()
    return $run
}

function Set-ConsoleStatusLine {
    <#
    .SYNOPSIS
        Rewrites a line previously created by New-ConsoleStatusLine.
    #>
    param($Run, [string]$Text, [string]$Color)

    $Run.Text = $Text
    if ($Color) { $Run.Foreground = Get-WPFBrush $Color }
    $UI.ConsoleOutput.ScrollToEnd()
}

function Get-DeploymentVerdict {
    <#
    .SYNOPSIS
        Turns a deployment script's own "DEPLOYMENT SUMMARY" block into a
        SUCCESS / PARTIAL / FAIL verdict plus a one-line detail.
    .DESCRIPTION
        Every Scripts\Deploy-*.ps1 closes with a summary of "<label> : <n>" counters and an
        "Errors : <n>" line. Only lines *after* the DEPLOYMENT SUMMARY header are read: the
        pre-flight configuration summary printed above it uses the very same
        "label : number" shape (Total tasks, Enabled, Disabled, ...) and would otherwise be
        mistaken for results.

        Verdict:
          SUCCESS - no errors reported
          PARTIAL - errors, but at least one unit of work still went through
          FAIL    - errors and nothing went through, or the script died before printing a
                    summary at all (bad config, no AD connectivity, ...)

        "skipped (disabled)" counters are ignored on purpose: a module the operator turned
        off is a deliberate no-op, not work that succeeded.
    .PARAMETER Lines
        Plain-text lines captured from the deployment script.
    .OUTPUTS
        PSCustomObject with Verdict and Detail.
    #>
    param([string[]]$Lines)

    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match 'DEPLOYMENT SUMMARY') { $start = $i; break }
    }
    if ($start -lt 0) {
        return [PSCustomObject]@{ Verdict = 'FAIL'; Detail = 'stopped before producing a summary' }
    }

    $errors   = 0
    $work     = 0
    $headline = $null

    for ($i = $start + 1; $i -lt $Lines.Count; $i++) {
        # Anchored on a numeric (or Yes/No) value to end-of-line, so the trailing
        # "Log file: ..." and "CSV report: ..." lines can never match.
        if ($Lines[$i] -notmatch '^\s+(?<label>\S.*?)\s*:\s*(?<value>\d+|Yes|No)\s*$') { continue }

        $label = ($Matches['label'] -replace '\s*\(SIMULATION\)\s*$', '').Trim()
        $raw   = $Matches['value']
        $value = if ($raw -eq 'Yes') { 1 } elseif ($raw -eq 'No') { 0 } else { [int]$raw }

        if ($label -match '^Errors') { $errors = $value; continue }
        if ($label -match 'skipped') { continue }

        $work += $value
        # First counter of the block is the module's headline figure (OUs created,
        # GPOs deployed, Groups created, ...) -- reuse it verbatim as the detail.
        if (-not $headline) { $headline = "${label}: $raw" }
    }

    $verdict = if ($errors -eq 0) { 'SUCCESS' } elseif ($work -gt 0) { 'PARTIAL' } else { 'FAIL' }
    $detail  = @($headline, ("{0} error(s)" -f $errors)) | Where-Object { $_ }

    return [PSCustomObject]@{ Verdict = $verdict; Detail = ($detail -join ', ') }
}

function Start-SingleDeployment([string]$module) {
    $whatIf = [bool]$UI.WhatIfToggle.IsChecked
    $label  = $module.PadRight(10)

    $scriptPath = $script:ScriptPaths[$module]
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        New-ConsoleStatusLine ("  {0,-9} {1} script not found: {2}" -f 'FAIL', $label, $scriptPath) $script:VerdictColors.FAIL | Out-Null
        return [PSCustomObject]@{ Module = $module; Verdict = 'FAIL' }
    }

    $configPath = $script:ConfigPaths[$module]
    $callParams = @{
        ConfigPath = $configPath
        NoConfirm  = $true
    }
    if ($script:Connection -and $script:Connection.Server)     { $callParams.Server     = $script:Connection.Server }
    if ($script:Connection -and $script:Connection.Credential) { $callParams.Credential = $script:Connection.Credential }
    if ($whatIf) { $callParams.WhatIf = $true }

    $statusRun = New-ConsoleStatusLine ("  {0,-9} {1} deploying..." -f $script:SpinnerFrames[0], $label) "#87CEEB"

    $lines = [System.Collections.Generic.List[string]]::new()
    $frame = 0
    $clock = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # Captured with `*>&1` (all streams), not `2>&1` (error stream only): every
        # Write-*Log writes through Write-Host, i.e. the Information stream, which `2>&1`
        # never merged. The lines now drive the spinner and the verdict instead of being
        # printed one by one -- the full transcript is still written to
        # Logs\<run>\<Module>_*.log by the modules themselves.
        & $scriptPath @callParams *>&1 | ForEach-Object {
            $record = $_
            $lines.Add($(
                if ($record -is [System.Management.Automation.InformationRecord]) { "$($record.MessageData)" }
                else { "$record" }
            ))

            # Repaint at ~12 fps at most. A GPO deployment emits several hundred lines and
            # pumping the dispatcher for every single one is pure overhead.
            if ($clock.ElapsedMilliseconds -ge 80) {
                $frame = ($frame + 1) % $script:SpinnerFrames.Count
                Set-ConsoleStatusLine $statusRun ("  {0,-9} {1} deploying..." -f $script:SpinnerFrames[$frame], $label)
                $script:Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
                $clock.Restart()
            }
        }
    }
    catch {
        $lines.Add("[Error] $_")
    }
    $clock.Stop()

    $result = Get-DeploymentVerdict -Lines $lines
    $color  = $script:VerdictColors[$result.Verdict]
    Set-ConsoleStatusLine $statusRun ("  {0,-9} {1} {2}" -f $result.Verdict, $label, $result.Detail) $color
    $script:Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    return [PSCustomObject]@{ Module = $module; Verdict = $result.Verdict }
}

function Start-SelectedDeployments {
    $selected = @()
    if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
    if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
    if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
    if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
    if ($UI.DeploySilo.IsChecked)      { $selected += "Silo" }
    if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }
    if ($UI.DeployJIT.IsChecked)       { $selected += "JIT" }

    if ($selected.Count -eq 0) {
        Write-ConsoleUI "No modules selected for deployment." "Warning"
        return
    }

    # Create a shared run folder so all modules log into the same directory
    $global:LOCKmeAD_RunFolder = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

    # Enforce safe order. Wrapped in @() because Where-Object returns a bare string when a
    # single module is selected, and indexing a string yields its first character.
    $ordered = @($script:DeploySafeOrder | Where-Object { $selected -contains $_ })

    $whatIf = [bool]$UI.WhatIfToggle.IsChecked
    $whatIfLabel = if ($whatIf) { " (WhatIf)" } else { "" }
    Write-ConsoleUI "Deploying: $($ordered -join ' > ')$whatIfLabel" "Info"

    # No "=== $module ===" header any more: each module now owns a single line that spins
    # while it runs and settles into its own verdict.
    $results = @()
    foreach ($module in $ordered) {
        $results += Start-SingleDeployment $module
    }

    $ok      = @($results | Where-Object { $_.Verdict -eq 'SUCCESS' }).Count
    $partial = @($results | Where-Object { $_.Verdict -eq 'PARTIAL' }).Count
    $failed  = @($results | Where-Object { $_.Verdict -eq 'FAIL' }).Count
    $level   = if ($failed -gt 0) { "Error" } elseif ($partial -gt 0) { "Warning" } else { "Success" }
    Write-ConsoleUI "$ok SUCCESS, $partial PARTIAL, $failed FAIL - full output in $(Get-DeploymentLogPath $ordered[0])" $level
}

function Get-DeploymentLogPath([string]$module) {
    <#
    .SYNOPSIS
        Absolute path of the folder the current run's log files were written to.
    .DESCRIPTION
        Since the console panel only reports a verdict per module, the operator has to open
        the logs to find out what actually failed -- so the closing line has to hand over a
        path that can be pasted straight into Explorer, not a project-relative one.

        Resolved exactly the way every Scripts\Deploy-*.ps1 resolves it: the module config's
        Settings.LogDirectory, treated as relative to the project root unless already rooted,
        then the shared run folder. Reading it from the config rather than hardcoding "Logs"
        keeps this correct if the LogDirectory setting is ever changed.
    #>
    $projectRoot = Split-Path (Split-Path $script:ConfigPaths.RBAC -Parent) -Parent

    $logRoot = $script:Configs[$module].Settings.LogDirectory
    if (-not $logRoot) { $logRoot = './Logs' }
    if (-not [System.IO.Path]::IsPathRooted($logRoot)) { $logRoot = Join-Path $projectRoot $logRoot }

    return [System.IO.Path]::GetFullPath((Join-Path $logRoot $global:LOCKmeAD_RunFolder))
}

function Update-DeployOrderHint {
    $selected = @()
    if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
    if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
    if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
    if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
    if ($UI.DeploySilo.IsChecked)      { $selected += "Silo" }
    if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }
    if ($UI.DeployJIT.IsChecked)       { $selected += "JIT" }

    if ($selected.Count -le 1) {
        $UI.DeployOrderHint.Visibility = "Collapsed"
    }
    else {
        $ordered = $script:DeploySafeOrder | Where-Object { $selected -contains $_ }
        $UI.DeployOrderHint.Text = "Order: $($ordered -join ' > ')"
        $UI.DeployOrderHint.Visibility = "Visible"
    }
}

# ============================================================================
# RBAC Dialogs & Helpers
# ============================================================================

$script:GuidToNameMap = @{}

function Build-GuidToNameMap {
    if ($script:GuidToNameMap.Count -gt 0) { return }
    try {
        $connParam = New-LOCKmeADConnectionParam -Connection $script:Connection
        $rootDse = Get-ADRootDSE @connParam -ErrorAction Stop
        Get-ADObject -SearchBase $rootDse.schemaNamingContext `
                     -LDAPFilter "(schemaidguid=*)" `
                     -Properties lDAPDisplayName, schemaIDGUID `
                     @connParam -ErrorAction Stop |
            ForEach-Object {
                $g = [System.Guid]$_.schemaIDGUID
                $script:GuidToNameMap[$g.ToString().ToLower()] = $_.lDAPDisplayName
            }
        Get-ADObject -SearchBase $rootDse.configurationNamingContext `
                     -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" `
                     -Properties displayName, rightsGuid `
                     @connParam -ErrorAction Stop |
            ForEach-Object {
                $g = [System.Guid]$_.rightsGuid
                $script:GuidToNameMap[$g.ToString().ToLower()] = $_.displayName
            }
    }
    catch { }
}

function Resolve-GuidToDisplayName([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    if ($Value -eq "00000000-0000-0000-0000-000000000000") { return "" }
    if ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        Build-GuidToNameMap
        $name = $script:GuidToNameMap[$Value.ToLower()]
        if ($name) { return $name }
    }
    return $Value
}

function Show-ADGroupSearchDialog {
    $searchXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add MemberOf — Search AD Group" Width="460" Height="380"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F5F5F5" FontFamily="Segoe UI">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid Grid.Row="0" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Name="SearchBox" Grid.Column="0" Padding="8,6" FontSize="13"
                     BorderBrush="#D0D0D0" BorderThickness="1"/>
            <Button Name="SearchBtn" Grid.Column="1" Content="Search" Margin="8,0,0,0"
                    Background="#0078D4" Foreground="White" Padding="14,6"
                    BorderThickness="0" FontSize="13" Cursor="Hand"/>
        </Grid>
        <ListBox Name="ResultList" Grid.Row="1" FontSize="13" Padding="4"
                 BorderBrush="#D0D0D0" BorderThickness="1"/>
        <Grid Grid.Row="2" Margin="0,8,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Name="StatusText" Grid.Column="0" FontSize="11" Foreground="#888888"
                       VerticalAlignment="Center"
                       Text="Enter a name, press Enter or Search. Double-click to select."/>
            <Button Name="UseTypedBtn" Grid.Column="1" Content="Use typed name" Margin="8,0,0,0"
                    Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                    FontSize="12" Padding="10,6" Cursor="Hand"/>
        </Grid>
    </Grid>
</Window>
"@
    [xml]$searchDoc   = $searchXaml
    $searchReader     = [System.Xml.XmlNodeReader]::new($searchDoc)
    $searchWindow     = [System.Windows.Markup.XamlReader]::Load($searchReader)
    $searchWindow.Owner = $script:Window

    $searchBox   = $searchWindow.FindName("SearchBox")
    $searchBtn   = $searchWindow.FindName("SearchBtn")
    $resultList  = $searchWindow.FindName("ResultList")
    $statusText  = $searchWindow.FindName("StatusText")
    $useTypedBtn = $searchWindow.FindName("UseTypedBtn")

    $script:dialogResult = $null

    $doSearch = {
        $val = $searchBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($val)) {
            $statusText.Text = "Please enter a search term."
            return
        }
        $resultList.Items.Clear()
        $statusText.Text = "Searching..."
        $searchWindow.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $connParam = New-LOCKmeADConnectionParam -Connection $script:Connection
            $results = Get-ADGroup -Filter "Name -like '*$val*'" @connParam -ErrorAction Stop | Select-Object -First 50
            foreach ($r in $results) {
                $item = [System.Windows.Controls.ListBoxItem]::new()
                $item.Content = "$($r.SamAccountName)  —  $($r.Name)"
                $item.Tag = $r.SamAccountName
                $resultList.Items.Add($item) | Out-Null
            }
            $count = $resultList.Items.Count
            $statusText.Text = if ($count -eq 0) { "No results found." }
                               elseif ($count -ge 50) { "$count results (showing first 50). Refine your search." }
                               else { "$count result(s). Double-click to select." }
        }
        catch {
            $statusText.Text = "Error: $($_.Exception.Message)"
        }
        finally {
            $searchWindow.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    }

    $searchBtn.Add_Click($doSearch)

    $useTypedBtn.Add_Click({
        $val = $searchBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($val)) {
            $statusText.Text = "Please enter a group name first."
            return
        }
        $script:dialogResult = $val
        $searchWindow.DialogResult = $true
        $searchWindow.Close()
    })

    $searchBox.Add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return) {
            $doSearch.Invoke()
            $e.Handled = $true
        }
    })

    $resultList.Add_MouseDoubleClick({
        $selected = $resultList.SelectedItem
        if ($selected -and $selected.Tag) {
            $script:dialogResult = $selected.Tag
            $searchWindow.DialogResult = $true
            $searchWindow.Close()
        }
    })

    $searchWindow.ShowDialog() | Out-Null
    return $script:dialogResult
}

function Show-ADObjectSearchDialog {
    param([ValidateSet("Group","User")][string]$SearchType = "Group")

    $typeLabel = if ($SearchType -eq "User") { "User" } else { "Group" }
    $searchXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Search AD $typeLabel" Width="460" Height="380"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F5F5F5" FontFamily="Segoe UI">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid Grid.Row="0" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Name="SearchBox" Grid.Column="0" Padding="8,6" FontSize="13"
                     BorderBrush="#D0D0D0" BorderThickness="1"/>
            <Button Name="SearchBtn" Grid.Column="1" Content="Search" Margin="8,0,0,0"
                    Background="#0078D4" Foreground="White" Padding="14,6"
                    BorderThickness="0" FontSize="13" Cursor="Hand"/>
        </Grid>
        <ListBox Name="ResultList" Grid.Row="1" FontSize="13" Padding="4"
                 BorderBrush="#D0D0D0" BorderThickness="1"/>
        <TextBlock Name="StatusText" Grid.Row="2" Margin="0,8,0,0"
                   FontSize="11" Foreground="#888888"
                   Text="Type a name and press Enter or click Search. Double-click to select."/>
    </Grid>
</Window>
"@
    [xml]$searchDoc   = $searchXaml
    $searchReader     = [System.Xml.XmlNodeReader]::new($searchDoc)
    $searchWindow     = [System.Windows.Markup.XamlReader]::Load($searchReader)
    $searchWindow.Owner = $script:Window

    $searchBox  = $searchWindow.FindName("SearchBox")
    $searchBtn  = $searchWindow.FindName("SearchBtn")
    $resultList = $searchWindow.FindName("ResultList")
    $statusText = $searchWindow.FindName("StatusText")

    $script:dialogResult = $null

    $capturedType = $SearchType
    $doSearch = {
        $val = $searchBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($val)) {
            $statusText.Text = "Please enter a search term."
            return
        }
        $resultList.Items.Clear()
        $statusText.Text = "Searching..."
        $searchWindow.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $connParam = New-LOCKmeADConnectionParam -Connection $script:Connection
            if ($capturedType -eq "User") {
                $results = Get-ADUser -Filter "Name -like '*$val*'" @connParam -ErrorAction Stop | Select-Object -First 50
                foreach ($r in $results) {
                    $item = [System.Windows.Controls.ListBoxItem]::new()
                    $item.Content = "$($r.SamAccountName)  —  $($r.Name)"
                    $item.Tag = $r.SamAccountName
                    $resultList.Items.Add($item) | Out-Null
                }
            } else {
                $results = Get-ADGroup -Filter "Name -like '*$val*'" @connParam -ErrorAction Stop | Select-Object -First 50
                foreach ($r in $results) {
                    $item = [System.Windows.Controls.ListBoxItem]::new()
                    $item.Content = "$($r.SamAccountName)  —  $($r.Name)"
                    $item.Tag = $r.SamAccountName
                    $resultList.Items.Add($item) | Out-Null
                }
            }
            $count = $resultList.Items.Count
            $statusText.Text = if ($count -eq 0) { "No results found." }
                               elseif ($count -ge 50) { "$count results (showing first 50). Refine your search." }
                               else { "$count result(s). Double-click to select." }
        }
        catch {
            $statusText.Text = "Error: $($_.Exception.Message)"
        }
        finally {
            $searchWindow.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    }

    $searchBtn.Add_Click($doSearch)

    $searchBox.Add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return) {
            $doSearch.Invoke()
            $e.Handled = $true
        }
    })

    $resultList.Add_MouseDoubleClick({
        $selected = $resultList.SelectedItem
        if ($selected -and $selected.Tag) {
            $script:dialogResult = $selected.Tag
            $searchWindow.DialogResult = $true
            $searchWindow.Close()
        }
    })

    $searchWindow.ShowDialog() | Out-Null
    return $script:dialogResult
}

function Show-CASearchDialog {
    $searchXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Search Enterprise CAs" Width="480" Height="360"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F5F5F5" FontFamily="Segoe UI">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBox Name="FilterBox" Grid.Row="0" Padding="8,6" FontSize="13"
                 BorderBrush="#D0D0D0" BorderThickness="1" Margin="0,0,0,10"/>
        <ListBox Name="ResultList" Grid.Row="1" FontSize="13" Padding="4"
                 BorderBrush="#D0D0D0" BorderThickness="1"/>
        <TextBlock Name="StatusText" Grid.Row="2" Margin="0,8,0,0"
                   FontSize="11" Foreground="#888888"
                   Text="Loading CAs from AD..."/>
    </Grid>
</Window>
"@
    [xml]$searchDoc  = $searchXaml
    $searchReader    = [System.Xml.XmlNodeReader]::new($searchDoc)
    $searchWindow    = [System.Windows.Markup.XamlReader]::Load($searchReader)
    $searchWindow.Owner = $script:Window

    $filterBox  = $searchWindow.FindName("FilterBox")
    $resultList = $searchWindow.FindName("ResultList")
    $statusText = $searchWindow.FindName("StatusText")

    $script:dialogResult = $null
    $script:caList = @()

    try {
        $connParam  = New-LOCKmeADConnectionParam -Connection $script:Connection
        $domainDN   = (Get-ADDomain @connParam).DistinguishedName
        $enrollBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $cas = Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" `
                            -SearchBase $enrollBase `
                            -Properties dNSHostName `
                            @connParam -ErrorAction Stop
        $script:caList = @($cas | ForEach-Object {
            [PSCustomObject]@{ CAName = $_.Name; CAHostname = $_.dNSHostName }
        })
        foreach ($ca in $script:caList) {
            $item = [System.Windows.Controls.ListBoxItem]::new()
            $item.Content = "$($ca.CAName)  —  $($ca.CAHostname)"
            $item.Tag = $ca
            $resultList.Items.Add($item) | Out-Null
        }
        $count = $resultList.Items.Count
        $statusText.Text = if ($count -eq 0) { "No Enterprise CAs found in AD." }
                           else { "$count CA(s) found. Type to filter, double-click to select." }
    }
    catch {
        $statusText.Text = "Error: $($_.Exception.Message)"
    }

    $capturedList = $script:caList
    $filterBox.Add_TextChanged({
        $filter = $filterBox.Text.Trim().ToLower()
        $resultList.Items.Clear()
        foreach ($ca in $capturedList) {
            if ([string]::IsNullOrEmpty($filter) -or
                $ca.CAName.ToLower().Contains($filter) -or
                $ca.CAHostname.ToLower().Contains($filter)) {
                $item = [System.Windows.Controls.ListBoxItem]::new()
                $item.Content = "$($ca.CAName)  —  $($ca.CAHostname)"
                $item.Tag = $ca
                $resultList.Items.Add($item) | Out-Null
            }
        }
    })

    $resultList.Add_MouseDoubleClick({
        $selected = $resultList.SelectedItem
        if ($selected -and $selected.Tag) {
            $script:dialogResult = $selected.Tag
            $searchWindow.DialogResult = $true
            $searchWindow.Close()
        }
    })

    $searchWindow.ShowDialog() | Out-Null
    return $script:dialogResult
}

function Get-TierOU([string]$tier) {
    $ggBase = $script:Configs.RBAC.Settings.DefaultOU.Global
    $dlBase = $script:Configs.RBAC.Settings.DefaultOU.DomainLocal
    return @{
        GG = $ggBase -replace 'GroupsT\d', "Groups$tier"
        DL = $dlBase -replace 'GroupsT\d', "Groups$tier"
    }
}

function Apply-RBACFilter {
    $filter = $script:RBACActiveFilter
    foreach ($item in $UI.RBACRoleList.Items) {
        $item.Visibility = if ($filter -and $item.Tag.Name -notlike "$filter*") { "Collapsed" } else { "Visible" }
    }
}

function Refresh-RBACRole($roleName) {
    Populate-RBACTab
    Apply-RBACFilter
    foreach ($item in $UI.RBACRoleList.Items) {
        if ($item.Tag.Name -eq $roleName) {
            $item.IsSelected = $true
            break
        }
    }
}

function Show-AddRoleDialog {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add RBAC Role" Width="520" SizeToContent="Height" WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize" Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="New RBAC Role" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,20"/>

        <TextBlock Text="Tier" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <ComboBox Name="TierSelect" FontSize="13" Padding="6,4" SelectedIndex="0">
            <ComboBoxItem Content="T0"/>
            <ComboBoxItem Content="T1"/>
            <ComboBoxItem Content="T2"/>
        </ComboBox>

        <TextBlock Text="Role Name (without tier prefix)" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="RoleName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <TextBlock Text="Description" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="RoleDesc" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <Border Background="#E8F2FC" CornerRadius="6" Padding="14" Margin="0,16,0,0">
            <StackPanel>
                <TextBlock Text="Global Group (GG)" FontSize="13" FontWeight="SemiBold"
                           Foreground="#0078D4" Margin="0,0,0,10"/>
                <TextBlock Text="GG Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
                <TextBox Name="GGName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <TextBlock Text="GG Description" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
                <TextBox Name="GGDesc" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <TextBlock Text="GG OU" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
                <TextBox Name="GGOU" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
            </StackPanel>
        </Border>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Add Role" Width="110" Padding="0,8"
                    Background="#0078D4" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $cmbTier     = $dlg.FindName("TierSelect")
    $txtRoleName = $dlg.FindName("RoleName")
    $txtRoleDesc = $dlg.FindName("RoleDesc")
    $txtGGName   = $dlg.FindName("GGName")
    $txtGGDesc   = $dlg.FindName("GGDesc")
    $txtGGOU     = $dlg.FindName("GGOU")
    $btnOK       = $dlg.FindName("BtnOK")
    $btnCancel   = $dlg.FindName("BtnCancel")

    # Pre-compute tier OUs for closure capture
    $tierOUs = @{
        T0 = (Get-TierOU "T0").GG
        T1 = (Get-TierOU "T1").GG
        T2 = (Get-TierOU "T2").GG
    }

    # Set initial OU
    $txtGGOU.Text = $tierOUs.T0

    # Auto-fill on tier or name change
    $updateFields = {
        $tier = $cmbTier.SelectedItem.Content
        $name = $txtRoleName.Text
        if ($name) {
            $txtGGName.Text = "GG_${tier}_${name}"
        }
        $txtGGOU.Text = $tierOUs[$tier]
    }.GetNewClosure()

    $cmbTier.Add_SelectionChanged($updateFields)
    $txtRoleName.Add_TextChanged($updateFields)

    $dlg.Tag = $null
    $btnOK.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtRoleName.Text)) {
            [System.Windows.MessageBox]::Show("Role Name is required.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $tier = $cmbTier.SelectedItem.Content
        $fullName = "${tier}_$($txtRoleName.Text)"
        $dlg.Tag = [PSCustomObject]@{
            Name        = $fullName
            Description = $txtRoleDesc.Text
            GlobalGroup = [PSCustomObject]@{
                Name        = $txtGGName.Text
                Description = $txtGGDesc.Text
                OU          = $txtGGOU.Text
            }
            DomainLocalGroups = @()
        }
        $dlg.Close()
    }.GetNewClosure())

    $btnCancel.Add_Click({ $dlg.Close() }.GetNewClosure())
    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

function Show-AddDLGroupDialog([string]$tier) {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Domain Local Group" Width="520" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="New DL Group" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,20"/>
        <TextBlock Text="Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox Name="DLName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
        <TextBlock Text="Description" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="DLDesc" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
        <TextBlock Text="OU (Distinguished Name)" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="DLOU" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Add DL Group" Width="120" Padding="0,8"
                    Background="#0078D4" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $txtName = $dlg.FindName("DLName")
    $txtDesc = $dlg.FindName("DLDesc")
    $txtOU   = $dlg.FindName("DLOU")
    $txtOU.Text = (Get-TierOU $tier).DL

    $dlg.Tag = $null
    $dlg.FindName("BtnOK").Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.MessageBox]::Show("Name is required.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $dlg.Tag = [PSCustomObject]@{
            Name        = $txtName.Text
            Description = $txtDesc.Text
            OU          = $txtOU.Text
            Permissions = @()
        }
        $dlg.Close()
    }.GetNewClosure())
    $dlg.FindName("BtnCancel").Add_Click({ $dlg.Close() }.GetNewClosure())

    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

function Show-PickExistingDLDialog($currentRole) {
    # Collect all DL groups from all roles + previously removed, excluding ones already in current role
    $currentDLNames = @($currentRole.DomainLocalGroups | ForEach-Object { $_.Name })
    $availableDLs = @()
    foreach ($role in $script:Configs.RBAC.Roles) {
        foreach ($dl in $role.DomainLocalGroups) {
            if ($dl.Name -notin $currentDLNames -and $dl.Name -notin ($availableDLs | ForEach-Object { $_.Name })) {
                $availableDLs += @{
                    Name        = [string]$dl.Name
                    Description = [string]$dl.Description
                    OU          = [string]$dl.OU
                }
            }
        }
    }
    foreach ($dl in $script:RemovedDLGroups) {
        if ($dl.Name -notin $currentDLNames -and $dl.Name -notin ($availableDLs | ForEach-Object { $_.Name })) {
            $availableDLs += @{
                Name        = [string]$dl.Name
                Description = [string]$dl.Description
                OU          = [string]$dl.OU
            }
        }
    }

    if ($availableDLs.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No other DL groups available to add.", "Info",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return $null
    }

    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Existing DL Groups" Width="500" Height="450"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <Grid Margin="24">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Text="Click Add on each DL group to include" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
        <Border Grid.Row="1" BorderBrush="#DDD" BorderThickness="1" CornerRadius="4" Background="White">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="4">
                <StackPanel Name="DLCardList"/>
            </ScrollViewer>
        </Border>
        <Button Name="BtnDone" Grid.Row="2" Content="Done" HorizontalAlignment="Right"
                Width="100" Padding="0,8" Margin="0,16,0,0"
                Background="#0078D4" Foreground="White" BorderThickness="0"
                FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
    </Grid>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $cardList = $dlg.FindName("DLCardList")
    $script:_pickResult = @()

    foreach ($info in $availableDLs) {
        $card = New-Object System.Windows.Controls.Border
        $card.Background = Get-WPFBrush "#F8F8F8"
        $card.CornerRadius = [System.Windows.CornerRadius]::new(6)
        $card.Padding = [System.Windows.Thickness]::new(12, 8, 12, 8)
        $card.Margin = [System.Windows.Thickness]::new(4, 4, 4, 4)

        $dock = New-Object System.Windows.Controls.DockPanel

        $addBtn = New-Object System.Windows.Controls.Button
        $addBtn.Content = "Add"
        $addBtn.Background = Get-WPFBrush "#E8F2FC"
        $addBtn.Foreground = Get-WPFBrush "#0078D4"
        $addBtn.BorderThickness = [System.Windows.Thickness]::new(0)
        $addBtn.Padding = [System.Windows.Thickness]::new(14, 4, 14, 4)
        $addBtn.FontSize = 12
        $addBtn.Cursor = "Hand"
        $addBtn.VerticalAlignment = "Center"
        $addBtn.Tag = @{ Name = [string]$info.Name; Description = [string]$info.Description; OU = [string]$info.OU }
        [System.Windows.Controls.DockPanel]::SetDock($addBtn, "Right")
        $addBtn.Add_Click({
            $data = $this.Tag
            $script:_pickResult += [PSCustomObject]@{
                Name        = $data.Name
                Description = $data.Description
                OU          = $data.OU
                Permissions = @()
            }
            $this.Content = "Added"
            $this.IsEnabled = $false
            $this.Background = Get-WPFBrush "#E0E0E0"
            $this.Foreground = Get-WPFBrush "#888"
        })

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.VerticalAlignment = "Center"

        $nameText = New-Object System.Windows.Controls.TextBlock
        $nameText.Text = $info.Name
        $nameText.FontSize = 13
        $nameText.FontWeight = "SemiBold"
        [void]$textStack.Children.Add($nameText)

        $descText = New-Object System.Windows.Controls.TextBlock
        $descText.Text = $info.Description
        $descText.FontSize = 11
        $descText.Foreground = Get-WPFBrush "#666"
        $descText.TextTrimming = "CharacterEllipsis"
        [void]$textStack.Children.Add($descText)

        [void]$dock.Children.Add($addBtn)
        [void]$dock.Children.Add($textStack)
        $card.Child = $dock
        [void]$cardList.Children.Add($card)
    }

    $dlg.Tag = $null
    $dlg.FindName("BtnDone").Add_Click({ $dlg.Tag = $true; $dlg.Close() }.GetNewClosure())

    $dlg.ShowDialog() | Out-Null
    $result = $script:_pickResult
    $script:_pickResult = $null
    if ($result.Count -eq 0) { return $null }
    return $result
}

function Show-ADSchemaSearchDialog {
    $searchXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Search AD Schema" Width="500" Height="500"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F5F5F5" FontFamily="Segoe UI">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBox Name="FilterBox" Grid.Row="0" Padding="8,6" FontSize="13"
                 BorderBrush="#D0D0D0" BorderThickness="1" Margin="0,0,0,10"/>
        <ListBox Name="ResultList" Grid.Row="1" FontSize="12" Padding="4"
                 BorderBrush="#D0D0D0" BorderThickness="1"/>
        <TextBlock Name="StatusText" Grid.Row="2" Margin="0,8,0,0"
                   FontSize="11" Foreground="#888888"
                   Text="Loading schema from AD..."/>
    </Grid>
</Window>
"@
    [xml]$searchDoc = $searchXaml
    $searchReader   = [System.Xml.XmlNodeReader]::new($searchDoc)
    $searchWindow   = [System.Windows.Markup.XamlReader]::Load($searchReader)
    $searchWindow.Owner = $script:Window

    $filterBox  = $searchWindow.FindName("FilterBox")
    $resultList = $searchWindow.FindName("ResultList")
    $statusText = $searchWindow.FindName("StatusText")

    $searchWindow.Tag = $null
    $allItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $connParam = New-LOCKmeADConnectionParam -Connection $script:Connection
        $rootDse = Get-ADRootDSE @connParam -ErrorAction Stop

        Get-ADObject -SearchBase $rootDse.schemaNamingContext `
                     -LDAPFilter "(schemaidguid=*)" `
                     -Properties lDAPDisplayName, objectClass `
                     @connParam -ErrorAction Stop |
            ForEach-Object {
                $type = if ('classSchema' -in $_.objectClass) { 'Class' } else { 'Attribute' }
                $allItems.Add([PSCustomObject]@{ Name = $_.lDAPDisplayName; Type = $type })
            }

        Get-ADObject -SearchBase $rootDse.configurationNamingContext `
                     -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" `
                     -Properties displayName `
                     @connParam -ErrorAction Stop |
            ForEach-Object {
                $allItems.Add([PSCustomObject]@{ Name = $_.displayName; Type = 'ExtendedRight' })
            }

        $sorted = $allItems | Sort-Object Type, Name

        foreach ($entry in $sorted) {
            $item = [System.Windows.Controls.ListBoxItem]::new()
            $item.Content = "$($entry.Name)  [$($entry.Type)]"
            $item.Tag     = $entry.Name
            $resultList.Items.Add($item) | Out-Null
        }

        $count = $resultList.Items.Count
        $statusText.Text = if ($count -eq 0) { "No schema items found." }
                           else { "$count item(s). Type to filter, double-click to select." }
    }
    catch {
        $statusText.Text = "Error: $($_.Exception.Message)"
        $sorted = @()
    }

    $capturedItems = $sorted
    $filterBox.Add_TextChanged({
        $filter = $filterBox.Text.Trim().ToLower()
        $resultList.Items.Clear()
        $filtered = if ([string]::IsNullOrWhiteSpace($filter)) { $capturedItems }
                    else { $capturedItems | Where-Object { $_.Name.ToLower().Contains($filter) } }
        foreach ($entry in $filtered) {
            $item = [System.Windows.Controls.ListBoxItem]::new()
            $item.Content = "$($entry.Name)  [$($entry.Type)]"
            $item.Tag     = $entry.Name
            $resultList.Items.Add($item) | Out-Null
        }
        $count = $resultList.Items.Count
        $statusText.Text = "$count item(s). Double-click to select."
    }.GetNewClosure())

    $resultList.Add_MouseDoubleClick({
        $selected = $resultList.SelectedItem
        if ($selected -and $selected.Tag) {
            $searchWindow.Tag = $selected.Tag
            $searchWindow.DialogResult = $true
        }
    }.GetNewClosure())

    $searchWindow.ShowDialog() | Out-Null
    return $searchWindow.Tag
}

function Show-PermissionDialog($existingPerm) {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Permission" Width="560" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="Permission" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,16"/>

        <TextBlock Text="Type" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <ComboBox Name="TypeSelect" FontSize="13" Padding="6,4" SelectedIndex="0">
            <ComboBoxItem Content="AD"/>
            <ComboBoxItem Content="NTFS"/>
            <ComboBoxItem Content="ADCS"/>
            <ComboBoxItem Content="Share"/>
        </ComboBox>

        <!-- AD fields -->
        <StackPanel Name="PanelAD" Margin="0,12,0,0">
            <TextBlock Text="Target OU (Distinguished Name)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <TextBox Name="ADTargetOU" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
            <TextBlock Text="AD Rights" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ADADRights" FontSize="13" Padding="6,4" IsEditable="True">
                <ComboBoxItem Content="GenericAll"/>
                <ComboBoxItem Content="WriteProperty"/>
                <ComboBoxItem Content="CreateChild, DeleteChild"/>
                <ComboBoxItem Content="ExtendedRight"/>
                <ComboBoxItem Content="ReadProperty"/>
            </ComboBox>
            <TextBlock Text="Inheritance Type" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ADInheritanceType" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="All"/>
                <ComboBoxItem Content="None"/>
                <ComboBoxItem Content="Descendents"/>
                <ComboBoxItem Content="SelfAndChildren"/>
                <ComboBoxItem Content="Children"/>
            </ComboBox>
            <TextBlock Text="Access Control Type" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ADAccessControl" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="Allow"/>
                <ComboBoxItem Content="Deny"/>
            </ComboBox>

            <Expander Header="Object Type / Inheritance Scope" Margin="0,14,0,0" FontSize="12" IsExpanded="True">
                <StackPanel Margin="0,8,0,0">
                    <TextBlock Text="ObjectType" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
                    <TextBlock Text="Targets a specific attribute, extended right, or object class. Leave empty for broad permissions (e.g. GenericAll)." FontSize="10" Foreground="#999" TextWrapping="Wrap" Margin="0,0,0,6"/>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="ADObjectType" Grid.Column="0" FontSize="13" Padding="6,4" BorderBrush="#DDD"/>
                        <Button Name="BtnSearchObjectType" Grid.Column="1" Content="Search AD" Margin="8,0,0,0"
                                Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                                FontSize="12" Padding="10,6" Cursor="Hand"/>
                    </Grid>
                    <TextBlock Text="InheritedObjectType" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
                    <TextBlock Text="Restricts inheritance to a specific child object class. Leave empty to apply to all child objects." FontSize="10" Foreground="#999" TextWrapping="Wrap" Margin="0,0,0,6"/>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="ADInheritedObjectType" Grid.Column="0" FontSize="13" Padding="6,4" BorderBrush="#DDD"/>
                        <Button Name="BtnSearchInheritedObjectType" Grid.Column="1" Content="Search AD" Margin="8,0,0,0"
                                Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                                FontSize="12" Padding="10,6" Cursor="Hand"/>
                    </Grid>
                </StackPanel>
            </Expander>
        </StackPanel>

        <!-- NTFS fields -->
        <StackPanel Name="PanelNTFS" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Text="Path (UNC or local)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBox Name="NTFSPath" Grid.Column="0" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <Button Name="BtnCheckNTFS" Grid.Column="1" Content="Check" Margin="8,0,0,0"
                        Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                        FontSize="12" Padding="10,6" Cursor="Hand"/>
            </Grid>
            <TextBlock Name="NTFSCheckStatus" FontSize="11" Margin="0,4,0,0" Visibility="Collapsed"/>
            <TextBlock Text="Rights" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="NTFSRights" FontSize="13" Padding="6,4" IsEditable="True">
                <ComboBoxItem Content="FullControl"/>
                <ComboBoxItem Content="Modify"/>
                <ComboBoxItem Content="ReadAndExecute"/>
                <ComboBoxItem Content="Read"/>
                <ComboBoxItem Content="Write"/>
            </ComboBox>
            <TextBlock Text="Inheritance Flags" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="NTFSInheritance" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="ContainerInherit, ObjectInherit"/>
                <ComboBoxItem Content="ContainerInherit"/>
                <ComboBoxItem Content="ObjectInherit"/>
                <ComboBoxItem Content="None"/>
            </ComboBox>
            <TextBlock Text="Propagation Flags" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="NTFSPropagation" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="None"/>
                <ComboBoxItem Content="InheritOnly"/>
                <ComboBoxItem Content="NoPropagateInherit"/>
            </ComboBox>
            <TextBlock Text="Access Control Type" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="NTFSAccessControl" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="Allow"/>
                <ComboBoxItem Content="Deny"/>
            </ComboBox>
            <CheckBox Name="NTFSSetShare" Content="Also set Share (SMB) permissions" Margin="0,14,0,0" FontSize="12"/>
            <StackPanel Name="PanelNTFSShare" Margin="0,8,0,0" Visibility="Collapsed">
                <TextBlock Text="Share Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
                <TextBox Name="NTFSShareName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <TextBlock Text="Share Right" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
                <ComboBox Name="NTFSShareRight" FontSize="13" Padding="6,4" SelectedIndex="1">
                    <ComboBoxItem Content="Full"/>
                    <ComboBoxItem Content="Change"/>
                    <ComboBoxItem Content="Read"/>
                </ComboBox>
            </StackPanel>
        </StackPanel>

        <!-- ADCS fields -->
        <StackPanel Name="PanelADCS" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Text="CA Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBox Name="ADCSCAName" Grid.Column="0" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <Button Name="BtnSearchCA" Grid.Column="1" Content="Search AD" Margin="8,0,0,0"
                        Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                        FontSize="12" Padding="10,6" Cursor="Hand"/>
            </Grid>
            <TextBlock Text="CA Hostname (FQDN)" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBox Name="ADCSCAHostname" Grid.Column="0" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <Button Name="BtnCheckADCS" Grid.Column="1" Content="Check" Margin="8,0,0,0"
                        Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                        FontSize="12" Padding="10,6" Cursor="Hand"/>
            </Grid>
            <TextBlock Name="ADCSCheckStatus" FontSize="11" Margin="0,4,0,0" Visibility="Collapsed"/>
            <TextBlock Text="Right" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ADCSRight" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="ManageCA"/>
                <ComboBoxItem Content="ManageCertificates"/>
                <ComboBoxItem Content="Enroll"/>
                <ComboBoxItem Content="Read"/>
            </ComboBox>
        </StackPanel>

        <!-- Share fields -->
        <StackPanel Name="PanelShare" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Text="File Server (hostname or FQDN)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBox Name="ShareServer" Grid.Column="0" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
                <Button Name="BtnCheckShare" Grid.Column="1" Content="Check" Margin="8,0,0,0"
                        Background="#F0F0F0" BorderBrush="#CCC" BorderThickness="1"
                        FontSize="12" Padding="10,6" Cursor="Hand"/>
            </Grid>
            <TextBlock Name="ShareCheckStatus" FontSize="11" Margin="0,4,0,0" Visibility="Collapsed"/>
            <TextBlock Text="Share Name" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <TextBox Name="ShareName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
            <TextBlock Text="Share Right" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ShareRight" FontSize="13" Padding="6,4" SelectedIndex="1">
                <ComboBoxItem Content="Full"/>
                <ComboBoxItem Content="Change"/>
                <ComboBoxItem Content="Read"/>
            </ComboBox>
        </StackPanel>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Save" Width="110" Padding="0,8"
                    Background="#0078D4" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $cmbType    = $dlg.FindName("TypeSelect")
    $panelAD    = $dlg.FindName("PanelAD")
    $panelNTFS  = $dlg.FindName("PanelNTFS")
    $panelADCS  = $dlg.FindName("PanelADCS")
    $panelShare = $dlg.FindName("PanelShare")

    # Type switching
    $cmbType.Add_SelectionChanged({
        $sel = $cmbType.SelectedItem.Content
        $panelAD.Visibility    = if ($sel -eq "AD")    { "Visible" } else { "Collapsed" }
        $panelNTFS.Visibility  = if ($sel -eq "NTFS")  { "Visible" } else { "Collapsed" }
        $panelADCS.Visibility  = if ($sel -eq "ADCS")  { "Visible" } else { "Collapsed" }
        $panelShare.Visibility = if ($sel -eq "Share") { "Visible" } else { "Collapsed" }
    }.GetNewClosure())

    # NTFS path connectivity check
    $ntfsPathBox     = $dlg.FindName("NTFSPath")
    $ntfsCheckStatus = $dlg.FindName("NTFSCheckStatus")
    $dlg.FindName("BtnCheckNTFS").Add_Click({
        $path = $ntfsPathBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($path)) {
            $ntfsCheckStatus.Text       = "Enter a path first."
            $ntfsCheckStatus.Foreground = Get-WPFBrush "#E67E22"
            $ntfsCheckStatus.Visibility = "Visible"
            return
        }
        $ntfsCheckStatus.Text       = "Checking..."
        $ntfsCheckStatus.Foreground = Get-WPFBrush "#888888"
        $ntfsCheckStatus.Visibility = "Visible"
        $dlg.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            if (Test-Path -LiteralPath $path) {
                $ntfsCheckStatus.Text       = [char]0x2713 + " Path is reachable"
                $ntfsCheckStatus.Foreground = Get-WPFBrush "#1E8449"
            } else {
                $ntfsCheckStatus.Text       = [char]0x2717 + " Path not found or not accessible"
                $ntfsCheckStatus.Foreground = Get-WPFBrush "#C0392B"
            }
        } catch {
            $ntfsCheckStatus.Text       = [char]0x2717 + " $($_.Exception.Message)"
            $ntfsCheckStatus.Foreground = Get-WPFBrush "#C0392B"
        } finally {
            $dlg.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    })

    # NTFS share (SMB) permissions toggle
    $ntfsSetShare    = $dlg.FindName("NTFSSetShare")
    $panelNTFSShare  = $dlg.FindName("PanelNTFSShare")
    $ntfsSetShare.Add_Checked({   $panelNTFSShare.Visibility = "Visible"   })
    $ntfsSetShare.Add_Unchecked({ $panelNTFSShare.Visibility = "Collapsed" })

    # ADCS CA search from AD
    $adcsCANameBox   = $dlg.FindName("ADCSCAName")
    $adcsHostnameBox = $dlg.FindName("ADCSCAHostname")
    $dlg.FindName("BtnSearchCA").Add_Click({
        $result = Show-CASearchDialog
        if ($result) {
            $adcsCANameBox.Text   = $result.CAName
            $adcsHostnameBox.Text = $result.CAHostname
        }
    })

    # ADCS CA hostname connectivity check (DCOM port 135 used by remote registry)
    $adcsCheckStatus  = $dlg.FindName("ADCSCheckStatus")
    $dlg.FindName("BtnCheckADCS").Add_Click({
        $hostname = $adcsHostnameBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $adcsCheckStatus.Text       = "Enter a CA hostname first."
            $adcsCheckStatus.Foreground = Get-WPFBrush "#E67E22"
            $adcsCheckStatus.Visibility = "Visible"
            return
        }
        $adcsCheckStatus.Text       = "Checking..."
        $adcsCheckStatus.Foreground = Get-WPFBrush "#888888"
        $adcsCheckStatus.Visibility = "Visible"
        $dlg.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $reachable = Test-NetConnection -ComputerName $hostname -Port 135 `
                             -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($reachable) {
                $adcsCheckStatus.Text       = [char]0x2713 + " CA host reachable (DCOM/RPC port 135)"
                $adcsCheckStatus.Foreground = Get-WPFBrush "#1E8449"
            } else {
                $adcsCheckStatus.Text       = [char]0x2717 + " CA host not reachable on port 135"
                $adcsCheckStatus.Foreground = Get-WPFBrush "#C0392B"
            }
        } catch {
            $adcsCheckStatus.Text       = [char]0x2717 + " $($_.Exception.Message)"
            $adcsCheckStatus.Foreground = Get-WPFBrush "#C0392B"
        } finally {
            $dlg.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    })

    # Share file server connectivity check (SMB port 445)
    $shareServerBox   = $dlg.FindName("ShareServer")
    $shareCheckStatus = $dlg.FindName("ShareCheckStatus")
    $dlg.FindName("BtnCheckShare").Add_Click({
        $hostname = $shareServerBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($hostname)) {
            $shareCheckStatus.Text       = "Enter a file server hostname first."
            $shareCheckStatus.Foreground = Get-WPFBrush "#E67E22"
            $shareCheckStatus.Visibility = "Visible"
            return
        }
        $shareCheckStatus.Text       = "Checking..."
        $shareCheckStatus.Foreground = Get-WPFBrush "#888888"
        $shareCheckStatus.Visibility = "Visible"
        $dlg.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $reachable = Test-NetConnection -ComputerName $hostname -Port 445 `
                             -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($reachable) {
                $shareCheckStatus.Text       = [char]0x2713 + " File server reachable (SMB port 445)"
                $shareCheckStatus.Foreground = Get-WPFBrush "#1E8449"
            } else {
                $shareCheckStatus.Text       = [char]0x2717 + " File server not reachable on port 445"
                $shareCheckStatus.Foreground = Get-WPFBrush "#C0392B"
            }
        } catch {
            $shareCheckStatus.Text       = [char]0x2717 + " $($_.Exception.Message)"
            $shareCheckStatus.Foreground = Get-WPFBrush "#C0392B"
        } finally {
            $dlg.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    })

    # AD schema search for ObjectType
    $objTypeBox      = $dlg.FindName("ADObjectType")
    $inheritedTypeBox = $dlg.FindName("ADInheritedObjectType")
    $schemaSearchFn  = ${function:Show-ADSchemaSearchDialog}

    $dlg.FindName("BtnSearchObjectType").Add_Click({
        $selected = & $schemaSearchFn
        if ($selected) { $objTypeBox.Text = $selected }
    }.GetNewClosure())

    $dlg.FindName("BtnSearchInheritedObjectType").Add_Click({
        $selected = & $schemaSearchFn
        if ($selected) { $inheritedTypeBox.Text = $selected }
    }.GetNewClosure())

    # Pre-fill if editing
    if ($existingPerm) {
        switch ($existingPerm.Type) {
            "AD" {
                $cmbType.SelectedIndex = 0
                $dlg.FindName("ADTargetOU").Text = $existingPerm.TargetOU
                $dlg.FindName("ADADRights").Text = $existingPerm.ADRights
                $dlg.FindName("ADObjectType").Text = Resolve-GuidToDisplayName $existingPerm.ObjectType
                $dlg.FindName("ADInheritedObjectType").Text = Resolve-GuidToDisplayName $existingPerm.InheritedObjectType
                foreach ($item in $dlg.FindName("ADInheritanceType").Items) {
                    if ($item.Content -eq $existingPerm.InheritanceType) { $item.IsSelected = $true }
                }
                foreach ($item in $dlg.FindName("ADAccessControl").Items) {
                    if ($item.Content -eq $existingPerm.AccessControlType) { $item.IsSelected = $true }
                }
            }
            "NTFS" {
                $cmbType.SelectedIndex = 1
                $panelAD.Visibility = "Collapsed"; $panelNTFS.Visibility = "Visible"
                $dlg.FindName("NTFSPath").Text = $existingPerm.Path
                $dlg.FindName("NTFSRights").Text = $existingPerm.Rights
                foreach ($item in $dlg.FindName("NTFSInheritance").Items) {
                    if ($item.Content -eq $existingPerm.InheritanceFlags) { $item.IsSelected = $true }
                }
                foreach ($item in $dlg.FindName("NTFSPropagation").Items) {
                    if ($item.Content -eq $existingPerm.PropagationFlags) { $item.IsSelected = $true }
                }
                foreach ($item in $dlg.FindName("NTFSAccessControl").Items) {
                    if ($item.Content -eq $existingPerm.AccessControlType) { $item.IsSelected = $true }
                }
                if ($existingPerm.ShareName) {
                    $dlg.FindName("NTFSSetShare").IsChecked = $true
                    $dlg.FindName("PanelNTFSShare").Visibility = "Visible"
                    $dlg.FindName("NTFSShareName").Text = $existingPerm.ShareName
                    foreach ($item in $dlg.FindName("NTFSShareRight").Items) {
                        if ($item.Content -eq $existingPerm.ShareRight) { $item.IsSelected = $true }
                    }
                }
            }
            "ADCS" {
                $cmbType.SelectedIndex = 2
                $panelAD.Visibility = "Collapsed"; $panelADCS.Visibility = "Visible"
                $dlg.FindName("ADCSCAName").Text = $existingPerm.CAName
                $dlg.FindName("ADCSCAHostname").Text = $existingPerm.CAHostname
                foreach ($item in $dlg.FindName("ADCSRight").Items) {
                    if ($item.Content -eq $existingPerm.Right) { $item.IsSelected = $true }
                }
            }
            "Share" {
                $cmbType.SelectedIndex = 3
                $panelAD.Visibility = "Collapsed"; $panelShare.Visibility = "Visible"
                $dlg.FindName("ShareServer").Text = $existingPerm.ShareServer
                $dlg.FindName("ShareName").Text   = $existingPerm.ShareName
                foreach ($item in $dlg.FindName("ShareRight").Items) {
                    if ($item.Content -eq $existingPerm.ShareRight) { $item.IsSelected = $true }
                }
            }
        }
    }

    $dlg.Tag = $null
    $dlg.FindName("BtnOK").Add_Click({
        $type = $cmbType.SelectedItem.Content
        $perm = $null
        switch ($type) {
            "AD" {
                $perm = [PSCustomObject]@{
                    Type                = "AD"
                    TargetOU            = $dlg.FindName("ADTargetOU").Text
                    ADRights            = $dlg.FindName("ADADRights").Text
                    ObjectType          = $dlg.FindName("ADObjectType").Text
                    InheritanceType     = $dlg.FindName("ADInheritanceType").SelectedItem.Content
                    InheritedObjectType = $dlg.FindName("ADInheritedObjectType").Text
                    AccessControlType   = $dlg.FindName("ADAccessControl").SelectedItem.Content
                }
            }
            "NTFS" {
                $perm = [PSCustomObject]@{
                    Type              = "NTFS"
                    Path              = $dlg.FindName("NTFSPath").Text
                    Rights            = $dlg.FindName("NTFSRights").Text
                    InheritanceFlags  = $dlg.FindName("NTFSInheritance").SelectedItem.Content
                    PropagationFlags  = $dlg.FindName("NTFSPropagation").SelectedItem.Content
                    AccessControlType = $dlg.FindName("NTFSAccessControl").SelectedItem.Content
                    ShareName         = if ($dlg.FindName("NTFSSetShare").IsChecked) { $dlg.FindName("NTFSShareName").Text } else { $null }
                    ShareRight        = if ($dlg.FindName("NTFSSetShare").IsChecked) { $dlg.FindName("NTFSShareRight").SelectedItem.Content } else { $null }
                }
            }
            "ADCS" {
                $perm = [PSCustomObject]@{
                    Type       = "ADCS"
                    CAName     = $dlg.FindName("ADCSCAName").Text
                    CAHostname = $dlg.FindName("ADCSCAHostname").Text
                    Right      = $dlg.FindName("ADCSRight").SelectedItem.Content
                }
            }
            "Share" {
                $perm = [PSCustomObject]@{
                    Type        = "Share"
                    ShareServer = $dlg.FindName("ShareServer").Text
                    ShareName   = $dlg.FindName("ShareName").Text
                    ShareRight  = $dlg.FindName("ShareRight").SelectedItem.Content
                }
            }
        }
        $dlg.Tag = $perm
        $dlg.Close()
    }.GetNewClosure())
    $dlg.FindName("BtnCancel").Add_Click({ $dlg.Close() }.GetNewClosure())

    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

# ============================================================================
# PSO Dialogs & Helpers
# ============================================================================

function Show-AddPSODialog {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Password Policy" Width="580" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="700">
    <StackPanel Margin="24">
        <TextBlock Text="New Password Policy (PSO)" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,20"/>

        <TextBlock Text="Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox Name="PSOName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <TextBlock Text="Description" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="PSODesc" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>

        <TextBlock Text="Precedence (lower = higher priority)" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
        <TextBox Name="PSOPrecedence" FontSize="13" Padding="8,6" BorderBrush="#DDD" Text="50"/>

        <Border Background="#E8F2FC" CornerRadius="6" Padding="14" Margin="0,16,0,0">
            <StackPanel>
                <TextBlock Text="Password Settings" FontSize="13" FontWeight="SemiBold"
                           Foreground="#0078D4" Margin="0,0,0,10"/>

                <CheckBox Name="PSOComplexity" Content="Password must meet complexity requirements"
                          FontSize="12" IsChecked="True" Margin="0,0,0,8"/>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Minimum password length" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOMinLength" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="12"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Minimum password age (days)" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOMinAge" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="1"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Maximum password age (days)" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOMaxAge" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="90"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Password history count" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOHistoryCount" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="24"/>
                </StackPanel>

                <CheckBox Name="PSOReversible" Content="Store password using reversible encryption"
                          FontSize="12" IsChecked="False" Margin="0,4,0,0"/>
            </StackPanel>
        </Border>

        <Border Background="#FFF8E8" CornerRadius="6" Padding="14" Margin="0,12,0,0">
            <StackPanel>
                <TextBlock Text="Account Lockout" FontSize="13" FontWeight="SemiBold"
                           Foreground="#B7950B" Margin="0,0,0,10"/>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Lockout threshold (0 = no lockout)" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOLockoutThreshold" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="5"/>
                </StackPanel>

                <CheckBox Name="PSOLockForever" Content="Until an administrator manually unlocks the account"
                          FontSize="12" IsChecked="False" Margin="0,4,0,8"/>

                <StackPanel Name="PSOLockDurationPanel" Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Lockout duration (minutes)" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOLockDuration" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="30"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <TextBlock Text="Observation window (minutes)" FontSize="12" Foreground="#555"
                               VerticalAlignment="Center" Width="220"/>
                    <TextBox Name="PSOLockWindow" FontSize="13" Padding="6,4" BorderBrush="#DDD"
                             Width="80" Text="30"/>
                </StackPanel>
            </StackPanel>
        </Border>

        <Border Background="#F0F0F0" CornerRadius="6" Padding="14" Margin="0,12,0,0">
            <StackPanel>
                <TextBlock Text="Applies To" FontSize="13" FontWeight="SemiBold"
                           Foreground="#555" Margin="0,0,0,4"/>
                <TextBlock Text="One group or user name per line" FontSize="10"
                           Foreground="#999" Margin="0,0,0,6"/>
                <TextBox Name="PSOAppliesTo" FontSize="12" Padding="6,4" BorderBrush="#DDD"
                         AcceptsReturn="True" TextWrapping="Wrap" MinLines="2" MaxLines="5"
                         VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
        </Border>

        <CheckBox Name="PSOProtected" Content="Protected from accidental deletion"
                  FontSize="12" IsChecked="True" Margin="0,14,0,0"/>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Add Policy" Width="120" Padding="0,8"
                    Background="#0078D4" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
    </ScrollViewer>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $txtName      = $dlg.FindName("PSOName")
    $txtDesc      = $dlg.FindName("PSODesc")
    $txtPrec      = $dlg.FindName("PSOPrecedence")
    $chkComplex   = $dlg.FindName("PSOComplexity")
    $txtMinLen    = $dlg.FindName("PSOMinLength")
    $txtMinAge    = $dlg.FindName("PSOMinAge")
    $txtMaxAge    = $dlg.FindName("PSOMaxAge")
    $txtHistory   = $dlg.FindName("PSOHistoryCount")
    $chkReversible = $dlg.FindName("PSOReversible")
    $txtThreshold = $dlg.FindName("PSOLockoutThreshold")
    $chkLockForever = $dlg.FindName("PSOLockForever")
    $pnlLockDuration = $dlg.FindName("PSOLockDurationPanel")
    $txtLockDur   = $dlg.FindName("PSOLockDuration")
    $txtLockWin   = $dlg.FindName("PSOLockWindow")
    $txtAppliesTo = $dlg.FindName("PSOAppliesTo")
    $chkProtected = $dlg.FindName("PSOProtected")
    $btnOK        = $dlg.FindName("BtnOK")
    $btnCancel    = $dlg.FindName("BtnCancel")

    # Lock forever toggle
    $chkLockForever.Add_Checked({
        $pnlLockDuration.IsEnabled = $false
        $txtLockDur.Text = "0"
    }.GetNewClosure())
    $chkLockForever.Add_Unchecked({
        $pnlLockDuration.IsEnabled = $true
        if ($txtLockDur.Text -eq "0") { $txtLockDur.Text = "30" }
    }.GetNewClosure())

    $dlg.Tag = $null
    $btnOK.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.MessageBox]::Show("Policy name is required.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $prec = 0
        if (-not [int]::TryParse($txtPrec.Text, [ref]$prec) -or $prec -lt 1) {
            [System.Windows.MessageBox]::Show("Precedence must be a positive integer.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        # Check for duplicate name
        $existingNames = @($script:Configs.PSO.Policies | ForEach-Object { $_.Name })
        if ($txtName.Text.Trim() -in $existingNames) {
            [System.Windows.MessageBox]::Show("A policy with this name already exists.", "Validation",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $subjects = @()
        if (-not [string]::IsNullOrWhiteSpace($txtAppliesTo.Text)) {
            $subjects = @($txtAppliesTo.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }

        $dlg.Tag = [PSCustomObject]@{
            Name                            = $txtName.Text.Trim()
            Description                     = $txtDesc.Text
            Enabled                         = $true
            Precedence                      = [int]$txtPrec.Text
            ComplexityEnabled               = [bool]$chkComplex.IsChecked
            MinPasswordLength               = [int]$txtMinLen.Text
            MinPasswordAgeDays              = [int]$txtMinAge.Text
            MaxPasswordAgeDays              = [int]$txtMaxAge.Text
            PasswordHistoryCount            = [int]$txtHistory.Text
            LockoutThreshold                = [int]$txtThreshold.Text
            LockoutDurationMinutes          = [int]$txtLockDur.Text
            LockoutObservationWindowMinutes = [int]$txtLockWin.Text
            ReversibleEncryptionEnabled     = [bool]$chkReversible.IsChecked
            ProtectedFromAccidentalDeletion = [bool]$chkProtected.IsChecked
            AppliesTo                       = $subjects
        }
        $dlg.Close()
    }.GetNewClosure())

    $btnCancel.Add_Click({ $dlg.Close() }.GetNewClosure())
    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

function Show-DeletePSODialog([string[]]$policyNames) {
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Delete Password Policy" Width="400" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        Background="#F3F3F3" FontFamily="Segoe UI">
    <StackPanel Margin="24">
        <TextBlock Text="Select a policy to delete" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
        <ListBox Name="PolicyList" FontSize="13" Padding="4" MinHeight="80" MaxHeight="300"
                 BorderBrush="#DDD" BorderThickness="1"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="90" Padding="0,8"
                    Background="#E8E8E8" BorderThickness="0" FontSize="13" Cursor="Hand" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Delete" Width="100" Padding="0,8"
                    Background="#A93226" Foreground="White" BorderThickness="0"
                    FontSize="13" FontWeight="SemiBold" Cursor="Hand"/>
        </StackPanel>
    </StackPanel>
</Window>
"@
    [xml]$dlgDoc = $dialogXaml
    $reader = [System.Xml.XmlNodeReader]::new($dlgDoc)
    $dlg = [System.Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:Window

    $listBox = $dlg.FindName("PolicyList")
    foreach ($name in $policyNames) {
        $listBox.Items.Add($name) | Out-Null
    }
    if ($listBox.Items.Count -gt 0) { $listBox.SelectedIndex = 0 }

    $dlg.Tag = $null
    $dlg.FindName("BtnOK").Add_Click({
        if ($listBox.SelectedItem) {
            $dlg.Tag = $listBox.SelectedItem
        }
        $dlg.Close()
    }.GetNewClosure())
    $dlg.FindName("BtnCancel").Add_Click({ $dlg.Close() }.GetNewClosure())

    $dlg.ShowDialog() | Out-Null
    return $dlg.Tag
}

# ============================================================================
# Initialize & Register Events
# ============================================================================

function Initialize-GUI {
    Load-AllConfigs
    Write-ConsoleUI "Configurations loaded." "Success"

    # Resolved once, here, rather than per card: Populate-HardeningTab runs on every refresh and
    # this costs a handful of LDAP queries. Domain Admins is already guaranteed by the connection
    # gate, so only IsSchemaAdmin is actually consumed downstream.
    $script:Privilege = Test-LOCKmeADPrivilege -Server $script:Connection.Server -Credential $script:Connection.Credential

    Populate-Dashboard
    if ($script:Configs.Hardening) { Populate-HardeningTab }
    if ($script:Configs.GPO)       { Populate-GPOTab }
    if ($script:Configs.Tiering)   { Populate-TieringTab }
    if ($script:Configs.RBAC)      { Populate-RBACTab }
    if ($script:Configs.PSO)       { Populate-PSOTab }
    if ($script:Configs.Silo)      { Populate-SiloTab }
    if ($script:Configs.JIT)       { Populate-JITTab }

    Write-ConsoleUI "GUI initialized. Ready." "Info"
}

function Register-GUIEvents {
    # Navigation
    $UI.NavDashboard.Add_Click({ Set-ActiveTab 0 })
    $UI.NavHardening.Add_Click({ Set-ActiveTab 1 })
    $UI.NavGPO.Add_Click({ Set-ActiveTab 2 })
    $UI.NavTiering.Add_Click({ Set-ActiveTab 3 })
    $UI.NavRBAC.Add_Click({ Set-ActiveTab 4 })
    $UI.NavPSO.Add_Click({ Set-ActiveTab 5 })
    $UI.NavSilo.Add_Click({ Set-ActiveTab 6 })
    $UI.NavJIT.Add_Click({ Set-ActiveTab 7 })

    # Search
    $UI.SearchBox.Add_TextChanged({ Invoke-Search $UI.SearchBox.Text })
    $UI.SearchBox.Add_GotFocus({ $UI.SearchPlaceholder.Visibility = "Collapsed" })
    $UI.SearchBox.Add_LostFocus({
        if ([string]::IsNullOrEmpty($UI.SearchBox.Text)) {
            $UI.SearchPlaceholder.Visibility = "Visible"
        }
    })

    # Hardening toolbar
    $UI.BtnSelectAll.Add_Click({
        foreach ($t in $script:HardeningToggles) { $t.IsChecked = $true }
    })
    $UI.BtnDeselectAll.Add_Click({
        foreach ($t in $script:HardeningToggles) { $t.IsChecked = $false }
    })

    $UI.BtnVerifyAll.Add_Click({
        $UI.BtnVerifyAll.IsEnabled = $false

        # Ensure the Hardening module is loaded — in a fresh session where Deploy
        # has not been run, the module is not yet imported
        $appRoot    = Split-Path (Split-Path $script:ScriptPaths.Hardening)
        $modulePath = Join-Path $appRoot "Modules\Hardening\Hardening.psm1"
        try {
            Import-Module $modulePath -Force -ErrorAction Stop
        } catch {
            Write-ConsoleUI "Cannot load Hardening module: $_" "Error"
            $UI.BtnVerifyAll.IsEnabled = $true
            return
        }

        # Mark badges as "checking" based on live toggle state, not saved config
        for ($i = 0; $i -lt $script:Configs.Hardening.Tasks.Count; $i++) {
            if (-not $script:HardeningToggles[$i].IsChecked) { continue }
            $b = $script:HardeningStatusBadges[$script:Configs.Hardening.Tasks[$i].Name]
            if ($b) {
                $b.Border.Background = Get-WPFBrush "#EBF5FB"
                $b.Text.Foreground   = Get-WPFBrush "#0078D4"
                $b.Text.Text         = "..."
            }
        }
        $script:Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

        for ($i = 0; $i -lt $script:Configs.Hardening.Tasks.Count; $i++) {
            if (-not $script:HardeningToggles[$i].IsChecked) { continue }
            $task = $script:Configs.Hardening.Tasks[$i]
            $b = $script:HardeningStatusBadges[$task.Name]
            if (-not $b) { continue }

            try {
                $result = Test-HardeningTask -TaskName $task.Name -TaskParameters $task.Parameters `
                    -Server $script:Connection.Server -Credential $script:Connection.Credential
                switch ($result.Status) {
                    'OK'      {
                        $b.Border.Background = Get-WPFBrush "#E8F5E9"
                        $b.Text.Foreground   = Get-WPFBrush "#2E7D32"
                        $b.Text.Text         = "✓ Applied"
                    }
                    'NotOK'   {
                        $b.Border.Background = Get-WPFBrush "#FFEBEE"
                        $b.Text.Foreground   = Get-WPFBrush "#C62828"
                        $b.Text.Text         = "✗ Missing"
                    }
                    'Partial' {
                        $b.Border.Background = Get-WPFBrush "#FFF8E1"
                        $b.Text.Foreground   = Get-WPFBrush "#F57F17"
                        $b.Text.Text         = "⚠ Partial"
                    }
                    'Info'    {
                        $b.Border.Background = Get-WPFBrush "#E3F2FD"
                        $b.Text.Foreground   = Get-WPFBrush "#1565C0"
                        $b.Text.Text         = "ℹ Details"
                    }
                    default   {
                        $b.Border.Background = Get-WPFBrush "#FFF3E0"
                        $b.Text.Foreground   = Get-WPFBrush "#E65100"
                        $b.Text.Text         = "? Error"
                    }
                }
                $b.Border.ToolTip = $result.Message
                $b.Message        = $result.Message
            } catch {
                $b.Border.Background = Get-WPFBrush "#FFF3E0"
                $b.Text.Foreground   = Get-WPFBrush "#E65100"
                $b.Text.Text         = "? Error"
                $b.Border.ToolTip    = $_.Exception.Message
                $b.Message           = $_.Exception.Message
            }
            $script:Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
        }

        $UI.BtnVerifyAll.IsEnabled = $true
    })

    # GPO toolbar
    $UI.BtnGPOSelectAll.Add_Click({
        foreach ($t in $script:GPOToggles) { $t.IsChecked = $true }
    })
    $UI.BtnGPODeselectAll.Add_Click({
        foreach ($t in $script:GPOToggles) { $t.IsChecked = $false }
    })

    # PSO toolbar
    $UI.BtnPSOSelectAll.Add_Click({
        foreach ($t in $script:PSOToggles) { $t.IsChecked = $true }
    })
    $UI.BtnPSODeselectAll.Add_Click({
        foreach ($t in $script:PSOToggles) { $t.IsChecked = $false }
    })

    # PSO add policy
    $UI.BtnAddPSO.Add_Click({
        $newPolicy = Show-AddPSODialog
        if ($newPolicy) {
            $script:Configs.PSO.Policies = @($script:Configs.PSO.Policies) + @($newPolicy)
            Populate-PSOTab
            Write-ConsoleUI "Policy '$($newPolicy.Name)' added." "Success"
        }
    })

    # PSO delete policy
    $UI.BtnDeletePSO.Add_Click({
        # Find which policy card is toggled ON and at the end of the list, or use a simpler approach:
        # Delete the last policy whose toggle matches, or ask the user to pick.
        # Simplest: show a picker dialog.
        if (-not $script:Configs.PSO -or $script:Configs.PSO.Policies.Count -eq 0) {
            Write-ConsoleUI "No policies to delete." "Warning"
            return
        }
        $names = @($script:Configs.PSO.Policies | ForEach-Object { $_.Name })
        $picked = Show-DeletePSODialog $names
        if ($picked) {
            $result = [System.Windows.MessageBox]::Show(
                "Delete policy '$picked'? This cannot be undone.", "Confirm Deletion",
                [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
            if ($result -eq "Yes") {
                $script:Configs.PSO.Policies = @($script:Configs.PSO.Policies | Where-Object { $_.Name -ne $picked })
                Populate-PSOTab
                Write-ConsoleUI "Policy '$picked' deleted." "Success"
            }
        }
    })

    # Silo toolbar
    $UI.BtnSiloSelectAll.Add_Click({
        foreach ($t in $script:SiloToggles) { $t.IsChecked = $true }
    })
    $UI.BtnSiloDeselectAll.Add_Click({
        foreach ($t in $script:SiloToggles) { $t.IsChecked = $false }
    })

    # Silo add
    $UI.BtnAddSilo.Add_Click({
        $newSilo = Show-AddSiloDialog
        if ($newSilo) {
            $script:Configs.Silo.Silos = @($script:Configs.Silo.Silos) + @($newSilo)
            Populate-SiloTab
            Write-ConsoleUI "Silo '$($newSilo.Name)' added." "Success"
        }
    })

    # Silo delete
    $UI.BtnDeleteSilo.Add_Click({
        if (-not $script:Configs.Silo -or $script:Configs.Silo.Silos.Count -eq 0) {
            Write-ConsoleUI "No silos to delete." "Warning"
            return
        }
        $names = @($script:Configs.Silo.Silos | ForEach-Object { $_.Name })
        $picked = Show-DeleteSiloDialog $names
        if ($picked) {
            $result = [System.Windows.MessageBox]::Show(
                "Delete silo '$picked'? This cannot be undone.", "Confirm Deletion",
                [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
            if ($result -eq "Yes") {
                $script:Configs.Silo.Silos = @($script:Configs.Silo.Silos | Where-Object { $_.Name -ne $picked })
                Populate-SiloTab
                Write-ConsoleUI "Silo '$picked' deleted." "Success"
            }
        }
    })

    # GPO Filtering Groups OU copy button
    $UI.GPOFilteringOUCopy.Add_Click({
        $ou = $UI.GPOFilteringGroupsOU.Text
        if ($ou) { [System.Windows.Clipboard]::SetText($ou) }
    })

    # GPO Filtering Groups OU: real-time validation
    $UI.GPOFilteringGroupsOU.Add_TextChanged({
        Update-GPOFilteringOUWarning
        $script:UnsavedChanges.GPO = $true
    })

    # Tiering DN copy button
    $UI.TieringPropDNCopy.Add_Click({
        $dn = $UI.TieringPropDN.Text
        if ($dn -and $dn -ne '-') { [System.Windows.Clipboard]::SetText($dn) }
    })

    # RBAC GG OU copy button
    $UI.RBACGGOUCopy.Add_Click({
        $ou = $UI.RBACGGOU.Text
        if ($ou) { [System.Windows.Clipboard]::SetText($ou) }
    })

    # Tiering tree selection
    $UI.TieringTree.Add_SelectedItemChanged({
        $selected = $UI.TieringTree.SelectedItem
        $script:isUpdatingSelection = $true
        if ($selected -and $selected.Tag) {
            $UI.TieringPropName.Text = $selected.Tag.Name
            $UI.TieringPropDesc.Text = $selected.Tag.Description
            $UI.TieringPropProtected.IsChecked = $selected.Tag.Protected
            $UI.TieringPropDN.Text = $selected.Tag.DN
            $UI.TieringPropName.IsEnabled = $true
            $UI.TieringPropDesc.IsEnabled = $true
            $UI.TieringPropProtected.IsEnabled = $true
        } else {
            $UI.TieringPropName.Text = ""
            $UI.TieringPropDesc.Text = ""
            $UI.TieringPropProtected.IsChecked = $false
            $UI.TieringPropDN.Text = "-"
            $UI.TieringPropName.IsEnabled = $false
            $UI.TieringPropDesc.IsEnabled = $false
            $UI.TieringPropProtected.IsEnabled = $false
        }
        $script:isUpdatingSelection = $false
    })

    # Tiering property edits -> update tree item tag + DN (guarded)
    $UI.TieringPropName.Add_TextChanged({
        if ($script:isUpdatingSelection) { return }
        $selected = $UI.TieringTree.SelectedItem
        if ($selected -and $UI.TieringPropName.Text.Length -gt 0) {
            $selected.Tag.Name = $UI.TieringPropName.Text
            $selected.Header = $UI.TieringPropName.Text
            Update-TreeItemDN $selected
            $UI.TieringPropDN.Text = $selected.Tag.DN
        }
    })
    $UI.TieringPropDesc.Add_TextChanged({
        if ($script:isUpdatingSelection) { return }
        $selected = $UI.TieringTree.SelectedItem
        if ($selected) { $selected.Tag.Description = $UI.TieringPropDesc.Text }
    })
    $UI.TieringPropProtected.Add_Click({
        $selected = $UI.TieringTree.SelectedItem
        if ($selected) { $selected.Tag.Protected = [bool]$UI.TieringPropProtected.IsChecked }
    })

    # Tiering add/delete OU
    $UI.BtnAddRootOU.Add_Click({
        $newItem = New-Object System.Windows.Controls.TreeViewItem
        $newItem.Header = "NewOU"
        $newItem.IsExpanded = $true
        $newItem.FontSize = 13
        $baseDN = $UI.TieringBaseDN.Text
        $newItem.Tag = @{ Name = "NewOU"; Description = ""; Protected = $true; DN = "OU=NewOU,$baseDN" }
        $UI.TieringTree.Items.Add($newItem) | Out-Null
        $newItem.IsSelected = $true
    })
    $UI.BtnAddChildOU.Add_Click({
        $parent = $UI.TieringTree.SelectedItem
        if (-not $parent) {
            Write-ConsoleUI "Select a parent OU first." "Warning"
            return
        }
        $newItem = New-Object System.Windows.Controls.TreeViewItem
        $newItem.Header = "NewChildOU"
        $newItem.IsExpanded = $true
        $newItem.FontSize = 13
        $newItem.Tag = @{ Name = "NewChildOU"; Description = ""; Protected = $true; DN = "OU=NewChildOU,$($parent.Tag.DN)" }
        $parent.Items.Add($newItem) | Out-Null
        $parent.IsExpanded = $true
        $newItem.IsSelected = $true
    })
    $UI.BtnDeleteOU.Add_Click({
        $selected = $UI.TieringTree.SelectedItem
        if (-not $selected) { return }
        $parent = $selected.Parent
        if ($parent -is [System.Windows.Controls.TreeView]) {
            $parent.Items.Remove($selected)
        } elseif ($parent -is [System.Windows.Controls.TreeViewItem]) {
            $parent.Items.Remove($selected)
        }
    })

    # RBAC role selection
    $UI.RBACRoleList.Add_SelectionChanged({
        $selected = $UI.RBACRoleList.SelectedItem
        if ($selected -and $selected.Tag) {
            Show-RBACRoleDetail $selected.Tag
        }
    })

    # RBAC GG OU edit
    $UI.RBACGGOU.Add_TextChanged({
        $selected = $UI.RBACRoleList.SelectedItem
        if (-not $selected) { return }
        $selected.Tag.GlobalGroup.OU = $UI.RBACGGOU.Text
        $script:UnsavedChanges.RBAC = $true
    })

    # RBAC GG MemberOf add
    $UI.RBACGGAddMemberOf.Add_Click({
        $selected = $UI.RBACRoleList.SelectedItem
        if (-not $selected) { return }
        $currentRole = $selected.Tag
        $groupName = Show-ADGroupSearchDialog
        if ($groupName) {
            if (-not $currentRole.GlobalGroup.MemberOf) {
                $currentRole.GlobalGroup | Add-Member -NotePropertyName MemberOf -NotePropertyValue @() -Force
            }
            $currentRole.GlobalGroup.MemberOf = @($currentRole.GlobalGroup.MemberOf) + @($groupName)
            $script:UnsavedChanges.RBAC = $true
            Refresh-RBACRole $currentRole.Name
        }
    })

    # RBAC tier filters
    $UI.RBACFilterAll.Add_Click({ $script:RBACActiveFilter = $null;  Apply-RBACFilter })
    $UI.RBACFilterT0.Add_Click({  $script:RBACActiveFilter = "T0_"; Apply-RBACFilter })
    $UI.RBACFilterT1.Add_Click({  $script:RBACActiveFilter = "T1_"; Apply-RBACFilter })
    $UI.RBACFilterT2.Add_Click({  $script:RBACActiveFilter = "T2_"; Apply-RBACFilter })

    # Deploy module checkboxes: update order hint on toggle
    $UI.DeployHardening.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployHardening.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployTiering.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployTiering.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployRBAC.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployRBAC.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployPSO.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployPSO.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeploySilo.Add_Checked({ Update-DeployOrderHint })
    $UI.DeploySilo.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployGPO.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployGPO.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployJIT.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployJIT.Add_Unchecked({ Update-DeployOrderHint })

    # Deploy button -> confirm, save configs, then deploy selected modules in safe order
    $UI.BtnDeploy.Add_Click({
        $selected = @()
        if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
        if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
        if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
        if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
        if ($UI.DeploySilo.IsChecked)      { $selected += "Silo" }
        if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }
        if ($UI.DeployJIT.IsChecked)       { $selected += "JIT" }
        if ($selected.Count -eq 0) {
            Write-ConsoleUI "No modules selected for deployment." "Warning"
            return
        }
        $ordered = $script:DeploySafeOrder | Where-Object { $selected -contains $_ }
        $whatIfLabel = if ($UI.WhatIfToggle.IsChecked) { " (WhatIf)" } else { "" }
        $result = [System.Windows.MessageBox]::Show(
            "Deploy: $($ordered -join ' > ')$whatIfLabel?", "Confirm Deployment",
            [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($result -eq "Yes") {
            Save-AllConfigs
            Start-SelectedDeployments
        }
    })

    # Save button
    $UI.BtnSave.Add_Click({ Save-AllConfigs })

    # Deploy select all / deselect all
    $UI.BtnDeploySelectAll.Add_Click({
        $UI.DeployHardening.IsChecked = $true
        $UI.DeployTiering.IsChecked   = $true
        $UI.DeployRBAC.IsChecked      = $true
        $UI.DeployPSO.IsChecked       = $true
        $UI.DeploySilo.IsChecked      = $true
        $UI.DeployGPO.IsChecked       = $true
        $UI.DeployJIT.IsChecked       = $true
    })
    $UI.BtnDeployDeselectAll.Add_Click({
        $UI.DeployHardening.IsChecked = $false
        $UI.DeployTiering.IsChecked   = $false
        $UI.DeployRBAC.IsChecked      = $false
        $UI.DeployPSO.IsChecked       = $false
        $UI.DeploySilo.IsChecked      = $false
        $UI.DeployGPO.IsChecked       = $false
        $UI.DeployJIT.IsChecked       = $false
    })

    # Console clear
    $UI.BtnClearConsole.Add_Click({
        $UI.ConsoleOutput.Document.Blocks.Clear()
    })

    # RBAC restore ACL
    $UI.BtnRestoreACL.Add_Click({
        $projectRoot = Split-Path (Split-Path $script:ConfigPaths.RBAC -Parent) -Parent
        $logDir = $script:Configs.RBAC.Settings.LogDirectory
        if (-not [System.IO.Path]::IsPathRooted($logDir)) {
            $logDir = Join-Path $projectRoot $logDir
        }

        # Find run folders that contain at least one ACL backup
        $runFolders = @()
        if (Test-Path $logDir) {
            $runFolders = @(Get-ChildItem -Path $logDir -Directory -ErrorAction SilentlyContinue |
                Where-Object {
                    $bp = Join-Path $_.FullName "Backups"
                    (Test-Path $bp) -and (@(Get-ChildItem -Path $bp -Filter "ACL_*.xml" -ErrorAction SilentlyContinue).Count -gt 0)
                } | Sort-Object Name -Descending)
        }

        if ($runFolders.Count -eq 0) {
            [System.Windows.MessageBox]::Show(
                "No deployment backups found under:`n$logDir`n`nBackups are created automatically when AD permissions are deployed.",
                "No Backups",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null
            return
        }

        $bW = New-Object System.Windows.Window
        $bW.Title  = "Restore AD ACL — $($runFolders.Count) deployment run(s)"
        $bW.Width  = 680
        $bW.Height = 420
        $bW.WindowStartupLocation = "CenterOwner"
        $bW.Owner  = $script:Window
        $bW.Background = Get-WPFBrush "#F5F5F5"
        $bW.FontFamily = New-Object System.Windows.Media.FontFamily("Segoe UI")

        $sp = New-Object System.Windows.Controls.StackPanel
        $sp.Margin = [System.Windows.Thickness]::new(16)

        $hdr = New-Object System.Windows.Controls.TextBlock
        $hdr.Text = "Select a deployment run to roll back"
        $hdr.FontSize = 15
        $hdr.FontWeight = "SemiBold"
        $hdr.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        $sp.Children.Add($hdr) | Out-Null

        $sub = New-Object System.Windows.Controls.TextBlock
        $sub.Text = "All ACL backups from the selected run will be restored at once."
        $sub.FontSize = 11
        $sub.Foreground = Get-WPFBrush "#666666"
        $sub.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        $sp.Children.Add($sub) | Out-Null

        $warn = New-Object System.Windows.Controls.TextBlock
        $warn.Text = "Warning: each OU's current ACL will be fully replaced. Permissions added after the backup will be removed."
        $warn.FontSize = 11
        $warn.Foreground = Get-WPFBrush "#B7950B"
        $warn.TextWrapping = "Wrap"
        $warn.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)
        $sp.Children.Add($warn) | Out-Null

        $lb = New-Object System.Windows.Controls.ListBox
        $lb.Height = 200
        $lb.FontSize = 12
        $lb.BorderBrush = Get-WPFBrush "#D0D0D0"
        $lb.BorderThickness = [System.Windows.Thickness]::new(1)
        $lb.Padding = [System.Windows.Thickness]::new(4)

        foreach ($folder in $runFolders) {
            $files = @(Get-ChildItem -Path (Join-Path $folder.FullName "Backups") -Filter "ACL_*.xml" -ErrorAction SilentlyContinue)
            $ouLines = foreach ($f in $files) {
                try { (Import-Clixml -Path $f.FullName).OU } catch { $f.Name }
            }
            $it = New-Object System.Windows.Controls.ListBoxItem
            $it.Content = "$($folder.Name)   ($($files.Count) OU(s))"
            $it.Tag     = $folder.FullName
            $it.Padding = [System.Windows.Thickness]::new(10, 7, 10, 7)
            $it.ToolTip = "OUs:`n" + ($ouLines -join "`n")
            $lb.Items.Add($it) | Out-Null
        }
        $sp.Children.Add($lb) | Out-Null

        # Opt-in, and deliberately not ticked by default: restoring an ACL is reversible by
        # re-deploying, deleting a group is not. Only groups the selected run actually created are
        # eligible, matched on the SID recorded at creation -- see Remove-RBACDeployedGroup.
        $chkGroups = New-Object System.Windows.Controls.CheckBox
        $chkGroups.Content = "Also delete the groups this run created (irreversible)"
        $chkGroups.FontSize = 12
        $chkGroups.Foreground = Get-WPFBrush "#A93226"
        $chkGroups.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)
        $sp.Children.Add($chkGroups) | Out-Null

        $btnRestore = New-Object System.Windows.Controls.Button
        $btnRestore.Content = "Restore Run"
        $btnRestore.Width = 120
        $btnRestore.Height = 32
        $btnRestore.Margin = [System.Windows.Thickness]::new(0, 14, 0, 0)
        $btnRestore.Background = Get-WPFBrush "#D68910"
        $btnRestore.Foreground = "White"
        $btnRestore.BorderThickness = [System.Windows.Thickness]::new(0)
        $btnRestore.FontWeight = "SemiBold"
        $btnRestore.Cursor = "Hand"
        $btnRestore.HorizontalAlignment = "Right"

        $capturedLb        = $lb
        $capturedBW        = $bW
        $capturedChkGroups = $chkGroups
        $capturedModule    = Join-Path $projectRoot "Modules\RBAC\RBAC.psm1"

        $btnRestore.Add_Click({
            $selected = $capturedLb.SelectedItem
            if (-not $selected -or [string]::IsNullOrWhiteSpace($selected.Tag)) {
                [System.Windows.MessageBox]::Show("Select a deployment run first.", "No Selection",
                    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
                return
            }

            $runPath = [string]$selected.Tag
            $files = @(Get-ChildItem -Path (Join-Path $runPath "Backups") -Filter "ACL_*.xml" -ErrorAction SilentlyContinue)
            if ($files.Count -eq 0) {
                [System.Windows.MessageBox]::Show("No backup files found in this run folder.", "Error",
                    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
                return
            }

            $runName = [System.IO.Path]::GetFileName($runPath)
            $alsoGroups = [bool]$capturedChkGroups.IsChecked
            $groupWarning = if ($alsoGroups) {
                "`n`nThe groups this run created will also be DELETED. That cannot be undone, and any GPO security template referencing them by SID will be left with a dangling entry."
            } else { "" }
            $confirm = [System.Windows.MessageBox]::Show(
                "Restore $($files.Count) ACL backup(s) from run '$runName'?`n`nEach OU's current ACL will be fully replaced.$groupWarning",
                "Confirm Restore",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Warning
            )
            if ($confirm -ne "Yes") { return }

            try {
                Import-Module $capturedModule -Force
                $okCount   = 0
                $failMsgs  = @()
                foreach ($f in $files) {
                    try {
                        Restore-RBACAdPermission -BackupFile $f.FullName `
                            -Server $script:Connection.Server -Credential $script:Connection.Credential | Out-Null
                        $okCount++
                    } catch {
                        $failMsgs += "$($f.Name): $($_.Exception.Message)"
                    }
                }
                $summary = "$okCount of $($files.Count) ACL(s) restored."

                # Groups go after the ACLs, never before: dropping a group first would leave its
                # SID orphaned in the very ACEs the restore is about to remove anyway.
                if ($alsoGroups) {
                    try {
                        $g = Remove-RBACDeployedGroup -RunFolder $runPath `
                                -Server $script:Connection.Server -Credential $script:Connection.Credential
                        $summary += "`n$($g.Deleted) group(s) deleted, $($g.Skipped) skipped, $($g.Errors) error(s)."
                        if ($g.SkipReasons.Count -gt 0) {
                            $summary += "`n`nSkipped:`n" + (($g.SkipReasons | Select-Object -First 10) -join "`n")
                        }
                    }
                    catch {
                        $failMsgs += "group removal: $($_.Exception.Message)"
                    }
                }

                if ($failMsgs.Count -gt 0) {
                    $summary += "`n`nFailed:`n" + ($failMsgs -join "`n")
                    [System.Windows.MessageBox]::Show($summary, "Restore Completed with Errors",
                        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
                } else {
                    [System.Windows.MessageBox]::Show($summary, "Restore Complete",
                        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
                    $capturedBW.Close()
                }
            } catch {
                [System.Windows.MessageBox]::Show("Error: $($_.Exception.Message)", "Restore Failed",
                    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
            }
        }.GetNewClosure())

        $sp.Children.Add($btnRestore) | Out-Null
        $bW.Content = $sp
        $bW.ShowDialog() | Out-Null
    })

    # RBAC add role
    $UI.BtnAddRole.Add_Click({
        $newRole = Show-AddRoleDialog
        if ($newRole) {
            $script:Configs.RBAC.Roles = @($script:Configs.RBAC.Roles) + @($newRole)

            # Add GG to the matching DL_Tx root group Members
            $ggName = $newRole.GlobalGroup.Name
            $tier = if ($ggName -match '^GG_(T\d)_') { $Matches[1] } else { $null }
            if ($tier -and $script:Configs.RBAC.RootGroups) {
                $rootGroup = $script:Configs.RBAC.RootGroups | Where-Object { $_.Name -eq "DL_$tier" }
                if ($rootGroup) {
                    $currentMembers = @(if ($rootGroup.Members) { $rootGroup.Members } else { @() })
                    if ($ggName -notin $currentMembers) {
                        $rootGroup.Members = @($currentMembers) + @($ggName)
                    }
                }
            }

            Refresh-RBACRole $newRole.Name
            Write-ConsoleUI "Role '$($newRole.Name)' added." "Success"
        }
    })

    # RBAC delete role
    $UI.BtnDeleteRole.Add_Click({
        $selected = $UI.RBACRoleList.SelectedItem
        if (-not $selected -or -not $selected.Tag) {
            Write-ConsoleUI "Select a role to delete." "Warning"
            return
        }
        $roleName = $selected.Tag.Name
        $result = [System.Windows.MessageBox]::Show(
            "Delete role '$roleName'? This cannot be undone.", "Confirm Deletion",
            [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($result -eq "Yes") {
            # Remove GG from the matching DL_Tx root group Members
            $role = $script:Configs.RBAC.Roles | Where-Object { $_.Name -eq $roleName }
            if ($role -and $role.GlobalGroup) {
                $ggName = $role.GlobalGroup.Name
                $tier = if ($ggName -match '^GG_(T\d)_') { $Matches[1] } else { $null }
                if ($tier -and $script:Configs.RBAC.RootGroups) {
                    $rootGroup = $script:Configs.RBAC.RootGroups | Where-Object { $_.Name -eq "DL_$tier" }
                    if ($rootGroup -and $rootGroup.Members) {
                        $rootGroup.Members = @($rootGroup.Members | Where-Object { $_ -ne $ggName })
                    }
                }
            }

            $script:Configs.RBAC.Roles = @($script:Configs.RBAC.Roles | Where-Object { $_.Name -ne $roleName })
            $UI.RBACDLList.Children.Clear()
            Populate-RBACTab
            Apply-RBACFilter
            Write-ConsoleUI "Role '$roleName' deleted." "Success"
        }
    })
}
