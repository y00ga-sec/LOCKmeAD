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
    foreach ($module in @('Hardening', 'GPO', 'Tiering', 'RBAC', 'PSO')) {
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
                $text = $control.Text
                if ($text -match '^\d+$') { [int]$text } else { $text }
            } else { $control.Text }
            $script:Configs.Hardening.Tasks[$taskIdx].Parameters.$paramName = $value
        }
        $script:Configs.Hardening | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPaths.Hardening -Encoding UTF8
    }

    # GPO: read toggle states, link targets, and filtering OU back into config
    if ($script:Configs.GPO) {
        for ($i = 0; $i -lt $script:GPOToggles.Count; $i++) {
            $script:Configs.GPO.GPOs[$i].Enabled = [bool]$script:GPOToggles[$i].IsChecked
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

    $script:UnsavedChanges = @{ Hardening = $false; GPO = $false; Tiering = $false; RBAC = $false; PSO = $false }
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
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $UI.DashEnvDC.Text        = "Current DC: $($env:COMPUTERNAME)"
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
}

function Populate-HardeningTab {
    $UI.HardeningTaskList.Children.Clear()
    $script:HardeningToggles = @()
    $script:HardeningParamControls = @{}

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

        [void]$headerDock.Children.Add($toggle)
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

        $card.Child = $outerStack
        [void]$UI.HardeningTaskList.Children.Add($card)
    }
}

function Update-GPOFilteringOUWarning {
    $text = $UI.GPOFilteringGroupsOU.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        $UI.GPOFilteringOUWarning.Visibility = "Collapsed"
    }
    elseif ($text -notmatch 'OU=GroupsT0,OU=Admin') {
        $UI.GPOFilteringOUWarning.Text = "Warning: This OU is not within OU=GroupsT0,OU=Admin. Filtering groups will not be deployed."
        $UI.GPOFilteringOUWarning.Foreground = Get-WPFBrush "#D35400"
        $UI.GPOFilteringOUWarning.Visibility = "Visible"
    }
    else {
        $UI.GPOFilteringOUWarning.Text = "OK: OU is within OU=GroupsT0,OU=Admin."
        $UI.GPOFilteringOUWarning.Foreground = Get-WPFBrush "#1E8449"
        $UI.GPOFilteringOUWarning.Visibility = "Visible"
    }
}

function Populate-GPOTab {
    $UI.GPOTaskList.Children.Clear()
    $script:GPOToggles = @()
    $script:GPOLinkControls = @{}

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
        $uraCount = if ($gpo.UserRightsAssignments) { $gpo.UserRightsAssignments.Count } else { 0 }

        if ($regCount -gt 0) {
            $regBadge = New-Object System.Windows.Controls.TextBlock
            $regBadge.Text = "$regCount reg"
            $regBadge.FontSize = 10
            $regBadge.Foreground = Get-WPFBrush "#1E8449"
            $regBadge.Background = Get-WPFBrush "#E8F8F0"
            $regBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
            $regBadge.Margin = [System.Windows.Thickness]::new(4, 0, 0, 0)
            [void]$badgePanel.Children.Add($regBadge)
        }
        if ($uraCount -gt 0) {
            $uraBadge = New-Object System.Windows.Controls.TextBlock
            $uraBadge.Text = "$uraCount URA"
            $uraBadge.FontSize = 10
            $uraBadge.Foreground = Get-WPFBrush "#6C3483"
            $uraBadge.Background = Get-WPFBrush "#F3E8FC"
            $uraBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
            $uraBadge.Margin = [System.Windows.Thickness]::new(4, 0, 0, 0)
            [void]$badgePanel.Children.Add($uraBadge)
        }

        $textStack = New-Object System.Windows.Controls.StackPanel
        $textStack.Margin = [System.Windows.Thickness]::new(14, 0, 10, 0)

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $gpo.Name
        $nameBlock.FontSize = 14
        $nameBlock.FontWeight = "SemiBold"

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $gpo.Description
        $descBlock.FontSize = 12
        $descBlock.Foreground = Get-WPFBrush "#666666"
        $descBlock.TextWrapping = "Wrap"

        [void]$textStack.Children.Add($nameBlock)
        [void]$textStack.Children.Add($descBlock)

        [void]$headerDock.Children.Add($toggle)
        [void]$headerDock.Children.Add($badgePanel)
        [void]$headerDock.Children.Add($textStack)
        [void]$outerStack.Children.Add($headerDock)

        # Registry Settings expander (read-only, only if registry settings exist)
        if ($regCount -gt 0) {
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

        # User Rights Assignments expander (read-only, only if URA exist)
        if ($uraCount -gt 0) {
            $uraExpander = New-Object System.Windows.Controls.Expander
            $uraExpander.Header = "User Rights Assignments"
            $uraExpander.Margin = [System.Windows.Thickness]::new(58, 8, 0, 0)
            $uraExpander.FontSize = 12

            $uraStack = New-Object System.Windows.Controls.StackPanel
            $uraStack.Margin = [System.Windows.Thickness]::new(0, 6, 0, 0)

            foreach ($assignment in $gpo.UserRightsAssignments) {
                $uraRow = New-Object System.Windows.Controls.DockPanel
                $uraRow.Margin = [System.Windows.Thickness]::new(0, 2, 0, 2)

                $rightLabel = New-Object System.Windows.Controls.TextBlock
                $rightLabel.FontSize = 11
                $rightLabel.Foreground = Get-WPFBrush "#6C3483"
                $rightLabel.FontWeight = "SemiBold"
                $rightLabel.MinWidth = 220
                $rightLabel.ToolTip = $assignment.Right
                if ($assignment.Description) {
                    $rightLabel.Text = $assignment.Description
                } else {
                    $rightLabel.Text = $assignment.Right
                }
                [System.Windows.Controls.DockPanel]::SetDock($rightLabel, "Left")

                $groupsLabel = New-Object System.Windows.Controls.TextBlock
                $groupsLabel.Text = ($assignment.Groups -join ", ")
                $groupsLabel.FontSize = 11
                $groupsLabel.Foreground = Get-WPFBrush "#555"
                $groupsLabel.TextWrapping = "Wrap"

                [void]$uraRow.Children.Add($rightLabel)
                [void]$uraRow.Children.Add($groupsLabel)
                [void]$uraStack.Children.Add($uraRow)
            }

            $uraExpander.Content = $uraStack
            [void]$outerStack.Children.Add($uraExpander)
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

        $appliesToHint = New-Object System.Windows.Controls.TextBlock
        $appliesToHint.Text = "One group or user name per line (e.g. GG_T0_PKI_Operators)"
        $appliesToHint.FontSize = 10
        $appliesToHint.Foreground = Get-WPFBrush "#999"
        $appliesToHint.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
        [void]$appliesToStack.Children.Add($appliesToHint)

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

function Show-RBACRoleDetail($role) {
    $UI.RBACDetailTitle.Text = $role.Name
    $UI.RBACDetailDesc.Text = $role.Description
    $UI.RBACGGPanel.Visibility = "Visible"
    $UI.RBACDLHeader.Visibility = "Visible"
    $UI.RBACGGName.Text = $role.GlobalGroup.Name
    $UI.RBACGGDesc.Text = $role.GlobalGroup.Description
    $UI.RBACGGOU.Text   = $role.GlobalGroup.OU

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
        $dlOUText = New-Object System.Windows.Controls.TextBlock
        $dlOUText.Text = $dl.OU
        $dlOUText.FontSize = 10
        $dlOUText.Foreground = Get-WPFBrush "#999"
        $dlOUText.TextWrapping = "Wrap"
        [void]$dlOUPanel.Children.Add($dlOUText)
        [void]$dlStack.Children.Add($dlOUPanel)

        # Permissions
        for ($pIdx = 0; $pIdx -lt $dl.Permissions.Count; $pIdx++) {
            $perm = $dl.Permissions[$pIdx]

            $permBorder = New-Object System.Windows.Controls.Border
            $permBorder.Background = Get-WPFBrush "#FFFFFF"
            $permBorder.CornerRadius = [System.Windows.CornerRadius]::new(4)
            $permBorder.Padding = [System.Windows.Thickness]::new(10, 6, 10, 6)
            $permBorder.Margin = [System.Windows.Thickness]::new(0, 0, 0, 4)
            $permBorder.BorderBrush = Get-WPFBrush "#EEE"
            $permBorder.BorderThickness = [System.Windows.Thickness]::new(1)

            $permDock = New-Object System.Windows.Controls.DockPanel

            # Delete perm button
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

            # Edit perm button
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

            # Type badge
            $typeBadge = New-Object System.Windows.Controls.TextBlock
            $typeBadge.Text = $perm.Type
            $typeBadge.FontSize = 10
            $typeBadge.FontWeight = "Bold"
            $typeBadge.Padding = [System.Windows.Thickness]::new(6, 2, 6, 2)
            $typeBadge.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
            $typeBadge.VerticalAlignment = "Center"
            switch ($perm.Type) {
                "NTFS" { $typeBadge.Foreground = Get-WPFBrush "#1E8449"; $typeBadge.Background = Get-WPFBrush "#E8F8F0" }
                "AD"   { $typeBadge.Foreground = Get-WPFBrush "#2E86C1"; $typeBadge.Background = Get-WPFBrush "#E8F2FC" }
                "ADCS" { $typeBadge.Foreground = Get-WPFBrush "#A93226"; $typeBadge.Background = Get-WPFBrush "#FCE8E8" }
            }
            [System.Windows.Controls.DockPanel]::SetDock($typeBadge, "Left")

            $permInfo = New-Object System.Windows.Controls.TextBlock
            $permInfo.FontSize = 11
            $permInfo.VerticalAlignment = "Center"
            $permInfo.TextWrapping = "Wrap"
            switch ($perm.Type) {
                "NTFS" { $permInfo.Text = "$($perm.Rights) on $($perm.Path)" }
                "AD"   { $permInfo.Text = "$($perm.ADRights) on $($perm.TargetOU)" }
                "ADCS" { $permInfo.Text = "$($perm.Right) on $($perm.CAName) ($($perm.CAHostname))" }
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

            [void]$permDock.Children.Add($delPermBtn)
            [void]$permDock.Children.Add($editPermBtn)
            [void]$permDock.Children.Add($typeBadge)
            [void]$permDock.Children.Add($permInfo)
            $permBorder.Child = $permDock
            [void]$dlStack.Children.Add($permBorder)
        }

        # "+ Add Permission" button per DL group
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

        $dlCard.Child = $dlStack
        [void]$UI.RBACDLList.Children.Add($dlCard)
    }
}

# ============================================================================
# Navigation
# ============================================================================

function Set-ActiveTab([int]$index) {
    $UI.MainTabs.SelectedIndex = $index
    $navButtons = @($UI.NavDashboard, $UI.NavHardening, $UI.NavGPO, $UI.NavTiering, $UI.NavRBAC, $UI.NavPSO)
    $activeStyle = $script:Window.FindResource("NavBtnActive")
    $normalStyle = $script:Window.FindResource("NavBtn")
    for ($i = 0; $i -lt $navButtons.Count; $i++) {
        $navButtons[$i].Style = if ($i -eq $index) { $activeStyle } else { $normalStyle }
    }
    # Search bar visible on Hardening and GPO tabs
    $UI.SearchBarPanel.Visibility = if ($index -in @(1, 2, 5)) { "Visible" } else { "Collapsed" }
    if ($index -eq 1) { $UI.SearchPlaceholder.Text = "Search hardening tasks..." }
    elseif ($index -eq 2) { $UI.SearchPlaceholder.Text = "Search GPO templates..." }
    elseif ($index -eq 5) { $UI.SearchPlaceholder.Text = "Search password policies..." }
    # Clear search when switching tabs
    if ($index -in @(1, 2, 5)) { $UI.SearchBox.Text = "" }
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
    }
}

# ============================================================================
# Deploy
# ============================================================================

# Canonical safe execution order
$script:DeploySafeOrder = @("Hardening", "Tiering", "RBAC", "PSO", "GPO")

function Start-SingleDeployment([string]$module) {
    $whatIf = [bool]$UI.WhatIfToggle.IsChecked

    $scriptPath = $script:ScriptPaths[$module]
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-ConsoleUI "Script not found: $scriptPath" "Error"
        return
    }

    $configPath = $script:ConfigPaths[$module]
    $cmd = "& '$scriptPath' -ConfigPath '$configPath' -NoConfirm"
    if ($whatIf) { $cmd += " -WhatIf" }

    try {
        $output = Invoke-Expression $cmd 2>&1
        foreach ($line in $output) {
            $lvl = "Info"
            $text = $line.ToString()
            if ($text -match '\[Success\]') { $lvl = "Success" }
            elseif ($text -match '\[Warning\]') { $lvl = "Warning" }
            elseif ($text -match '\[Error\]' -or $line -is [System.Management.Automation.ErrorRecord]) { $lvl = "Error" }
            Write-ConsoleUI $text $lvl
        }
        Write-ConsoleUI "$module deployment completed." "Success"
    } catch {
        Write-ConsoleUI "$module deployment failed: $_" "Error"
    }
}

function Start-SelectedDeployments {
    $selected = @()
    if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
    if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
    if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
    if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
    if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }

    if ($selected.Count -eq 0) {
        Write-ConsoleUI "No modules selected for deployment." "Warning"
        return
    }

    # Enforce safe order
    $ordered = $script:DeploySafeOrder | Where-Object { $selected -contains $_ }

    $whatIf = [bool]$UI.WhatIfToggle.IsChecked
    $whatIfLabel = if ($whatIf) { " (WhatIf)" } else { "" }
    Write-ConsoleUI "Deploying: $($ordered -join ' > ')$whatIfLabel" "Info"

    foreach ($module in $ordered) {
        Write-ConsoleUI "=== $module ===" "Info"
        Start-SingleDeployment $module
    }
    Write-ConsoleUI "All selected deployments completed." "Success"
}

function Update-DeployOrderHint {
    $selected = @()
    if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
    if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
    if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
    if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
    if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }

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

function Get-TierOU([string]$tier) {
    $ggBase = $script:Configs.RBAC.Settings.DefaultOU.Global
    $dlBase = $script:Configs.RBAC.Settings.DefaultOU.DomainLocal
    return @{
        GG = $ggBase -replace 'GroupsT\d', "Groups$tier"
        DL = $dlBase -replace 'GroupsT\d', "Groups$tier"
    }
}

function Refresh-RBACRole($roleName) {
    Populate-RBACTab
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

            <Expander Header="Advanced GUID Options" Margin="0,14,0,0" FontSize="12" IsExpanded="False">
                <StackPanel Margin="0,8,0,0">
                    <TextBlock Text="ObjectType (GUID)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
                    <TextBlock Text="Targets a specific property, extended right, or child object class. Leave default for broad permissions (e.g. GenericAll)." FontSize="10" Foreground="#999" TextWrapping="Wrap" Margin="0,0,0,6"/>
                    <TextBox Name="ADObjectType" FontSize="13" Padding="8,6" BorderBrush="#DDD"
                             Text="00000000-0000-0000-0000-000000000000"/>
                    <TextBlock Text="InheritedObjectType (GUID)" FontSize="12" Foreground="#555" Margin="0,12,0,4"/>
                    <TextBlock Text="Restricts inheritance to a specific child object type. Leave default to apply to all child objects." FontSize="10" Foreground="#999" TextWrapping="Wrap" Margin="0,0,0,6"/>
                    <TextBox Name="ADInheritedObjectType" FontSize="13" Padding="8,6" BorderBrush="#DDD"
                             Text="00000000-0000-0000-0000-000000000000"/>
                    <TextBlock Text="See Config/AD-GUIDs-Reference.md for common GUIDs." FontSize="10" Foreground="#0078D4" Margin="0,8,0,0"/>
                </StackPanel>
            </Expander>
        </StackPanel>

        <!-- NTFS fields -->
        <StackPanel Name="PanelNTFS" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Text="Path (UNC or local)" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <TextBox Name="NTFSPath" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
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
        </StackPanel>

        <!-- ADCS fields -->
        <StackPanel Name="PanelADCS" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Text="CA Name" FontSize="12" Foreground="#555" Margin="0,0,0,4"/>
            <TextBox Name="ADCSCAName" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
            <TextBlock Text="CA Hostname (FQDN)" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <TextBox Name="ADCSCAHostname" FontSize="13" Padding="8,6" BorderBrush="#DDD"/>
            <TextBlock Text="Right" FontSize="12" Foreground="#555" Margin="0,10,0,4"/>
            <ComboBox Name="ADCSRight" FontSize="13" Padding="6,4" SelectedIndex="0">
                <ComboBoxItem Content="ManageCA"/>
                <ComboBoxItem Content="ManageCertificates"/>
                <ComboBoxItem Content="Enroll"/>
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

    # Type switching
    $cmbType.Add_SelectionChanged({
        $sel = $cmbType.SelectedItem.Content
        $panelAD.Visibility   = if ($sel -eq "AD")   { "Visible" } else { "Collapsed" }
        $panelNTFS.Visibility = if ($sel -eq "NTFS") { "Visible" } else { "Collapsed" }
        $panelADCS.Visibility = if ($sel -eq "ADCS") { "Visible" } else { "Collapsed" }
    }.GetNewClosure())

    # Pre-fill if editing
    if ($existingPerm) {
        switch ($existingPerm.Type) {
            "AD" {
                $cmbType.SelectedIndex = 0
                $dlg.FindName("ADTargetOU").Text = $existingPerm.TargetOU
                $dlg.FindName("ADADRights").Text = $existingPerm.ADRights
                $dlg.FindName("ADObjectType").Text = $existingPerm.ObjectType
                $dlg.FindName("ADInheritedObjectType").Text = $existingPerm.InheritedObjectType
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

    Populate-Dashboard
    if ($script:Configs.Hardening) { Populate-HardeningTab }
    if ($script:Configs.GPO)       { Populate-GPOTab }
    if ($script:Configs.Tiering)   { Populate-TieringTab }
    if ($script:Configs.RBAC)      { Populate-RBACTab }
    if ($script:Configs.PSO)       { Populate-PSOTab }

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

    # RBAC tier filters
    $UI.RBACFilterAll.Add_Click({
        foreach ($item in $UI.RBACRoleList.Items) { $item.Visibility = "Visible" }
    })
    $UI.RBACFilterT0.Add_Click({
        foreach ($item in $UI.RBACRoleList.Items) {
            $item.Visibility = if ($item.Tag.Name -like "T0_*") { "Visible" } else { "Collapsed" }
        }
    })
    $UI.RBACFilterT1.Add_Click({
        foreach ($item in $UI.RBACRoleList.Items) {
            $item.Visibility = if ($item.Tag.Name -like "T1_*") { "Visible" } else { "Collapsed" }
        }
    })
    $UI.RBACFilterT2.Add_Click({
        foreach ($item in $UI.RBACRoleList.Items) {
            $item.Visibility = if ($item.Tag.Name -like "T2_*") { "Visible" } else { "Collapsed" }
        }
    })

    # Deploy module checkboxes: update order hint on toggle
    $UI.DeployHardening.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployHardening.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployTiering.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployTiering.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployRBAC.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployRBAC.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployPSO.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployPSO.Add_Unchecked({ Update-DeployOrderHint })
    $UI.DeployGPO.Add_Checked({ Update-DeployOrderHint })
    $UI.DeployGPO.Add_Unchecked({ Update-DeployOrderHint })

    # Deploy button -> confirm, save configs, then deploy selected modules in safe order
    $UI.BtnDeploy.Add_Click({
        $selected = @()
        if ($UI.DeployHardening.IsChecked) { $selected += "Hardening" }
        if ($UI.DeployTiering.IsChecked)   { $selected += "Tiering" }
        if ($UI.DeployRBAC.IsChecked)      { $selected += "RBAC" }
        if ($UI.DeployPSO.IsChecked)       { $selected += "PSO" }
        if ($UI.DeployGPO.IsChecked)       { $selected += "GPO" }
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

    # Console clear
    $UI.BtnClearConsole.Add_Click({
        $UI.ConsoleOutput.Document.Blocks.Clear()
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
            Write-ConsoleUI "Role '$roleName' deleted." "Success"
        }
    })
}
