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
    foreach ($module in @('Hardening', 'Tiering', 'RBAC')) {
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

    $script:UnsavedChanges = @{ Hardening = $false; Tiering = $false; RBAC = $false }
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

        $dlOUText = New-Object System.Windows.Controls.TextBlock
        $dlOUText.Text = $dl.OU
        $dlOUText.FontSize = 10
        $dlOUText.Foreground = Get-WPFBrush "#999"
        $dlOUText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        [void]$dlStack.Children.Add($dlOUText)

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
    $navButtons = @($UI.NavDashboard, $UI.NavHardening, $UI.NavTiering, $UI.NavRBAC)
    $activeStyle = $script:Window.FindResource("NavBtnActive")
    $normalStyle = $script:Window.FindResource("NavBtn")
    for ($i = 0; $i -lt $navButtons.Count; $i++) {
        $navButtons[$i].Style = if ($i -eq $index) { $activeStyle } else { $normalStyle }
    }
    # Search bar only visible on Hardening tab
    $UI.SearchBarPanel.Visibility = if ($index -eq 1) { "Visible" } else { "Collapsed" }
}

# ============================================================================
# Search
# ============================================================================

function Invoke-Search([string]$query) {
    if ([string]::IsNullOrWhiteSpace($query)) {
        $UI.SearchPlaceholder.Visibility = "Visible"
        foreach ($child in $UI.HardeningTaskList.Children) { $child.Visibility = "Visible" }
        return
    }

    $UI.SearchPlaceholder.Visibility = "Collapsed"
    $q = $query.ToLower()

    for ($i = 0; $i -lt $UI.HardeningTaskList.Children.Count; $i++) {
        $task = $script:Configs.Hardening.Tasks[$i]
        $match = $task.Name.ToLower().Contains($q) -or $task.Description.ToLower().Contains($q)
        $UI.HardeningTaskList.Children[$i].Visibility = if ($match) { "Visible" } else { "Collapsed" }
    }
}

# ============================================================================
# Deploy
# ============================================================================

function Start-Deployment([string]$module) {
    $whatIf = [bool]$UI.WhatIfToggle.IsChecked
    $whatIfLabel = if ($whatIf) { " (WhatIf)" } else { "" }
    Write-ConsoleUI "Starting $module deployment$whatIfLabel..." "Info"

    $scriptPath = $null
    switch ($module) {
        "Hardening" { $scriptPath = $script:ScriptPaths.Hardening }
        "Tiering"   { $scriptPath = $script:ScriptPaths.Tiering }
        "RBAC"      { $scriptPath = $script:ScriptPaths.RBAC }
        "All" {
            Start-Deployment "Hardening"
            Start-Deployment "Tiering"
            Start-Deployment "RBAC"
            return
        }
    }

    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-ConsoleUI "Script not found: $scriptPath" "Error"
        return
    }

    $configPath = $script:ConfigPaths[$module]
    $cmd = "& '$scriptPath' -ConfigPath '$configPath'"
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
# Initialize & Register Events
# ============================================================================

function Initialize-GUI {
    Load-AllConfigs
    Write-ConsoleUI "Configurations loaded." "Success"

    Populate-Dashboard
    if ($script:Configs.Hardening) { Populate-HardeningTab }
    if ($script:Configs.Tiering)   { Populate-TieringTab }
    if ($script:Configs.RBAC)      { Populate-RBACTab }

    Write-ConsoleUI "GUI initialized. Ready." "Info"
}

function Register-GUIEvents {
    # Navigation
    $UI.NavDashboard.Add_Click({ Set-ActiveTab 0 })
    $UI.NavHardening.Add_Click({ Set-ActiveTab 1 })
    $UI.NavTiering.Add_Click({ Set-ActiveTab 2 })
    $UI.NavRBAC.Add_Click({ Set-ActiveTab 3 })

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

    # Deploy button -> open context menu
    $UI.BtnDeploy.Add_Click({ $UI.BtnDeploy.ContextMenu.IsOpen = $true })
    $deployMenu = $UI.BtnDeploy.ContextMenu
    $deployMenu.Items[0].Add_Click({ Save-AllConfigs; Start-Deployment "All" })       # Deploy All
    $deployMenu.Items[2].Add_Click({ Save-AllConfigs; Start-Deployment "Hardening" }) # Deploy Hardening
    $deployMenu.Items[3].Add_Click({ Save-AllConfigs; Start-Deployment "Tiering" })   # Deploy Tiering
    $deployMenu.Items[4].Add_Click({ Save-AllConfigs; Start-Deployment "RBAC" })      # Deploy RBAC

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
            $script:Configs.RBAC.Roles = @($script:Configs.RBAC.Roles | Where-Object { $_.Name -ne $roleName })
            $UI.RBACDLList.Children.Clear()
            Populate-RBACTab
            Write-ConsoleUI "Role '$roleName' deleted." "Success"
        }
    })
}
