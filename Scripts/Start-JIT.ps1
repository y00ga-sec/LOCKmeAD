#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LOCKmeAD - JIT Access Manager.
.DESCRIPTION
    Operational WPF GUI tool for Tier 0 administrators to temporarily add accounts
    to Active Directory groups using PAM time-limited membership (TTL).
    Requires the Privileged Access Management (PAM) optional feature to be enabled.
.EXAMPLE
    .\Start-JIT.ps1
#>

$ErrorActionPreference = "Stop"

# ============================================================================
# WPF Assemblies
# ============================================================================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# ============================================================================
# Script-scoped state
# ============================================================================

$script:LogFilePath = $null
$script:EnvInfo = $null
$script:LogDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) "Logs"

# ============================================================================
# Functions
# ============================================================================

function Write-JITLog {
    <#
    .SYNOPSIS
        Writes a message to the console and to a log file.
    .PARAMETER Message
        The message to write.
    .PARAMETER Level
        The message level: Info, Success, Warning, Error.
    .PARAMETER LogDirectory
        The directory where the log file is written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info",

        [string]$LogDirectory
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }

    # Write to log file
    if ($LogDirectory) {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        if (-not $script:LogFilePath) {
            $logFileName = "JIT_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            $script:LogFilePath = Join-Path $LogDirectory $logFileName
        }
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
    }
}

function Get-JITEnvironmentInfo {
    <#
    .SYNOPSIS
        Retrieves Active Directory environment information including PAM feature status.
    .OUTPUTS
        PSCustomObject with environment information.
    #>
    [CmdletBinding()]
    param()

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $currentDC = $env:COMPUTERNAME
        $pdcEmulator = $domain.PDCEmulator
        $isPDC = $pdcEmulator -like "$currentDC.*"

        $pamEnabled = $false
        try {
            $pamFeature = Get-ADOptionalFeature -Filter { Name -eq 'Privileged Access Management Feature' }
            $pamEnabled = $pamFeature.EnabledScopes.Count -gt 0
        }
        catch {
            $pamEnabled = $false
        }

        return [PSCustomObject]@{
            CurrentDC   = $currentDC
            IsPDC       = $isPDC
            PDCEmulator = $pdcEmulator
            DomainName  = $domain.DNSRoot
            DomainDN    = $domain.DistinguishedName
            ForestName  = $forest.Name
            PamEnabled  = $pamEnabled
        }
    }
    catch {
        throw "Unable to retrieve Active Directory information: $_"
    }
}

function Convert-SecondsToReadable {
    <#
    .SYNOPSIS
        Converts seconds to a human-readable "Xd Xh Xm Xs" format.
    .PARAMETER Seconds
        The number of seconds to convert.
    .OUTPUTS
        String in the format "Xd Xh Xm Xs".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Seconds
    )

    if ($Seconds -le 0) { return "Expired" }

    $days    = [math]::Floor($Seconds / 86400)
    $hours   = [math]::Floor(($Seconds % 86400) / 3600)
    $minutes = [math]::Floor(($Seconds % 3600) / 60)
    $secs    = $Seconds % 60

    $parts = @()
    if ($days -gt 0)    { $parts += "${days}d" }
    if ($hours -gt 0)   { $parts += "${hours}h" }
    if ($minutes -gt 0) { $parts += "${minutes}m" }
    if ($secs -gt 0 -or $parts.Count -eq 0) { $parts += "${secs}s" }

    return ($parts -join " ")
}

function Get-JITGroupTTLMembers {
    <#
    .SYNOPSIS
        Retrieves TTL-based (time-limited) members of an AD group.
    .PARAMETER GroupName
        The name of the AD group.
    .PARAMETER Server
        Target DC for the AD query.
    .OUTPUTS
        Array of PSCustomObjects with UserName, SamAccountName, TTL, TTLFormatted, ExpiresAt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [string]$Server
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    $group = Get-ADGroup -Identity $GroupName -Property member -ShowMemberTimeToLive @serverParam
    $members = $group.member

    $results = @()
    foreach ($memberDN in $members) {
        $ttlSeconds = 0
        $hasTTL = $false

        if ($memberDN -match '<TTL=(\d+)>,') {
            $ttlSeconds = [int]$Matches[1]
            $hasTTL = $true
            # Strip the TTL prefix to get the real DN
            $cleanDN = $memberDN -replace '<TTL=\d+>,', ''
        }
        else {
            $cleanDN = $memberDN
        }

        if (-not $hasTTL) { continue }

        try {
            $adUser = Get-ADUser -Identity $cleanDN @serverParam -ErrorAction Stop
            $results += [PSCustomObject]@{
                UserName       = $adUser.Name
                SamAccountName = $adUser.SamAccountName
                TTL            = $ttlSeconds
                TTLFormatted   = Convert-SecondsToReadable -Seconds $ttlSeconds
                ExpiresAt      = (Get-Date).AddSeconds($ttlSeconds)
            }
        }
        catch {
            # Could be a computer or other object, try generic approach
            try {
                $adObj = Get-ADObject -Identity $cleanDN -Properties SamAccountName, Name @serverParam -ErrorAction Stop
                $results += [PSCustomObject]@{
                    UserName       = $adObj.Name
                    SamAccountName = $adObj.SamAccountName
                    TTL            = $ttlSeconds
                    TTLFormatted   = Convert-SecondsToReadable -Seconds $ttlSeconds
                    ExpiresAt      = (Get-Date).AddSeconds($ttlSeconds)
                }
            }
            catch {
                # Last resort: extract CN from DN
                $cn = ($cleanDN -split ',')[0] -replace '^CN=', ''
                $results += [PSCustomObject]@{
                    UserName       = $cn
                    SamAccountName = $cn
                    TTL            = $ttlSeconds
                    TTLFormatted   = Convert-SecondsToReadable -Seconds $ttlSeconds
                    ExpiresAt      = (Get-Date).AddSeconds($ttlSeconds)
                }
            }
        }
    }

    return $results
}

function Add-JITGroupMember {
    <#
    .SYNOPSIS
        Adds a user to an AD group with a time-limited (TTL) membership.
    .PARAMETER GroupName
        The name of the AD group.
    .PARAMETER UserName
        The SAM account name of the user.
    .PARAMETER TimeSpan
        The duration of the membership as a TimeSpan object.
    .PARAMETER Server
        Target DC for the AD operation.
    .PARAMETER LogDirectory
        Log directory.
    .OUTPUTS
        String message indicating success or failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [TimeSpan]$TimeSpan,

        [string]$Server,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    try {
        Add-ADGroupMember -Identity $GroupName -Members $UserName -MemberTimeToLive $TimeSpan @serverParam
        $formatted = Convert-SecondsToReadable -Seconds ([int]$TimeSpan.TotalSeconds)
        $message = "Added '$UserName' to '$GroupName' with TTL $formatted."
        Write-JITLog -Message $message -Level Success -LogDirectory $LogDirectory
        return $message
    }
    catch {
        $message = "Error adding '$UserName' to '$GroupName': $_"
        Write-JITLog -Message $message -Level Error -LogDirectory $LogDirectory
        return $message
    }
}

function Remove-JITGroupMember {
    <#
    .SYNOPSIS
        Removes a user from an AD group.
    .PARAMETER GroupName
        The name of the AD group.
    .PARAMETER UserName
        The SAM account name of the user.
    .PARAMETER Server
        Target DC for the AD operation.
    .PARAMETER LogDirectory
        Log directory.
    .OUTPUTS
        String message indicating success or failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$UserName,

        [string]$Server,
        [string]$LogDirectory
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    try {
        Remove-ADGroupMember -Identity $GroupName -Members $UserName -Confirm:$false @serverParam
        $message = "Removed '$UserName' from '$GroupName'."
        Write-JITLog -Message $message -Level Success -LogDirectory $LogDirectory
        return $message
    }
    catch {
        $message = "Error removing '$UserName' from '$GroupName': $_"
        Write-JITLog -Message $message -Level Error -LogDirectory $LogDirectory
        return $message
    }
}

# ============================================================================
# Search Dialog
# ============================================================================

function Show-SearchDialog {
    <#
    .SYNOPSIS
        Displays a WPF popup dialog for searching AD users or groups.
    .PARAMETER Title
        The window title.
    .PARAMETER SearchType
        Either "User" or "Group".
    .PARAMETER Owner
        The parent window.
    .PARAMETER Server
        Target DC for AD queries.
    .OUTPUTS
        The selected item's SamAccountName, or $null if cancelled.
    #>
    [CmdletBinding()]
    param(
        [string]$Title = "Search",
        [ValidateSet("User", "Group")]
        [string]$SearchType = "User",
        [System.Windows.Window]$Owner,
        [string]$Server
    )

    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    $searchXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Title" Width="420" Height="380" WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize" Background="#F5F5F5" FontFamily="Segoe UI">
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
                   FontSize="11" Foreground="#888888" Text="Type a search term and click Search. Double-click to select."/>
    </Grid>
</Window>
"@

    [xml]$searchDoc = $searchXaml
    $searchReader = [System.Xml.XmlNodeReader]::new($searchDoc)
    $searchWindow = [System.Windows.Markup.XamlReader]::Load($searchReader)

    if ($Owner) {
        $searchWindow.Owner = $Owner
    }

    $searchBox    = $searchWindow.FindName("SearchBox")
    $searchBtn    = $searchWindow.FindName("SearchBtn")
    $resultList   = $searchWindow.FindName("ResultList")
    $statusText   = $searchWindow.FindName("StatusText")

    $script:SearchDialogResult = $null

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
            if ($SearchType -eq "User") {
                $filter = "Name -like '*$val*'"
                $results = Get-ADUser -Filter $filter -Properties DisplayName @serverParam -ErrorAction Stop |
                    Select-Object -First 50
                foreach ($r in $results) {
                    $display = "$($r.SamAccountName)  -  $($r.Name)"
                    if ($r.DisplayName) { $display = "$($r.SamAccountName)  -  $($r.DisplayName)" }
                    $item = [System.Windows.Controls.ListBoxItem]::new()
                    $item.Content = $display
                    $item.Tag = $r.SamAccountName
                    $resultList.Items.Add($item) | Out-Null
                }
            }
            else {
                $filter = "Name -like '*$val*'"
                $results = Get-ADGroup -Filter $filter @serverParam -ErrorAction Stop |
                    Select-Object -First 50
                foreach ($r in $results) {
                    $display = "$($r.SamAccountName)  -  $($r.Name)"
                    $item = [System.Windows.Controls.ListBoxItem]::new()
                    $item.Content = $display
                    $item.Tag = $r.SamAccountName
                    $resultList.Items.Add($item) | Out-Null
                }
            }

            $count = $resultList.Items.Count
            if ($count -eq 0) {
                $statusText.Text = "No results found."
            }
            elseif ($count -ge 50) {
                $statusText.Text = "$count results (showing first 50). Refine your search."
            }
            else {
                $statusText.Text = "$count result(s) found. Double-click to select."
            }
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
        param($sender, $e)
        $selected = $resultList.SelectedItem
        if ($selected -and $selected.Tag) {
            $script:SearchDialogResult = $selected.Tag
            $searchWindow.DialogResult = $true
            $searchWindow.Close()
        }
    })

    $dialogResult = $searchWindow.ShowDialog()
    if ($dialogResult -eq $true) {
        return $script:SearchDialogResult
    }
    return $null
}

# ============================================================================
# WPF GUI Definition
# ============================================================================

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="LOCKmeAD - JIT Access Manager" Width="950" Height="700"
        WindowStartupLocation="CenterScreen" Background="#F5F5F5"
        FontFamily="Segoe UI" MinWidth="900" MinHeight="600">

    <Window.Resources>
        <!-- Card border -->
        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="White"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="16"/>
            <Setter Property="Margin" Value="0,0,0,8"/>
            <Setter Property="BorderBrush" Value="#E5E5E5"/>
            <Setter Property="BorderThickness" Value="1"/>
        </Style>

        <!-- Accent button -->
        <Style x:Key="AccentBtn" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="16,10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#1984D8"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#006CBE"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#CCCCCC"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Danger button (red) -->
        <Style x:Key="DangerBtn" TargetType="Button">
            <Setter Property="Background" Value="#E74C3C"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="16,10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#CB3427"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#B92D1F"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#CCCCCC"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Toolbar button -->
        <Style x:Key="ToolbarBtn" TargetType="Button">
            <Setter Property="Background" Value="#E8E8E8"/>
            <Setter Property="Foreground" Value="#333333"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}" CornerRadius="4">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#D0D0D0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Toggle switch for auto-refresh -->
        <Style x:Key="ToggleSwitch" TargetType="CheckBox">
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <Grid Width="44" Height="24">
                            <Border Name="Track" CornerRadius="12" Background="#CCCCCC"/>
                            <Border Name="Thumb" HorizontalAlignment="Left" Margin="2"
                                    Width="20" Height="20" CornerRadius="10" Background="White">
                                <Border.Effect>
                                    <DropShadowEffect ShadowDepth="0.5" BlurRadius="2" Opacity="0.3"/>
                                </Border.Effect>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="Track" Property="Background" Value="#0078D4"/>
                                <Setter TargetName="Thumb" Property="HorizontalAlignment" Value="Right"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Small inline revoke button -->
        <Style x:Key="RowRevokeBtn" TargetType="Button">
            <Setter Property="Background" Value="#E74C3C"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Width" Value="24"/>
            <Setter Property="Height" Value="24"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="ToolTip" Value="Revoke membership"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="0">
                            <TextBlock Text="X" HorizontalAlignment="Center" VerticalAlignment="Center"
                                       Foreground="White" FontSize="11" FontWeight="Bold"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#CB3427"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#B92D1F"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <DockPanel>
        <!-- Status bar at bottom -->
        <Border DockPanel.Dock="Bottom" Background="#E8E8E8" Padding="12,6"
                BorderBrush="#D0D0D0" BorderThickness="0,1,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Name="StatusPam" Grid.Column="0" FontSize="11"
                           VerticalAlignment="Center" Foreground="#27AE60" Text="PAM Enabled"/>
                <TextBlock Name="StatusDC" Grid.Column="1" FontSize="11"
                           VerticalAlignment="Center" Foreground="#555555"
                           HorizontalAlignment="Center" Text="Target DC: ..."/>
                <TextBlock Name="StatusUser" Grid.Column="2" FontSize="11"
                           VerticalAlignment="Center" Foreground="#555555"
                           HorizontalAlignment="Right" Text="User: ..."/>
            </Grid>
        </Border>

        <!-- Main content -->
        <Grid Margin="12,12,12,4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="380"/>
                <ColumnDefinition Width="12"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- ============ LEFT COLUMN ============ -->
            <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto">
                <StackPanel>

                    <!-- Card 1: Add Temporary Membership -->
                    <Border Style="{StaticResource Card}">
                        <StackPanel>
                            <TextBlock Text="Add Temporary Membership" FontSize="15"
                                       FontWeight="SemiBold" Foreground="#1A1A1A" Margin="0,0,0,12"/>

                            <!-- User field -->
                            <TextBlock Text="User" FontSize="12" Foreground="#555555" Margin="0,0,0,4"/>
                            <Grid Margin="0,0,0,8">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox Name="AddUserBox" Grid.Column="0" Padding="8,6" FontSize="13"
                                         BorderBrush="#D0D0D0" BorderThickness="1"/>
                                <Button Name="AddUserSearchBtn" Grid.Column="1" Content="Search"
                                        Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                            </Grid>

                            <!-- Group field -->
                            <TextBlock Text="Group" FontSize="12" Foreground="#555555" Margin="0,0,0,4"/>
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox Name="AddGroupBox" Grid.Column="0" Padding="8,6" FontSize="13"
                                         BorderBrush="#D0D0D0" BorderThickness="1"/>
                                <Button Name="AddGroupSearchBtn" Grid.Column="1" Content="Search"
                                        Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                            </Grid>

                            <!-- Duration section -->
                            <TextBlock Text="Duration" FontSize="12" Foreground="#555555" Margin="0,0,0,6"/>

                            <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                <RadioButton Name="RadioDuration" Content="Duration"
                                             IsChecked="True" FontSize="12" Foreground="#1A1A1A"
                                             VerticalContentAlignment="Center" Margin="0,0,16,0"/>
                                <RadioButton Name="RadioUntilDate" Content="Until date"
                                             FontSize="12" Foreground="#1A1A1A"
                                             VerticalContentAlignment="Center"/>
                            </StackPanel>

                            <!-- Duration slider panel -->
                            <StackPanel Name="DurationPanel">
                                <Grid Margin="0,0,0,4">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <Slider Name="DurationSlider" Grid.Column="0"
                                            Minimum="30" Maximum="480" Value="240"
                                            TickFrequency="30" IsSnapToTickEnabled="True"
                                            VerticalAlignment="Center"/>
                                    <TextBox Name="DurationMinutesBox" Grid.Column="1"
                                             Width="55" Padding="6,4" FontSize="12"
                                             HorizontalContentAlignment="Center"
                                             BorderBrush="#D0D0D0" BorderThickness="1"
                                             Margin="8,0,0,0" Text="240"/>
                                </Grid>
                                <TextBlock Name="DurationLabel" FontSize="11" Foreground="#888888"
                                           Margin="0,2,0,0" Text="4h 0m"/>
                            </StackPanel>

                            <!-- Until date panel (hidden by default) -->
                            <StackPanel Name="UntilDatePanel" Visibility="Collapsed">
                                <Grid Margin="0,0,0,4">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <DatePicker Name="UntilDatePicker" Grid.Column="0" FontSize="13"
                                                BorderBrush="#D0D0D0" BorderThickness="1"/>
                                    <TextBox Name="UntilTimeBox" Grid.Column="1" Width="65"
                                             Padding="6,4" FontSize="12" Text="00:00"
                                             HorizontalContentAlignment="Center"
                                             BorderBrush="#D0D0D0" BorderThickness="1"
                                             Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock FontSize="11" Foreground="#888888"
                                           Margin="0,2,0,0" Text="Select date and time (HH:mm)"/>
                            </StackPanel>

                            <!-- Add button -->
                            <Button Name="AddMemberBtn" Content="Add Member"
                                    Style="{StaticResource AccentBtn}" Margin="0,14,0,0"
                                    HorizontalAlignment="Stretch"/>
                        </StackPanel>
                    </Border>

                    <!-- Card 2: Quick Actions -->
                    <Border Style="{StaticResource Card}">
                        <StackPanel>
                            <TextBlock Text="Quick Actions" FontSize="15"
                                       FontWeight="SemiBold" Foreground="#1A1A1A" Margin="0,0,0,12"/>

                            <TextBlock Text="Revoke Membership" FontSize="13" Foreground="#1A1A1A"
                                       FontWeight="Medium" Margin="0,0,0,8"/>

                            <CheckBox Name="UseAboveCheckBox" Content="Use user/group from above"
                                      FontSize="12" Foreground="#555555" Margin="0,0,0,8"
                                      IsChecked="True"/>

                            <!-- Revoke User field -->
                            <TextBlock Name="RevokeUserLabel" Text="User" FontSize="12"
                                       Foreground="#555555" Margin="0,0,0,4"
                                       Visibility="Collapsed"/>
                            <Grid Name="RevokeUserGrid" Margin="0,0,0,8" Visibility="Collapsed">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox Name="RevokeUserBox" Grid.Column="0" Padding="8,6"
                                         FontSize="13" BorderBrush="#D0D0D0" BorderThickness="1"/>
                                <Button Name="RevokeUserSearchBtn" Grid.Column="1" Content="Search"
                                        Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                            </Grid>

                            <!-- Revoke Group field -->
                            <TextBlock Name="RevokeGroupLabel" Text="Group" FontSize="12"
                                       Foreground="#555555" Margin="0,0,0,4"
                                       Visibility="Collapsed"/>
                            <Grid Name="RevokeGroupGrid" Margin="0,0,0,8" Visibility="Collapsed">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox Name="RevokeGroupBox" Grid.Column="0" Padding="8,6"
                                         FontSize="13" BorderBrush="#D0D0D0" BorderThickness="1"/>
                                <Button Name="RevokeGroupSearchBtn" Grid.Column="1" Content="Search"
                                        Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                            </Grid>

                            <!-- Revoke button -->
                            <Button Name="RevokeBtn" Content="Revoke"
                                    Style="{StaticResource DangerBtn}" Margin="0,4,0,0"
                                    HorizontalAlignment="Stretch"/>
                        </StackPanel>
                    </Border>

                    <!-- Result log area -->
                    <Border Style="{StaticResource Card}">
                        <StackPanel>
                            <TextBlock Text="Activity Log" FontSize="15"
                                       FontWeight="SemiBold" Foreground="#1A1A1A" Margin="0,0,0,8"/>
                            <TextBox Name="ActivityLog" IsReadOnly="True" TextWrapping="Wrap"
                                     Height="100" FontSize="11" FontFamily="Consolas"
                                     Foreground="#555555" Background="#FAFAFA"
                                     BorderBrush="#E5E5E5" BorderThickness="1"
                                     Padding="8" VerticalScrollBarVisibility="Auto"/>
                        </StackPanel>
                    </Border>

                </StackPanel>
            </ScrollViewer>

            <!-- ============ RIGHT COLUMN ============ -->
            <Border Grid.Column="2" Style="{StaticResource Card}">
                <DockPanel>
                    <!-- Header -->
                    <StackPanel DockPanel.Dock="Top">
                        <TextBlock Text="Group TTL Members" FontSize="15"
                                   FontWeight="SemiBold" Foreground="#1A1A1A" Margin="0,0,0,10"/>

                        <!-- Group search and controls -->
                        <Grid Margin="0,0,0,8">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBox Name="ViewGroupBox" Grid.Column="0" Padding="8,6"
                                     FontSize="13" BorderBrush="#D0D0D0" BorderThickness="1"/>
                            <Button Name="LoadGroupBtn" Grid.Column="1" Content="Load"
                                    Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                            <Button Name="LoadAllBtn" Grid.Column="2" Content="Load All"
                                    Style="{StaticResource ToolbarBtn}" Margin="6,0,0,0"/>
                        </Grid>

                        <!-- Toolbar row -->
                        <Grid Margin="0,0,0,8">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="Auto-refresh" FontSize="12"
                                       Foreground="#555555" VerticalAlignment="Center"
                                       Margin="0,0,6,0"/>
                            <CheckBox Name="AutoRefreshToggle" Grid.Column="1"
                                      Style="{StaticResource ToggleSwitch}"
                                      VerticalAlignment="Center" Margin="0,0,10,0"/>
                            <Button Name="RefreshBtn" Grid.Column="2" Content="Refresh"
                                    Style="{StaticResource ToolbarBtn}"/>
                            <TextBlock Name="MemberCountLabel" Grid.Column="4" FontSize="12"
                                       Foreground="#888888" VerticalAlignment="Center"
                                       Text="0 active TTL members"/>
                        </Grid>
                    </StackPanel>

                    <!-- Members list -->
                    <Grid>
                        <ListView Name="MembersListView" FontSize="12"
                                  BorderBrush="#E5E5E5" BorderThickness="1">
                            <ListView.View>
                                <GridView>
                                    <GridViewColumn Header="User" Width="120"
                                                    DisplayMemberBinding="{Binding UserName}"/>
                                    <GridViewColumn Header="Account" Width="110"
                                                    DisplayMemberBinding="{Binding SamAccountName}"/>
                                    <GridViewColumn Header="Group" Width="120"
                                                    DisplayMemberBinding="{Binding GroupName}"/>
                                    <GridViewColumn Header="Time Remaining" Width="105"
                                                    DisplayMemberBinding="{Binding TTLFormatted}"/>
                                    <GridViewColumn Header="Expires At" Width="120"
                                                    DisplayMemberBinding="{Binding ExpiresAtFormatted}"/>
                                    <GridViewColumn Header="" Width="36">
                                        <GridViewColumn.CellTemplate>
                                            <DataTemplate>
                                                <Button Style="{StaticResource RowRevokeBtn}"
                                                        Tag="{Binding SamAccountName}"
                                                        Click="RowRevoke_Click"/>
                                            </DataTemplate>
                                        </GridViewColumn.CellTemplate>
                                    </GridViewColumn>
                                </GridView>
                            </ListView.View>
                        </ListView>
                        <TextBlock Name="NoMembersLabel" Text="No TTL members found"
                                   FontSize="13" Foreground="#888888"
                                   HorizontalAlignment="Center" VerticalAlignment="Center"
                                   Visibility="Visible"/>
                    </Grid>
                </DockPanel>
            </Border>

        </Grid>
    </DockPanel>
</Window>
"@

# ============================================================================
# Parse XAML and build window
# ============================================================================

# Remove event handler attribute from XAML (we wire it in code)
$cleanXaml = $xaml -replace 'Click="RowRevoke_Click"', ''

[xml]$xamlDoc = $cleanXaml
$reader = [System.Xml.XmlNodeReader]::new($xamlDoc)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Resolve all named elements
$ui = @{}
$xamlDoc.SelectNodes('//*[@Name]') | ForEach-Object {
    $name = $_.Name
    $el = $window.FindName($name)
    if ($el) { $ui[$name] = $el }
}

# ============================================================================
# Initialize environment
# ============================================================================

$script:TargetServer = $null
$script:CurrentViewGroup = $null
$script:ViewAllMode = $false
$script:SessionGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Initialize-Environment {
    try {
        $script:EnvInfo = Get-JITEnvironmentInfo
        $script:TargetServer = $script:EnvInfo.PDCEmulator

        $ui['StatusDC'].Text = "Target DC: $($script:EnvInfo.PDCEmulator)"
        $ui['StatusUser'].Text = "User: $env:USERNAME"

        if ($script:EnvInfo.PamEnabled) {
            $ui['StatusPam'].Text = "PAM Enabled"
            $ui['StatusPam'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#27AE60")
        }
        else {
            $ui['StatusPam'].Text = "PAM Not Enabled - JIT requires the Privileged Access Management feature"
            $ui['StatusPam'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#E74C3C")
        }

        Write-JITLog -Message "JIT Access Manager started. Target DC: $($script:TargetServer), PAM: $($script:EnvInfo.PamEnabled)" -Level Info -LogDirectory $script:LogDirectory
        Append-ActivityLog "JIT Access Manager initialized. Target DC: $($script:EnvInfo.PDCEmulator)"
    }
    catch {
        $ui['StatusDC'].Text = "Target DC: ERROR"
        $ui['StatusPam'].Text = "Unable to connect to Active Directory"
        $ui['StatusPam'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom("#E74C3C")
        Append-ActivityLog "ERROR: Unable to connect to AD - $($_.Exception.Message)"
    }
}

# ============================================================================
# Helper: Append to activity log
# ============================================================================

function Append-ActivityLog {
    param([string]$Text)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $entry = "[$timestamp] $Text"
    $ui['ActivityLog'].AppendText("$entry`r`n")
    $ui['ActivityLog'].ScrollToEnd()
}

# ============================================================================
# Helper: Update duration label from slider/minutes
# ============================================================================

function Update-DurationLabel {
    $minutes = 0
    if ([int]::TryParse($ui['DurationMinutesBox'].Text, [ref]$minutes) -and $minutes -gt 0) {
        $h = [math]::Floor($minutes / 60)
        $m = $minutes % 60
        $ui['DurationLabel'].Text = "${h}h ${m}m"
    }
    else {
        $ui['DurationLabel'].Text = "Invalid"
    }
}

# ============================================================================
# Helper: Load group TTL members into the ListView
# ============================================================================

function Load-GroupMembers {
    param([string]$GroupName)

    if ([string]::IsNullOrWhiteSpace($GroupName)) { return }

    $script:ViewAllMode = $false
    $ui['MembersListView'].Items.Clear()
    $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Collapsed

    try {
        $members = Get-JITGroupTTLMembers -GroupName $GroupName -Server $script:TargetServer
        $script:CurrentViewGroup = $GroupName
        $script:SessionGroups.Add($GroupName) | Out-Null

        if ($members -and $members.Count -gt 0) {
            foreach ($m in $members) {
                $item = [PSCustomObject]@{
                    GroupName         = $GroupName
                    UserName          = $m.UserName
                    SamAccountName    = $m.SamAccountName
                    TTLFormatted      = $m.TTLFormatted
                    ExpiresAtFormatted = $m.ExpiresAt.ToString("yyyy-MM-dd HH:mm")
                }
                $ui['MembersListView'].Items.Add($item) | Out-Null
            }
            $ui['MemberCountLabel'].Text = "$($members.Count) active TTL member$(if($members.Count -ne 1){'s'})"
            $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Collapsed
        }
        else {
            $ui['MemberCountLabel'].Text = "0 active TTL members"
            $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Visible
        }
    }
    catch {
        Append-ActivityLog "ERROR loading members for '$GroupName': $($_.Exception.Message)"
        $ui['MemberCountLabel'].Text = "Error loading members"
        $ui['NoMembersLabel'].Text = "Error: $($_.Exception.Message)"
        $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Visible
    }
}

# ============================================================================
# Helper: Load all TTL members from all session-tracked groups
# ============================================================================

function Load-AllTTLMembers {
    $script:ViewAllMode = $true
    $script:CurrentViewGroup = $null
    $ui['MembersListView'].Items.Clear()
    $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Collapsed

    if ($script:SessionGroups.Count -eq 0) {
        $ui['MemberCountLabel'].Text = "0 active TTL members"
        $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Visible
        return
    }

    $total = 0
    foreach ($groupName in $script:SessionGroups) {
        try {
            $members = Get-JITGroupTTLMembers -GroupName $groupName -Server $script:TargetServer
            foreach ($m in $members) {
                $item = [PSCustomObject]@{
                    GroupName         = $groupName
                    UserName          = $m.UserName
                    SamAccountName    = $m.SamAccountName
                    TTLFormatted      = $m.TTLFormatted
                    ExpiresAtFormatted = $m.ExpiresAt.ToString("yyyy-MM-dd HH:mm")
                }
                $ui['MembersListView'].Items.Add($item) | Out-Null
                $total++
            }
        }
        catch {
            Append-ActivityLog "ERROR loading members for '$groupName': $($_.Exception.Message)"
        }
    }

    $groupCount = $script:SessionGroups.Count
    if ($total -gt 0) {
        $ui['MemberCountLabel'].Text = "$total active TTL member$(if($total -ne 1){'s'}) across $groupCount group$(if($groupCount -ne 1){'s'})"
        $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Collapsed
    }
    else {
        $ui['MemberCountLabel'].Text = "0 active TTL members"
        $ui['NoMembersLabel'].Visibility = [System.Windows.Visibility]::Visible
    }
}

# ============================================================================
# Helper: Revoke a specific user from a group
# ============================================================================

function Revoke-MemberFromView {
    param(
        [string]$SamAccountName,
        [string]$GroupName
    )

    if ([string]::IsNullOrWhiteSpace($GroupName) -or [string]::IsNullOrWhiteSpace($SamAccountName)) {
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Remove '$SamAccountName' from '$GroupName'?",
        "Confirm Revoke",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $result = Remove-JITGroupMember -GroupName $GroupName `
                                         -UserName $SamAccountName `
                                         -Server $script:TargetServer `
                                         -LogDirectory $script:LogDirectory
        Append-ActivityLog $result
        if ($script:ViewAllMode) {
            Load-AllTTLMembers
        }
        else {
            Load-GroupMembers -GroupName $GroupName
        }
    }
}

# ============================================================================
# Event wiring: Duration radio buttons
# ============================================================================

$ui['RadioDuration'].Add_Checked({
    $ui['DurationPanel'].Visibility = [System.Windows.Visibility]::Visible
    $ui['UntilDatePanel'].Visibility = [System.Windows.Visibility]::Collapsed
})

$ui['RadioUntilDate'].Add_Checked({
    $ui['DurationPanel'].Visibility = [System.Windows.Visibility]::Collapsed
    $ui['UntilDatePanel'].Visibility = [System.Windows.Visibility]::Visible
})

# ============================================================================
# Event wiring: Duration slider and text sync
# ============================================================================

$ui['DurationSlider'].Add_ValueChanged({
    $val = [int]$ui['DurationSlider'].Value
    $ui['DurationMinutesBox'].Text = $val.ToString()
    Update-DurationLabel
})

$ui['DurationMinutesBox'].Add_LostFocus({
    $minutes = 0
    if ([int]::TryParse($ui['DurationMinutesBox'].Text, [ref]$minutes)) {
        if ($minutes -lt 1) { $minutes = 1 }
        if ($minutes -ge 30 -and $minutes -le 480) {
            $ui['DurationSlider'].Value = $minutes
        }
    }
    Update-DurationLabel
})

# ============================================================================
# Event wiring: Initialize date/time defaults
# ============================================================================

$window.Add_Loaded({
    $ui['UntilDatePicker'].SelectedDate = (Get-Date).AddHours(4).Date
    $ui['UntilTimeBox'].Text = (Get-Date).AddHours(4).ToString("HH:mm")
    Update-DurationLabel
    Initialize-Environment
})

# ============================================================================
# Event wiring: "Use above" checkbox for Quick Actions
# ============================================================================

$ui['UseAboveCheckBox'].Add_Checked({
    $ui['RevokeUserLabel'].Visibility = [System.Windows.Visibility]::Collapsed
    $ui['RevokeUserGrid'].Visibility = [System.Windows.Visibility]::Collapsed
    $ui['RevokeGroupLabel'].Visibility = [System.Windows.Visibility]::Collapsed
    $ui['RevokeGroupGrid'].Visibility = [System.Windows.Visibility]::Collapsed
})

$ui['UseAboveCheckBox'].Add_Unchecked({
    $ui['RevokeUserLabel'].Visibility = [System.Windows.Visibility]::Visible
    $ui['RevokeUserGrid'].Visibility = [System.Windows.Visibility]::Visible
    $ui['RevokeGroupLabel'].Visibility = [System.Windows.Visibility]::Visible
    $ui['RevokeGroupGrid'].Visibility = [System.Windows.Visibility]::Visible
})

# ============================================================================
# Event wiring: Search buttons
# ============================================================================

$ui['AddUserSearchBtn'].Add_Click({
    $result = Show-SearchDialog -Title "Search User" -SearchType "User" `
                                 -Owner $window -Server $script:TargetServer
    if ($result) { $ui['AddUserBox'].Text = $result }
})

$ui['AddGroupSearchBtn'].Add_Click({
    $result = Show-SearchDialog -Title "Search Group" -SearchType "Group" `
                                 -Owner $window -Server $script:TargetServer
    if ($result) { $ui['AddGroupBox'].Text = $result }
})

$ui['RevokeUserSearchBtn'].Add_Click({
    $result = Show-SearchDialog -Title "Search User" -SearchType "User" `
                                 -Owner $window -Server $script:TargetServer
    if ($result) { $ui['RevokeUserBox'].Text = $result }
})

$ui['RevokeGroupSearchBtn'].Add_Click({
    $result = Show-SearchDialog -Title "Search Group" -SearchType "Group" `
                                 -Owner $window -Server $script:TargetServer
    if ($result) { $ui['RevokeGroupBox'].Text = $result }
})

# ============================================================================
# Event wiring: Add Member button
# ============================================================================

$ui['AddMemberBtn'].Add_Click({
    $userName  = $ui['AddUserBox'].Text.Trim()
    $groupName = $ui['AddGroupBox'].Text.Trim()

    if ([string]::IsNullOrWhiteSpace($userName)) {
        [System.Windows.MessageBox]::Show("Please enter or search for a user.",
            "Validation", [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        [System.Windows.MessageBox]::Show("Please enter or search for a group.",
            "Validation", [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Calculate TimeSpan
    $timeSpan = $null

    if ($ui['RadioDuration'].IsChecked) {
        $minutes = 0
        if (-not [int]::TryParse($ui['DurationMinutesBox'].Text, [ref]$minutes) -or $minutes -le 0) {
            [System.Windows.MessageBox]::Show("Please enter a valid duration in minutes.",
                "Validation", [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $timeSpan = [TimeSpan]::FromMinutes($minutes)
    }
    else {
        # Until date mode
        $selectedDate = $ui['UntilDatePicker'].SelectedDate
        $timeText = $ui['UntilTimeBox'].Text.Trim()

        if (-not $selectedDate) {
            [System.Windows.MessageBox]::Show("Please select a target date.",
                "Validation", [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $timeParts = $timeText -split ':'
        if ($timeParts.Count -ne 2) {
            [System.Windows.MessageBox]::Show("Please enter time in HH:mm format.",
                "Validation", [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $hour = 0; $min = 0
        if (-not [int]::TryParse($timeParts[0], [ref]$hour) -or
            -not [int]::TryParse($timeParts[1], [ref]$min) -or
            $hour -lt 0 -or $hour -gt 23 -or $min -lt 0 -or $min -gt 59) {
            [System.Windows.MessageBox]::Show("Please enter a valid time in HH:mm format.",
                "Validation", [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $targetDateTime = $selectedDate.Date.AddHours($hour).AddMinutes($min)
        $diff = $targetDateTime - (Get-Date)

        if ($diff.TotalSeconds -le 0) {
            [System.Windows.MessageBox]::Show("The target date/time must be in the future.",
                "Validation", [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $timeSpan = [TimeSpan]::FromSeconds([Math]::Floor($diff.TotalSeconds))
    }

    # Perform the add
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        $result = Add-JITGroupMember -GroupName $groupName -UserName $userName `
                                      -TimeSpan $timeSpan -Server $script:TargetServer `
                                      -LogDirectory $script:LogDirectory
        Append-ActivityLog $result
        $script:SessionGroups.Add($groupName) | Out-Null

        if ($script:ViewAllMode) {
            Load-AllTTLMembers
        }
        elseif ($script:CurrentViewGroup -eq $groupName) {
            Load-GroupMembers -GroupName $groupName
        }
    }
    catch {
        Append-ActivityLog "ERROR: $($_.Exception.Message)"
    }
    finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
})

# ============================================================================
# Event wiring: Revoke button
# ============================================================================

$ui['RevokeBtn'].Add_Click({
    $userName  = $null
    $groupName = $null

    if ($ui['UseAboveCheckBox'].IsChecked) {
        $userName  = $ui['AddUserBox'].Text.Trim()
        $groupName = $ui['AddGroupBox'].Text.Trim()
    }
    else {
        $userName  = $ui['RevokeUserBox'].Text.Trim()
        $groupName = $ui['RevokeGroupBox'].Text.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($userName)) {
        [System.Windows.MessageBox]::Show("Please enter or search for a user.",
            "Validation", [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        [System.Windows.MessageBox]::Show("Please enter or search for a group.",
            "Validation", [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Remove '$userName' from '$groupName'?",
        "Confirm Revoke",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $result = Remove-JITGroupMember -GroupName $groupName -UserName $userName `
                                             -Server $script:TargetServer `
                                             -LogDirectory $script:LogDirectory
            Append-ActivityLog $result

            if ($script:ViewAllMode) {
                Load-AllTTLMembers
            }
            elseif ($script:CurrentViewGroup -eq $groupName) {
                Load-GroupMembers -GroupName $groupName
            }
        }
        catch {
            Append-ActivityLog "ERROR: $($_.Exception.Message)"
        }
        finally {
            $window.Cursor = [System.Windows.Input.Cursors]::Arrow
        }
    }
})

# ============================================================================
# Event wiring: Load Group button (right panel)
# ============================================================================

$ui['LoadGroupBtn'].Add_Click({
    $groupName = $ui['ViewGroupBox'].Text.Trim()
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        [System.Windows.MessageBox]::Show("Please enter a group name to load.",
            "Validation", [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Load-GroupMembers -GroupName $groupName
        Append-ActivityLog "Loaded TTL members for group '$groupName'."
    }
    catch {
        Append-ActivityLog "ERROR loading group: $($_.Exception.Message)"
    }
    finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
})

# Load All button: loads TTL members from all session-tracked groups
$ui['LoadAllBtn'].Add_Click({
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Load-AllTTLMembers
        Append-ActivityLog "Loaded TTL members for all session groups ($($script:SessionGroups.Count) group$(if($script:SessionGroups.Count -ne 1){'s'}))."
    }
    catch {
        Append-ActivityLog "ERROR loading all groups: $($_.Exception.Message)"
    }
    finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
})

# Enter key in ViewGroupBox triggers load
$ui['ViewGroupBox'].Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
        $ui['LoadGroupBtn'].RaiseEvent(
            [System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)
        )
        $e.Handled = $true
    }
})

# ============================================================================
# Event wiring: Refresh button
# ============================================================================

$ui['RefreshBtn'].Add_Click({
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        if ($script:ViewAllMode) {
            Load-AllTTLMembers
        }
        elseif (-not [string]::IsNullOrWhiteSpace($script:CurrentViewGroup)) {
            Load-GroupMembers -GroupName $script:CurrentViewGroup
        }
    }
    finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
})

# ============================================================================
# Event wiring: Row revoke button via ListView MouseDoubleClick alternative
# We use a helper approach: add context menu and also handle button clicks
# by scanning the visual tree. Since we removed the XAML Click handler,
# we wire it via AddHandler on the ListView.
# ============================================================================

$ui['MembersListView'].AddHandler(
    [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent,
    [System.Windows.RoutedEventHandler]{
        param($sender, $e)
        # Walk up to find a Button with a Tag (the row revoke button)
        $current = $e.OriginalSource
        while ($current -ne $null -and $current -ne $sender) {
            if ($current -is [System.Windows.Controls.Button] -and $current.Tag) {
                $samAccount = $current.Tag.ToString()
                if (-not [string]::IsNullOrWhiteSpace($samAccount)) {
                    # Resolve group from DataContext by walking up to the ListViewItem
                    $groupName = $script:CurrentViewGroup
                    $lvi = $current
                    while ($lvi -ne $null -and $lvi -isnot [System.Windows.Controls.ListViewItem]) {
                        $lvi = [System.Windows.Media.VisualTreeHelper]::GetParent($lvi)
                    }
                    if ($lvi -and $lvi.DataContext -and $lvi.DataContext.GroupName) {
                        $groupName = $lvi.DataContext.GroupName
                    }
                    Revoke-MemberFromView -SamAccountName $samAccount -GroupName $groupName
                }
                break
            }
            if ($current -is [System.Windows.FrameworkElement]) {
                $current = $current.Parent
                if (-not $current -and $e.OriginalSource -is [System.Windows.FrameworkElement]) {
                    $current = [System.Windows.Media.VisualTreeHelper]::GetParent($e.OriginalSource)
                }
            }
            else {
                break
            }
        }
    }
)

# ============================================================================
# Event wiring: Auto-refresh timer (DispatcherTimer, 30s)
# ============================================================================

$script:RefreshTimer = [System.Windows.Threading.DispatcherTimer]::new()
$script:RefreshTimer.Interval = [TimeSpan]::FromSeconds(30)
$script:RefreshTimer.Add_Tick({
    try {
        if ($script:ViewAllMode) {
            Load-AllTTLMembers
        }
        elseif (-not [string]::IsNullOrWhiteSpace($script:CurrentViewGroup)) {
            Load-GroupMembers -GroupName $script:CurrentViewGroup
        }
    }
    catch {
        # Silently handle refresh errors
    }
})

$ui['AutoRefreshToggle'].Add_Checked({
    $script:RefreshTimer.Start()
    Append-ActivityLog "Auto-refresh enabled (every 30s)."
})

$ui['AutoRefreshToggle'].Add_Unchecked({
    $script:RefreshTimer.Stop()
    Append-ActivityLog "Auto-refresh disabled."
})

# ============================================================================
# Show window
# ============================================================================

$window.ShowDialog() | Out-Null

# Stop timer on exit
if ($script:RefreshTimer.IsEnabled) {
    $script:RefreshTimer.Stop()
}
