function Get-MainWindowXaml {
    return @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="LOCKmeAD Manager" Width="1400" Height="900"
    MinWidth="1100" MinHeight="700"
    WindowStartupLocation="CenterScreen"
    Background="#F5F5F5" FontFamily="Segoe UI">

    <Window.Resources>
        <!-- Sidebar nav button - light theme with indicator slot -->
        <Style x:Key="NavBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#616161"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Grid Margin="4,2,6,2">
                            <Border Name="Indicator" Width="3" HorizontalAlignment="Left"
                                    CornerRadius="1.5" Background="Transparent"
                                    VerticalAlignment="Center" Height="16"/>
                            <Border Name="Bd" Background="{TemplateBinding Background}"
                                    CornerRadius="4" Padding="14,8,10,8" Margin="5,0,0,0">
                                <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#E9E9E9"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Active nav button with accent indicator -->
        <Style x:Key="NavBtnActive" TargetType="Button">
            <Setter Property="Background" Value="#ECF2FF"/>
            <Setter Property="Foreground" Value="#005FB8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Grid Margin="4,2,6,2">
                            <Border Width="3" HorizontalAlignment="Left"
                                    CornerRadius="1.5" Background="#0078D4"
                                    VerticalAlignment="Center" Height="16"/>
                            <Border Name="Bd" Background="{TemplateBinding Background}"
                                    CornerRadius="4" Padding="14,8,10,8" Margin="5,0,0,0">
                                <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#DEE9FC"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Toggle switch -->
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

        <!-- Filter button -->
        <Style x:Key="FilterBtn" TargetType="Button" BasedOn="{StaticResource ToolbarBtn}">
            <Setter Property="Padding" Value="14,6"/>
            <Setter Property="Margin" Value="0,0,4,0"/>
        </Style>

        <!-- Card border -->
        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="White"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="16"/>
            <Setter Property="Margin" Value="0,0,0,8"/>
            <Setter Property="BorderBrush" Value="#E5E5E5"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="BorderBrush" Value="#C8C8C8"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="220"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- ============ SIDEBAR ============ -->
        <Border Grid.Column="0" Background="#FAFAFA" BorderBrush="#E5E5E5" BorderThickness="0,0,1,0">
            <DockPanel>
                <!-- App title -->
                <StackPanel DockPanel.Dock="Top" Margin="16,20,16,8">
                    <TextBlock Text="LOCKmeAD" FontSize="18" FontWeight="Bold" Foreground="#1A1A1A"/>
                    <TextBlock Text="Manager" FontSize="11" Foreground="#888" Margin="0,2,0,0"/>
                </StackPanel>

                <!-- Navigation -->
                <StackPanel DockPanel.Dock="Top" Margin="0,8,0,0">
                    <Button Name="NavDashboard" Style="{StaticResource NavBtnActive}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE80F;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="Dashboard" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>

                    <TextBlock Text="MODULES" FontSize="10" FontWeight="SemiBold" Foreground="#999"
                               Margin="24,14,0,6"/>

                    <Button Name="NavHardening" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="Hardening" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavGPO" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="GPO" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavTiering" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE7EF;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="Tiering" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavRBAC" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE716;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="RBAC" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavPSO" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE8D7;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="Password Policy" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavSilo" Style="{StaticResource NavBtn}">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="&#xE81E;" FontFamily="Segoe MDL2 Assets" FontSize="16"
                                       VerticalAlignment="Center" Width="24"/>
                            <TextBlock Text="Service Silos" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                </StackPanel>

                <!-- Bottom controls -->
                <StackPanel DockPanel.Dock="Bottom" Margin="12,0,12,16">
                    <Border Height="1" Background="#E5E5E5" Margin="4,0,4,14"/>

                    <StackPanel Orientation="Horizontal" Margin="6,0,0,12">
                        <CheckBox Name="WhatIfToggle" Style="{StaticResource ToggleSwitch}"
                                  VerticalAlignment="Center"/>
                        <TextBlock Text="WhatIf mode" Foreground="#666" FontSize="12"
                                   Margin="10,0,0,0" VerticalAlignment="Center"/>
                    </StackPanel>

                    <TextBlock Text="Modules to deploy:" Foreground="#666" FontSize="11"
                               Margin="6,0,0,6"/>
                    <StackPanel Margin="6,0,0,8">
                        <CheckBox Name="DeployHardening" Content="Hardening" FontSize="12" Margin="0,2"/>
                        <CheckBox Name="DeployTiering"   Content="Tiering"   FontSize="12" Margin="0,2"/>
                        <CheckBox Name="DeployRBAC"      Content="RBAC"      FontSize="12" Margin="0,2"/>
                        <CheckBox Name="DeployPSO"       Content="PSO"       FontSize="12" Margin="0,2"/>
                        <CheckBox Name="DeploySilo"      Content="Silo"      FontSize="12" Margin="0,2"/>
                        <CheckBox Name="DeployGPO"       Content="GPO"       FontSize="12" Margin="0,2"/>
                    </StackPanel>
                    <TextBlock Name="DeployOrderHint" Text="" FontSize="10" Foreground="#999"
                               Margin="6,0,0,4" TextWrapping="Wrap" Visibility="Collapsed"/>
                    <Button Name="BtnDeploy" Content="Deploy selected" Style="{StaticResource AccentBtn}"
                            HorizontalAlignment="Stretch"/>
                    <Button Name="BtnSave" Content="Save configs" Style="{StaticResource ToolbarBtn}"
                            HorizontalAlignment="Stretch" Margin="0,6,0,0"/>
                </StackPanel>

                <Border/> <!-- spacer -->
            </DockPanel>
        </Border>

        <!-- ============ CONTENT ============ -->
        <Grid Grid.Column="1">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="170"/>
            </Grid.RowDefinitions>

            <!-- Search bar -->
            <Border Name="SearchBarPanel" Grid.Row="0" Background="White" CornerRadius="8"
                    Margin="16,16,16,0" Padding="12,10" Visibility="Collapsed"
                    BorderBrush="#E5E5E5" BorderThickness="1">
                <DockPanel>
                    <TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                               Foreground="#AAAAAA" VerticalAlignment="Center"
                               DockPanel.Dock="Left" Margin="0,0,10,0"/>
                    <Grid>
                        <TextBlock Name="SearchPlaceholder" Text="Search hardening tasks..."
                                   Foreground="#AAAAAA" FontSize="14" VerticalAlignment="Center"
                                   IsHitTestVisible="False"/>
                        <TextBox Name="SearchBox" Background="Transparent" BorderThickness="0"
                                 FontSize="14" VerticalAlignment="Center"/>
                    </Grid>
                </DockPanel>
            </Border>

            <!-- Tab content -->
            <TabControl Name="MainTabs" Grid.Row="1" Margin="16,12,16,0"
                        BorderThickness="0" Background="Transparent" SelectedIndex="0">
                <TabControl.ItemContainerStyle>
                    <Style TargetType="TabItem">
                        <Setter Property="Visibility" Value="Collapsed"/>
                    </Style>
                </TabControl.ItemContainerStyle>

                <!-- ======== DASHBOARD ======== -->
                <TabItem>
                    <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
                        <StackPanel>
                            <!-- Gradient banner -->
                            <Border CornerRadius="8" ClipToBounds="True" Margin="0,0,0,16">
                                <Border.Background>
                                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,0.6">
                                        <GradientStop Color="#4A6CF7" Offset="0"/>
                                        <GradientStop Color="#7B5FC7" Offset="0.5"/>
                                        <GradientStop Color="#B66DB8" Offset="0.8"/>
                                        <GradientStop Color="#C9A0D4" Offset="1"/>
                                    </LinearGradientBrush>
                                </Border.Background>
                                <StackPanel Margin="32,28,32,32">
                                    <TextBlock Text="Active Directory" FontSize="11" Foreground="#C8C8FF"
                                               FontWeight="SemiBold" Margin="0,0,0,4"/>
                                    <TextBlock Text="LOCKmeAD Manager" FontSize="28" Foreground="White"
                                               FontWeight="Bold" Margin="0,0,0,8"/>
                                    <TextBlock Text="Configure and deploy RBAC, Tiering, Hardening, and GPO policies"
                                               FontSize="13" Foreground="#DDDDF0"/>
                                </StackPanel>
                            </Border>

                            <!-- Environment info -->
                            <Border Style="{StaticResource Card}" Padding="20">
                                <StackPanel>
                                    <TextBlock Text="Environment" FontSize="15" FontWeight="SemiBold" Margin="0,0,0,10"/>
                                    <TextBlock Name="DashEnvDC" Text="Current DC: ..." FontSize="13" Foreground="#555" Margin="0,2"/>
                                    <TextBlock Name="DashEnvPDC" Text="PDC Emulator: ..." FontSize="13" Foreground="#555" Margin="0,2"/>
                                    <TextBlock Name="DashEnvDomain" Text="Domain: ..." FontSize="13" Foreground="#555" Margin="0,2"/>
                                    <TextBlock Name="DashEnvForest" Text="Forest: ..." FontSize="13" Foreground="#555" Margin="0,2"/>
                                    <TextBlock Name="DashEnvFunctional" Text="Functional levels: ..." FontSize="13" Foreground="#555" Margin="0,2"/>
                                </StackPanel>
                            </Border>

                            <!-- Module summaries -->
                            <UniformGrid Columns="6" Margin="0,8,0,0">
                                <Border Style="{StaticResource Card}" Margin="0,0,6,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="Hardening" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashHardeningSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashHardeningDetail" Text="tasks enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="3,0,3,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="GPO" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashGPOSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashGPODetail" Text="GPOs enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="3,0,3,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE7EF;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="Tiering" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashTieringSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashTieringDetail" Text="OUs defined" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="3,0,3,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE716;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="RBAC" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashRBACSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashRBACDetail" Text="roles defined" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="3,0,3,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE8D7;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="PSO" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashPSOSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashPSODetail" Text="policies enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="6,0,0,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="&#xE81E;" FontFamily="Segoe MDL2 Assets" FontSize="22"
                                                   Foreground="#0078D4" Margin="0,0,0,10"/>
                                        <TextBlock Text="Silo" FontSize="14" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashSiloSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,6,0,2"/>
                                        <TextBlock Name="DashSiloDetail" Text="silos enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                        </StackPanel>
                    </ScrollViewer>
                </TabItem>

                <!-- ======== HARDENING ======== -->
                <TabItem>
                    <DockPanel>
                        <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="Hardening Tasks" FontSize="22" FontWeight="SemiBold"
                                       VerticalAlignment="Center" Margin="0,0,20,0"/>
                            <Button Name="BtnSelectAll"   Content="Select All"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnDeselectAll" Content="Deselect All" Style="{StaticResource ToolbarBtn}"/>
                        </StackPanel>
                        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
                            <StackPanel Name="HardeningTaskList"/>
                        </ScrollViewer>
                    </DockPanel>
                </TabItem>

                <!-- ======== GPO ======== -->
                <TabItem>
                    <DockPanel>
                        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
                            <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                <TextBlock Text="Security GPO Templates" FontSize="22" FontWeight="SemiBold"
                                           VerticalAlignment="Center" Margin="0,0,20,0"/>
                                <Button Name="BtnGPOSelectAll"   Content="Select All"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                                <Button Name="BtnGPODeselectAll" Content="Deselect All" Style="{StaticResource ToolbarBtn}"/>
                            </StackPanel>
                            <Border Background="#F8F8F8" CornerRadius="6" Padding="12,8" BorderBrush="#E0E0E0" BorderThickness="1">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="Filtering Groups OU" FontSize="12" FontWeight="SemiBold"
                                                   VerticalAlignment="Center" Margin="0,0,10,0"/>
                                        <TextBox Name="GPOFilteringGroupsOU" Width="450" FontSize="12"
                                                 Padding="6,4" BorderBrush="#DDD" VerticalAlignment="Center"
                                                 ToolTip="OU where Apply/Deny filtering groups will be created (must be within T0-Prod)"/>
                                        <Button Name="GPOFilteringOUCopy" Content="&#xE8C8;"
                                                FontFamily="Segoe MDL2 Assets" FontSize="12"
                                                Background="Transparent" BorderThickness="0" Cursor="Hand"
                                                Foreground="#999" ToolTip="Copy DN to clipboard"
                                                Padding="4,0" VerticalAlignment="Center" Margin="4,0,0,0"/>
                                    </StackPanel>
                                    <TextBlock Name="GPOFilteringOUWarning" Text="" FontSize="11"
                                               Foreground="#D35400" Margin="0,4,0,0" Visibility="Collapsed"/>
                                </StackPanel>
                            </Border>
                        </StackPanel>
                        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
                            <StackPanel Name="GPOTaskList"/>
                        </ScrollViewer>
                    </DockPanel>
                </TabItem>

                <!-- ======== TIERING ======== -->
                <TabItem>
                    <DockPanel>
                        <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="Tiering OU Structure" FontSize="22" FontWeight="SemiBold"
                                       VerticalAlignment="Center" Margin="0,0,20,0"/>
                            <Button Name="BtnAddRootOU" Content="+ Add Root OU" Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnDeleteOU"  Content="Delete"         Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnAddChildOU" Content="+ Add Child"   Style="{StaticResource ToolbarBtn}"/>
                        </StackPanel>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="320"/>
                            </Grid.ColumnDefinitions>

                            <!-- Tree -->
                            <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,8,0" Padding="8">
                                <TreeView Name="TieringTree" Background="Transparent" BorderThickness="0"
                                          FontSize="13"/>
                            </Border>

                            <!-- Properties panel -->
                            <Border Grid.Column="1" Style="{StaticResource Card}" Padding="16">
                                <StackPanel Name="TieringPropsPanel">
                                    <TextBlock Text="OU Properties" FontSize="15" FontWeight="SemiBold" Margin="0,0,0,14"/>
                                    <TextBlock Text="Name" FontSize="12" Foreground="#888" Margin="0,0,0,4"/>
                                    <TextBox Name="TieringPropName" FontSize="13" Padding="8,6"
                                             BorderBrush="#DDD" BorderThickness="1"/>
                                    <TextBlock Text="Description" FontSize="12" Foreground="#888" Margin="0,10,0,4"/>
                                    <TextBox Name="TieringPropDesc" FontSize="13" Padding="8,6"
                                             BorderBrush="#DDD" BorderThickness="1"/>
                                    <CheckBox Name="TieringPropProtected" Content="Protected from accidental deletion"
                                              FontSize="12" Margin="0,12,0,0" IsChecked="True"/>
                                    <TextBlock Text="Distinguished Name" FontSize="12" Foreground="#888" Margin="0,14,0,4"/>
                                    <DockPanel>
                                        <Button Name="TieringPropDNCopy" DockPanel.Dock="Right" Content="&#xE8C8;"
                                                FontFamily="Segoe MDL2 Assets" FontSize="12"
                                                Background="Transparent" BorderThickness="0" Cursor="Hand"
                                                Foreground="#999" ToolTip="Copy DN to clipboard"
                                                Padding="4,0" VerticalAlignment="Top" Margin="4,0,0,0"/>
                                        <TextBlock Name="TieringPropDN" Text="-" FontSize="11" Foreground="#0078D4"
                                                   TextWrapping="Wrap"/>
                                    </DockPanel>
                                    <TextBlock Text="Base DN" FontSize="12" Foreground="#888" Margin="0,14,0,4"/>
                                    <TextBox Name="TieringBaseDN" FontSize="13" Padding="8,6"
                                             BorderBrush="#DDD" BorderThickness="1"/>
                                </StackPanel>
                            </Border>
                        </Grid>
                    </DockPanel>
                </TabItem>

                <!-- ======== RBAC ======== -->
                <TabItem>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="360"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Role list -->
                        <DockPanel Grid.Column="0" Margin="0,0,8,0">
                            <TextBlock DockPanel.Dock="Top" Text="RBAC Roles" FontSize="22"
                                       FontWeight="SemiBold" Margin="0,0,0,12"/>
                            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
                                <Button Name="RBACFilterAll" Content="All" Style="{StaticResource FilterBtn}"/>
                                <Button Name="RBACFilterT0"  Content="T0"  Style="{StaticResource FilterBtn}"/>
                                <Button Name="RBACFilterT1"  Content="T1"  Style="{StaticResource FilterBtn}"/>
                                <Button Name="RBACFilterT2"  Content="T2"  Style="{StaticResource FilterBtn}"/>
                            </StackPanel>
                            <StackPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
                                <Button Name="BtnAddRole" Content="+ Add Role"
                                        Style="{StaticResource ToolbarBtn}" HorizontalAlignment="Stretch"/>
                                <Button Name="BtnDeleteRole" Content="Delete Role"
                                        Background="#FCE8E8" Foreground="#A93226"
                                        BorderThickness="0" Padding="12,6" FontSize="12"
                                        Cursor="Hand" HorizontalAlignment="Stretch" Margin="0,4,0,0"/>
                            </StackPanel>
                            <Border Style="{StaticResource Card}" Padding="0">
                                <ListBox Name="RBACRoleList" Background="Transparent" BorderThickness="0"
                                         FontSize="13" Padding="4"/>
                            </Border>
                        </DockPanel>

                        <!-- Role detail -->
                        <Border Grid.Column="1" Style="{StaticResource Card}" Padding="20">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <StackPanel Name="RBACDetailPanel">
                                    <TextBlock Name="RBACDetailTitle" Text="Select a role" FontSize="18"
                                               FontWeight="SemiBold" Margin="0,0,0,16"/>
                                    <TextBlock Name="RBACDetailDesc" Text="" FontSize="13" Foreground="#666"
                                               TextWrapping="Wrap" Margin="0,0,0,16"/>

                                    <!-- GG info -->
                                    <Border Name="RBACGGPanel" Background="#F0F7FF" CornerRadius="6"
                                            Padding="14" Margin="0,0,0,12" Visibility="Collapsed">
                                        <StackPanel>
                                            <TextBlock Text="Global Group (GG)" FontSize="13"
                                                       FontWeight="SemiBold" Foreground="#0078D4" Margin="0,0,0,6"/>
                                            <TextBlock Name="RBACGGName" FontSize="13"/>
                                            <TextBlock Name="RBACGGDesc" FontSize="12" Foreground="#666"/>
                                            <DockPanel Margin="0,4,0,0">
                                                <Button Name="RBACGGOUCopy" DockPanel.Dock="Right" Content="&#xE8C8;"
                                                        FontFamily="Segoe MDL2 Assets" FontSize="12"
                                                        Background="Transparent" BorderThickness="0" Cursor="Hand"
                                                        Foreground="#999" ToolTip="Copy DN to clipboard"
                                                        Padding="4,0" VerticalAlignment="Center" Margin="4,0,0,0"/>
                                                <TextBlock Name="RBACGGOU" FontSize="11" Foreground="#999" TextWrapping="Wrap"/>
                                            </DockPanel>
                                        </StackPanel>
                                    </Border>

                                    <!-- DL groups -->
                                    <TextBlock Name="RBACDLHeader" Text="Domain Local Groups"
                                               FontSize="14" FontWeight="SemiBold" Margin="0,0,0,8"
                                               Visibility="Collapsed"/>
                                    <StackPanel Name="RBACDLList"/>
                                </StackPanel>
                            </ScrollViewer>
                        </Border>
                    </Grid>
                </TabItem>

                <!-- ======== PSO ======== -->
                <TabItem>
                    <DockPanel>
                        <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="Password Policies (PSO)" FontSize="22" FontWeight="SemiBold"
                                       VerticalAlignment="Center" Margin="0,0,20,0"/>
                            <Button Name="BtnPSOSelectAll"   Content="Select All"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnPSODeselectAll" Content="Deselect All" Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnAddPSO"         Content="+ Add Policy" Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnDeletePSO"      Content="Delete"       Background="#FCE8E8" Foreground="#A93226"
                                    BorderThickness="0" Padding="12,6" FontSize="12" Cursor="Hand"/>
                        </StackPanel>
                        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
                            <StackPanel Name="PSOPolicyList"/>
                        </ScrollViewer>
                    </DockPanel>
                </TabItem>

                <!-- ======== SILO ======== -->
                <TabItem>
                    <DockPanel>
                        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
                            <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                <TextBlock Text="Service Silos" FontSize="22" FontWeight="SemiBold"
                                           VerticalAlignment="Center" Margin="0,0,20,0"/>
                                <Button Name="BtnSiloSelectAll"   Content="Select All"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                                <Button Name="BtnSiloDeselectAll" Content="Deselect All" Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                                <Button Name="BtnAddSilo"         Content="+ Add Silo"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                                <Button Name="BtnDeleteSilo"      Content="Delete"       Background="#FCE8E8" Foreground="#A93226"
                                        BorderThickness="0" Padding="12,6" FontSize="12" Cursor="Hand"/>
                            </StackPanel>
                            <Border Background="#E8F4FD" CornerRadius="6" Padding="14,10" BorderBrush="#B8DAEF" BorderThickness="1">
                                <StackPanel>
                                    <TextBlock Text="&#xE946;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                               Foreground="#0078D4" VerticalAlignment="Top" Margin="0,0,0,6"/>
                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#333">
                                        <Run FontWeight="SemiBold">Create per-service silos to prevent lateral movement in case a service account or T1 server running a service/scheduled task is compromised. This module is meant for restricting domain service accounts to the machine they run services on. It creates an authentication policy as well as a dedicated silo for each service account you need protection for.
                                        Each silo prevents assigned service accounts from authenticating on systems that do not run said service. It limits blast radius for T1 lateral movement attempts. Supports both gMSAs and regular service accounts. Not meant for T0</Run>
                                    </TextBlock>
                                </StackPanel>
                            </Border>
                        </StackPanel>
                        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,0,8,0">
                            <StackPanel Name="SiloTaskList"/>
                        </ScrollViewer>
                    </DockPanel>
                </TabItem>
            </TabControl>

            <!-- Console splitter -->
            <GridSplitter Grid.Row="2" Height="6" HorizontalAlignment="Stretch"
                          Background="Transparent" Margin="16,4"/>

            <!-- Console panel -->
            <Border Grid.Row="3" Background="#1E1E1E" Margin="16,0,16,16" CornerRadius="8"
                    BorderBrush="#333333" BorderThickness="1" ClipToBounds="True">
                <DockPanel>
                    <Border DockPanel.Dock="Top" Background="#252525" Padding="14,8">
                        <DockPanel>
                            <Button Name="BtnClearConsole" DockPanel.Dock="Right" Content="Clear"
                                    Background="#3D3D3D" Foreground="#CCC" BorderThickness="0"
                                    Padding="10,3" FontSize="11" Cursor="Hand"/>
                            <TextBlock Text="&#xE756;" FontFamily="Segoe MDL2 Assets" FontSize="13"
                                       Foreground="#777" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <TextBlock Text="Console Output" Foreground="#999" FontSize="12"
                                       VerticalAlignment="Center"/>
                        </DockPanel>
                    </Border>
                    <RichTextBox Name="ConsoleOutput" Background="#1E1E1E" Foreground="#CCCCCC"
                                 IsReadOnly="True" VerticalScrollBarVisibility="Auto" BorderThickness="0"
                                 FontFamily="Cascadia Mono,Consolas,Courier New" FontSize="12"
                                 Padding="10,6"/>
                </DockPanel>
            </Border>
        </Grid>
    </Grid>
</Window>
'@
}
