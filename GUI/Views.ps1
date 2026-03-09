function Get-MainWindowXaml {
    return @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="AD-RBAC Manager" Width="1400" Height="900"
    MinWidth="1100" MinHeight="700"
    WindowStartupLocation="CenterScreen"
    Background="#F3F3F3" FontFamily="Segoe UI">

    <Window.Resources>
        <!-- Sidebar nav button -->
        <Style x:Key="NavBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#999999"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Padding" Value="20,11"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}" CornerRadius="6" Margin="6,2">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#2D2D2D"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Active nav button -->
        <Style x:Key="NavBtnActive" TargetType="Button" BasedOn="{StaticResource NavBtn}">
            <Setter Property="Background" Value="#2D2D2D"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
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

        <!-- Filter button (RBAC tier filters) -->
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
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#FAFAFA"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- ============ SIDEBAR ============ -->
        <Border Grid.Column="0" Background="#1B1B1B">
            <DockPanel>
                <StackPanel DockPanel.Dock="Top" Margin="20,24,20,24">
                    <TextBlock Text="AD-RBAC" FontSize="22" FontWeight="Bold" Foreground="White"/>
                    <TextBlock Text="Manager" FontSize="13" Foreground="#666" Margin="0,2,0,0"/>
                </StackPanel>

                <StackPanel DockPanel.Dock="Top">
                    <Button Name="NavDashboard" Content="Dashboard" Style="{StaticResource NavBtnActive}"/>
                    <Button Name="NavHardening" Content="Hardening" Style="{StaticResource NavBtn}"/>
                    <Button Name="NavGPO"       Content="GPO"       Style="{StaticResource NavBtn}"/>
                    <Button Name="NavTiering"   Content="Tiering"   Style="{StaticResource NavBtn}"/>
                    <Button Name="NavRBAC"      Content="RBAC"      Style="{StaticResource NavBtn}"/>
                </StackPanel>

                <StackPanel DockPanel.Dock="Bottom" Margin="16,0,16,20">
                    <CheckBox Name="WhatIfToggle" Style="{StaticResource ToggleSwitch}" Margin="20,0,0,14"/>
                    <TextBlock Text="WhatIf (simulation)" Foreground="#999" FontSize="11"
                               Margin="20,-10,0,16"/>
                    <Button Name="BtnDeploy" Content="Deploy" Style="{StaticResource AccentBtn}"
                            HorizontalAlignment="Stretch">
                        <Button.ContextMenu>
                            <ContextMenu>
                                <MenuItem Header="Deploy All"/>
                                <Separator/>
                                <MenuItem Header="Deploy Hardening"/>
                                <MenuItem Header="Deploy GPO"/>
                                <MenuItem Header="Deploy Tiering"/>
                                <MenuItem Header="Deploy RBAC"/>
                            </ContextMenu>
                        </Button.ContextMenu>
                    </Button>
                    <Button Name="BtnSave" Content="Save configs" Style="{StaticResource ToolbarBtn}"
                            HorizontalAlignment="Stretch" Margin="0,8,0,0"/>
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

            <!-- Search bar (Hardening only) -->
            <Border Name="SearchBarPanel" Grid.Row="0" Background="White" CornerRadius="8"
                    Margin="16,16,16,0" Padding="12,10" Visibility="Collapsed">
                <Grid>
                    <TextBlock Name="SearchPlaceholder" Text="Search hardening tasks..."
                               Foreground="#AAAAAA" FontSize="14" VerticalAlignment="Center"
                               IsHitTestVisible="False"/>
                    <TextBox Name="SearchBox" Background="Transparent" BorderThickness="0"
                             FontSize="14" VerticalAlignment="Center"/>
                </Grid>
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
                            <TextBlock Text="Dashboard" FontSize="22" FontWeight="SemiBold" Margin="0,0,0,16"/>

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
                            <UniformGrid Columns="4" Margin="0,8,0,0">
                                <Border Style="{StaticResource Card}" Margin="0,0,4,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="Hardening" FontSize="15" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashHardeningSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,8,0,4"/>
                                        <TextBlock Name="DashHardeningDetail" Text="tasks enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="4,0,4,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="GPO" FontSize="15" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashGPOSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,8,0,4"/>
                                        <TextBlock Name="DashGPODetail" Text="GPOs enabled" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="4,0,4,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="Tiering" FontSize="15" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashTieringSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,8,0,4"/>
                                        <TextBlock Name="DashTieringDetail" Text="OUs defined" FontSize="12" Foreground="#888"/>
                                    </StackPanel>
                                </Border>
                                <Border Style="{StaticResource Card}" Margin="4,0,0,0" Padding="20">
                                    <StackPanel>
                                        <TextBlock Text="RBAC" FontSize="15" FontWeight="SemiBold"/>
                                        <TextBlock Name="DashRBACSummary" Text="..." FontSize="28"
                                                   FontWeight="Bold" Foreground="#0078D4" Margin="0,8,0,4"/>
                                        <TextBlock Name="DashRBACDetail" Text="roles defined" FontSize="12" Foreground="#888"/>
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
                        <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="Security GPO Templates" FontSize="22" FontWeight="SemiBold"
                                       VerticalAlignment="Center" Margin="0,0,20,0"/>
                            <Button Name="BtnGPOSelectAll"   Content="Select All"   Style="{StaticResource ToolbarBtn}" Margin="0,0,6,0"/>
                            <Button Name="BtnGPODeselectAll" Content="Deselect All" Style="{StaticResource ToolbarBtn}"/>
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
                                    <TextBlock Name="TieringPropDN" Text="-" FontSize="11" Foreground="#0078D4"
                                               TextWrapping="Wrap"/>
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
                                            <TextBlock Name="RBACGGOU"   FontSize="11" Foreground="#999" Margin="0,4,0,0"/>
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
            </TabControl>

            <!-- Console splitter -->
            <GridSplitter Grid.Row="2" Height="6" HorizontalAlignment="Stretch"
                          Background="Transparent" Margin="16,0"/>

            <!-- Console panel -->
            <Border Grid.Row="3" Background="#1E1E1E" Margin="16,0,16,16" CornerRadius="0,0,8,8">
                <DockPanel>
                    <Border DockPanel.Dock="Top" Background="#2D2D2D" CornerRadius="0" Padding="12,6">
                        <DockPanel>
                            <Button Name="BtnClearConsole" DockPanel.Dock="Right" Content="Clear"
                                    Background="#3D3D3D" Foreground="#CCC" BorderThickness="0"
                                    Padding="10,3" FontSize="11" Cursor="Hand"/>
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
