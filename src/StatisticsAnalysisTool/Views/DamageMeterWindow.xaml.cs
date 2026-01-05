using StatisticsAnalysisTool.Common;
using StatisticsAnalysisTool.DamageMeter;
using StatisticsAnalysisTool.ViewModels;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Controls;
using System.Globalization;

namespace StatisticsAnalysisTool.Views;

/// <summary>
/// Interaction logic for DamageMeterWindow.xaml
/// </summary>
public partial class DamageMeterWindow
{
    // 标题栏最大化状态缓存，用于双击标题栏在最大化/还原之间切换
    private static bool _isWindowMaximized;
    // 是否启用整窗点击穿透（透传鼠标到下层应用），通过热键或标题栏开关切换
    private bool _isClickThroughEnabled;
    // Win32 消息钩子源，注册后用于接收热键与命中测试等消息
    private HwndSource _hwndSource;

    // Win32 扩展样式与消息常量（点击穿透、热键注册）
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TRANSPARENT = 0x20;
    private const int WS_EX_LAYERED = 0x80000;
    private const int WM_HOTKEY = 0x0312;
    private const int HOTKEY_ID = 0x1001;
    private const uint MOD_CONTROL = 0x0002;
    private const uint MOD_SHIFT = 0x0004;
    private const uint VK_T = 0x54;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    public DamageMeterWindow(ObservableCollection<DamageMeterFragment> damageMeter)
    {
        // 初始化 UI 与绑定的视图模型
        InitializeComponent();
        DataContext = new DamageMeterWindowViewModel(damageMeter);
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        // 句柄创建完成后注册 Win32 消息钩子与热键（Ctrl+Shift+T 切换穿透）
        base.OnSourceInitialized(e);
        var hwnd = new WindowInteropHelper(this).Handle;
        _hwndSource = HwndSource.FromHwnd(hwnd);
        _hwndSource?.AddHook(WndProc);
        _ = RegisterHotKey(hwnd, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, VK_T);
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void MaximizedButton_Click(object sender, RoutedEventArgs e)
    {
        // 自绘标题栏最大化/还原按钮行为，与双击标题栏一致
        if (_isWindowMaximized)
        {
            WindowState = WindowState.Normal;
            Utilities.CenterWindowOnScreen(this);
            MaximizedButton.Content = 1;
            _isWindowMaximized = false;
        }
        else
        {
            WindowState = WindowState.Maximized;
            MaximizedButton.Content = 2;
            _isWindowMaximized = true;
        }
    }

    private void Hotbar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // 标题栏拖动移动窗口
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        // 双击标题栏在最大化/还原间切换
        if (e.ClickCount == 2 && WindowState == WindowState.Normal)
        {
            WindowState = WindowState.Maximized;
            return;
        }

        if (e.ClickCount == 2 && WindowState == WindowState.Maximized) WindowState = WindowState.Normal;
    }

    private void ClickThroughToggle_Click(object sender, RoutedEventArgs e)
    {
        // 标题栏开关：切换整窗穿透状态
        SetClickThrough(ClickThroughToggle.IsChecked == true);
    }

    private void SetClickThrough(bool enable)
    {
        // 通过 Win32 扩展样式切换 WS_EX_TRANSPARENT 实现穿透；关闭时移除该样式
        _isClickThroughEnabled = enable;
        var hwnd = new WindowInteropHelper(this).Handle;
        var exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

        if (enable)
        {
            SetWindowLong(hwnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT);
        }
        else
        {
            SetWindowLong(hwnd, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
        }

        Dispatcher.Invoke(() =>
        {
            // 与 UI 同步复选框状态（启用后标题栏仍可点击）
            try { ClickThroughToggle.IsChecked = enable; } catch { }
        });
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        // 全局热键：Ctrl+Shift+T 切换整窗穿透
        if (msg == WM_HOTKEY && wParam == (IntPtr)HOTKEY_ID)
        {
            SetClickThrough(!_isClickThroughEnabled);
            handled = true;
        }
        return IntPtr.Zero;
    }

    protected override void OnClosed(EventArgs e)
    {
        // 清理消息钩子与热键注册，避免资源泄漏
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            _hwndSource?.RemoveHook(WndProc);
            _ = UnregisterHotKey(hwnd, HOTKEY_ID);
        }
        catch
        {
        }

        base.OnClosed(e);
    }

    private void DamageMeterWindow_OnLoaded(object sender, RoutedEventArgs e)
    {
        // 加载时应用用户上次保存的窗口尺寸/位置与透明度
        var s = StatisticsAnalysisTool.Common.UserSettings.SettingsController.CurrentSettings;
        if (s.DamageMeterWindowWidth > 0) Width = s.DamageMeterWindowWidth;
        if (s.DamageMeterWindowHeight > 0) Height = s.DamageMeterWindowHeight;
        if (s.DamageMeterWindowLeft != 0 || s.DamageMeterWindowTop != 0)
        {
            Left = s.DamageMeterWindowLeft;
            Top = s.DamageMeterWindowTop;
        }
        if (s.DamageMeterWindowOpacity >= 0.2 && s.DamageMeterWindowOpacity <= 1.0)
        {
            Opacity = s.DamageMeterWindowOpacity;
        }
        if (s.IsDamageMeterClickThrough)
        {
            SetClickThrough(true);
        }
        OpacityInput.Text = Opacity.ToString("0.##", CultureInfo.CurrentCulture);
    }

    private void OpacityInput_OnLostFocus(object sender, RoutedEventArgs e)
    {
        // 输入框失焦时应用透明度
        ApplyOpacityFromInput();
    }

    private void OpacityInput_OnKeyDown(object sender, KeyEventArgs e)
    {
        // 回车键应用透明度
        if (e.Key == Key.Enter)
        {
            ApplyOpacityFromInput();
        }
    }

    private void ApplyOpacityFromInput()
    {
        // 解析透明度（0.2–1.0），更新窗口并持久化到设置
        var text = OpacityInput.Text?.Trim();
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.CurrentCulture, out var value) || double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
        {
            if (value < 0.2) value = 0.2;
            if (value > 1.0) value = 1.0;
            Opacity = value;
            OpacityInput.Text = value.ToString("0.##", CultureInfo.CurrentCulture);
            var s = StatisticsAnalysisTool.Common.UserSettings.SettingsController.CurrentSettings;
            s.DamageMeterWindowOpacity = value;
        }
    }

    private void DamageMeterWindow_OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // 关闭前保存当前窗口尺寸与位置到设置文件
        var s = StatisticsAnalysisTool.Common.UserSettings.SettingsController.CurrentSettings;
        s.DamageMeterWindowWidth = Width;
        s.DamageMeterWindowHeight = Height;
        s.DamageMeterWindowLeft = Left;
        s.DamageMeterWindowTop = Top;
        s.IsDamageMeterClickThrough = _isClickThroughEnabled;
    }
}
