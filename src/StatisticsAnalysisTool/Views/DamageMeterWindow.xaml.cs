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
    private static bool _isWindowMaximized;
    private bool _isClickThroughEnabled;
    private HwndSource _hwndSource;

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
        InitializeComponent();
        DataContext = new DamageMeterWindowViewModel(damageMeter);
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
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
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    private void Grid_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2 && WindowState == WindowState.Normal)
        {
            WindowState = WindowState.Maximized;
            return;
        }

        if (e.ClickCount == 2 && WindowState == WindowState.Maximized) WindowState = WindowState.Normal;
    }

    private void ClickThroughToggle_Click(object sender, RoutedEventArgs e)
    {
        SetClickThrough(ClickThroughToggle.IsChecked == true);
    }

    private void SetClickThrough(bool enable)
    {
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
            try { ClickThroughToggle.IsChecked = enable; } catch { }
        });
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam == (IntPtr)HOTKEY_ID)
        {
            SetClickThrough(!_isClickThroughEnabled);
            handled = true;
        }
        return IntPtr.Zero;
    }

    protected override void OnClosed(EventArgs e)
    {
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
        OpacityInput.Text = Opacity.ToString("0.##", CultureInfo.CurrentCulture);
    }

    private void OpacityInput_OnLostFocus(object sender, RoutedEventArgs e)
    {
        ApplyOpacityFromInput();
    }

    private void OpacityInput_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            ApplyOpacityFromInput();
        }
    }

    private void ApplyOpacityFromInput()
    {
        var text = OpacityInput.Text?.Trim();
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.CurrentCulture, out var value) || double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
        {
            if (value < 0.2) value = 0.2;
            if (value > 1.0) value = 1.0;
            Opacity = value;
            OpacityInput.Text = value.ToString("0.##", CultureInfo.CurrentCulture);
        }
    }
}