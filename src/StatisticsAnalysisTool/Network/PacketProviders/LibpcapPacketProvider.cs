#nullable enable // 启用可空引用类型分析（编译器会提示潜在的空引用问题）

using BinaryFormat; // 二进制读取工具（用于逐层解析网络帧）
using BinaryFormat.EthernetFrame; // 以太网（L2）帧解析模型
using BinaryFormat.IPv4; // IPv4（L3）报文解析模型
using BinaryFormat.Udp; // UDP（L4）报文解析模型
using Libpcap; // Npcap/Libpcap 抓包库封装
using Serilog; // 日志
using StatisticsAnalysisTool.Abstractions;
using StatisticsAnalysisTool.Common.UserSettings;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;

namespace StatisticsAnalysisTool.Network.PacketProviders;

// LibpcapPacketProvider：基于 Npcap/Libpcap 的抓包提供者
// 负责：
// 1) 打开网卡设备，使用可选的 BPF 过滤器进行捕获
// 2) 启动后台线程循环读取数据，通过 Dispatcher 分发
// 3) 逐层解析（L2 以太网 → L3 IPv4/IPv6 → L4 UDP），识别 Photon 负载，投递给上层 IPhotonReceiver
public class LibpcapPacketProvider : PacketProvider
{
    private readonly IPhotonReceiver _photonReceiver;
    private PcapDispatcher? _dispatcher;
    private CancellationTokenSource? _cts;
    private Thread? _thread;
    private volatile Pcap? _activePcap;
    private readonly Lock _lockObj = new();
    private readonly Dictionary<Pcap, int> _pcapScores = new();
    private DateTime _lastValidPacketUtc = DateTime.MinValue;
    private readonly Dictionary<Pcap, int> _pcapDeviceType = new();


    private const int ScoreToLock = 1; // 累积到该分数即锁定设备（默认 1，首次有效即锁定）
    private static readonly TimeSpan LockIdleTimeout = TimeSpan.FromSeconds(20); // 超过 20s 无有效包则释放锁定设备

    public override bool IsRunning => _thread is { IsAlive: true }; // C# 模式匹配：线程对象存在且存活即认为正在运行

    public LibpcapPacketProvider(IPhotonReceiver photonReceiver)
    {
        _photonReceiver = photonReceiver ?? throw new ArgumentNullException(nameof(photonReceiver)); // 空检查：避免上层未传递接收器
        _dispatcher = new PcapDispatcher(Dispatch); // 将本类的 Dispatch 方法注册为回调（每次捕获都会调用）
    }

    public override void Start()
    {
        if (_thread is { IsAlive: true }) // 已经启动则直接返回
        {
            return;
        }

        _activePcap = null; // 启动前清空当前锁定设备

        _dispatcher?.Dispose();
        _dispatcher = new PcapDispatcher(Dispatch);

        _cts?.Dispose();
        _cts = new CancellationTokenSource(); // 创建取消令牌（Stop 时用于通知 Worker 退出）

        var dispatcher = _dispatcher;
        if (dispatcher is null)
        {
            Log.Warning("Npcap: dispatcher unavailable, capture cannot start");
            return;
        }

        var devices = Pcap.ListDevices();
        if (devices.Count == 0)
        {
            Log.Warning("Npcap: no devices found");
            return;
        }

        var filter = GetEffectiveFilter(); // 用户配置的 BPF 过滤器（例如仅捕获 UDP 5055/5056/5058）
        bool hasFilter = !string.IsNullOrWhiteSpace(filter);

        int configuredIndex = SettingsController.CurrentSettings.NetworkDevice; // 指定的设备索引（-1 表示自动）
        int opened = 0;
        for (int i = 0; i < devices.Count; i++)
        {
            var device = devices[i];

            if (configuredIndex >= 0 && i != configuredIndex) // 用户指定了设备索引，则跳过其它设备
            {
                continue;
            }

            if (device.Flags.HasFlag(PcapDeviceFlags.Loopback)) // 跳过回环设备（本机回环）
            {
                Log.Information("Npcap[ID:{Index}]: skip loopback {Name}:{Desc}", i, device.Name, device.Description);
                continue;
            }
            if (!device.Flags.HasFlag(PcapDeviceFlags.Up)) // 跳过未启用的设备
            {
                Log.Information("Npcap[ID:{Index}]: skip down {Name}:{Desc}", i, device.Name, device.Description);
                continue;
            }

            try
            {
                Log.Information("Npcap[ID:{Index}]: opening {Name}:{Desc} (Type={Type}, Flags={Flags})",
                    i, device.Name, device.Description, device.Type, device.Flags);

                dispatcher.OpenDevice(device, pcap =>
                {
                    pcap.NonBlocking = true;
                    lock (_lockObj)
                    {
                        _pcapDeviceType[pcap] = (int)device.Type;
                    }
                });

                if (hasFilter)
                {
                    dispatcher.Filter = filter!;
                    Log.Information("Npcap[ID:{Index}]: filter set => {Filter}", i, filter);
                }
                else
                {
                    Log.Information("Npcap[ID:{Index}]: no filter (capturing all)", i);
                }

                opened++;

                if (configuredIndex >= 0)
                {
                    break;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Npcap[ID:{Index}]: open failed for {Name}:{Desc}", i, device.Name, device.Description);
            }
        }

        if (opened == 0)
        {
            Log.Warning("Npcap: no device opened (check NetworkDevice index or admin rights)");
            return;
        }

        _thread = new Thread(Worker) { IsBackground = true }; // 创建后台线程并启动 Worker 循环
        _thread.Start();

        Log.Information("Npcap: capture started on {Opened} device(s), filter: {Filter}", opened, hasFilter ? filter : "<none>");
    }


    private void Dispatch(Pcap pcap, ref Packet packet) // Dispatcher 回调：每个捕获的 Packet 都会经过这里
    {
        var current = _activePcap;
        if (current is not null && !ReferenceEquals(current, pcap))
        {
            return;
        }

        int deviceType = -1;
        lock (_lockObj)
        {
            _pcapDeviceType.TryGetValue(pcap, out deviceType);
        }

        if (deviceType == 53)
        {
            TryHandleRawIp(packet.Data, pcap);
            return;
        }

        // L2 (Ethernet)
        var ethReader = new BinaryFormatReader(packet.Data);
        var eth = new L2EthernetFrameShape();
        if (!ethReader.TryReadL2EthernetFrame(ref eth))
        {
            Log.Information("Npcap: failed to read L2 Ethernet frame");
            return;
        }

        ushort etherType = (ushort)((packet.Data[12] << 8) | packet.Data[13]);
        ReadOnlySpan<byte> l3 = eth.Payload;
        if (etherType == 0x0800)
        {
            var ipReader = new BinaryFormatReader(l3);
            var ip4 = new IPv4PacketShape();
            if (!ipReader.TryReadIPv4Packet(ref ip4))
                return;

            switch ((ProtocolType)ip4.Protocol)
            {
                case ProtocolType.Udp:
                    HandleUdp(ip4.Payload, pcap);
                    return;
                case ProtocolType.Tcp:
                    return;
                default:
                    return;
            }
        }
        else if (etherType == 0x86DD)
        {
            if (!TryReadIPv6(l3, out byte nextHeader, out ReadOnlySpan<byte> ip6Payload))
                return;

            switch ((ProtocolType)nextHeader)
            {
                case ProtocolType.Udp:
                    HandleUdp(ip6Payload, pcap);
                    return;
                case ProtocolType.Tcp:
                    return;
                default:
                    return;
            }
        }
    }

    private static bool TryReadIPv6(ReadOnlySpan<byte> bytes, out byte nextHeader, out ReadOnlySpan<byte> payload) // 简化的 IPv6 读取：固定 40 字节头
    {
        nextHeader = 0;
        payload = default;

        // IPv6-Header = 40 Bytes
        if (bytes.Length < 40)
        {
            return false;
        }

        // Byte 6 = Next Header
        nextHeader = bytes[6];

        // Payload from Byte 40
        payload = bytes[40..];
        return true;
    }

    private void HandleUdp(ReadOnlySpan<byte> l4Payload, Pcap pcap) // 处理 UDP：识别是否为 Photon 并投递给接收器
    {
        var udpReader = new BinaryFormatReader(l4Payload);
        var udp = new UdpPacketShape(); // 解析 UDP 头与负载
        if (!udpReader.TryReadUdpPacket(ref udp))
        {
            return;
        }

        bool isPhotonPort = PhotonPorts.Udp.Contains(udp.SourcePort) || PhotonPorts.Udp.Contains(udp.DestinationPort); // 端口白名单（5055/5056/5058）
        bool looksPhoton = isPhotonPort || LooksLikePhoton(udp.Payload); // 端口或负载特征判定
        Log.Information("UDP: {SourcePort} -> {DestinationPort}, {PayloadLength} bytes, isPhotonPort: {IsPhotonPort}, looksPhoton: {LooksPhoton}",
            udp.SourcePort, udp.DestinationPort, udp.Payload.Length, isPhotonPort, looksPhoton);
        if (!looksPhoton || udp.Payload.Length == 0)
        {
            return;
        }

        SelectAndMaybeLockAdapter(pcap); // 根据有效数据为设备打分并锁定，避免多设备同时输入导致乱序

        var current = _activePcap;
        if (current is not null && !ReferenceEquals(current, pcap))
        {
            return;
        }

        _lastValidPacketUtc = DateTime.UtcNow; // 更新最后有效时间（用于释放锁定的判断）

        try
        {
            _photonReceiver.ReceivePacket(udp.Payload); // 将 Photon 负载投递到上层解析器（AlbionParser）
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "PhotonReceiver.ReceivePacket failed");
        }
    }

    private void SelectAndMaybeLockAdapter(Pcap pcap) // 设备选择与锁定：优先使用有有效数据的设备，长时间无数据释放锁
    {
        lock (_lockObj)
        {
            if (_activePcap is not null)
            {
                if (DateTime.UtcNow - _lastValidPacketUtc > LockIdleTimeout)
                {
                    Log.Information("Npcap: releasing locked adapter due to inactivity");
                    _activePcap = null;
                    _pcapScores.Clear();
                }
                else
                {
                    return;
                }
            }

            var score = _pcapScores.GetValueOrDefault(pcap, 0);

            score++;
            _pcapScores[pcap] = score;

            if (score >= ScoreToLock)
            {
                _activePcap = pcap;
                _lastValidPacketUtc = DateTime.UtcNow;
                Log.Information("Npcap: locked to adapter({device}) after {Score} valid packets", pcap.Name, score);
            }
        }
    }

    private static bool LooksLikePhoton(ReadOnlySpan<byte> payload) // 负载特征判定：首字节常见 Photon 标识（简化版）
    {
        if (payload.Length < 3)
        {
            return false;
        }

        byte b0 = payload[0];

        return b0 is 0xF1 or 0xF2 or 0xFE;
    }

    private void TryHandleRawIp(ReadOnlySpan<byte> bytes, Pcap pcap)
    {
        if (bytes.Length < 1)
        {
            return;
        }

        int version = (bytes[0] >> 4) & 0x0F;
        if (version == 4)
        {
            var ipReader = new BinaryFormatReader(bytes);
            var ip4 = new IPv4PacketShape();
            if (!ipReader.TryReadIPv4Packet(ref ip4))
            {
                return;
            }

            switch ((ProtocolType)ip4.Protocol)
            {
                case ProtocolType.Udp:
                    HandleUdp(ip4.Payload, pcap);
                    return;
                case ProtocolType.Tcp:
                    return;
                default:
                    return;
            }
        }
        else if (version == 6)
        {
            if (!TryReadIPv6(bytes, out byte nextHeader, out ReadOnlySpan<byte> ip6Payload))
            {
                return;
            }

            switch ((ProtocolType)nextHeader)
            {
                case ProtocolType.Udp:
                    HandleUdp(ip6Payload, pcap);
                    return;
                case ProtocolType.Tcp:
                    return;
                default:
                    return;
            }
        }
    }

    private void Worker() // 后台线程循环：周期性从 Dispatcher 拉取数据并分发
    {
        try
        {
            var dispatcher = _dispatcher;
            if (dispatcher is null)
            {
                return;
            }

            while (_cts is { IsCancellationRequested: false })
            {
                int dispatched;
                try
                {
                    dispatched = dispatcher.Dispatch(50);  // 轮询分发（最多等待 50ms），返回处理的包数量
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (InvalidOperationException)
                {
                    break;
                }

                if (dispatched <= 0)
                {
                    _cts?.Token.WaitHandle.WaitOne(25); // 无数据时短暂休眠，避免空转占用 CPU
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Libpcap worker crashed");
        }
    }

    public override void Stop() // 停止抓包：取消令牌 → 释放设备 → 等待线程退出 → 清理状态
    {
        try
        {
            _cts?.Cancel();
            _dispatcher?.Dispose();
            _thread?.Join();
        }
        finally
        {
            _activePcap = null;
            _cts?.Dispose();
            _cts = null;
            _thread = null;
            _dispatcher = null;
        }
    }

    public static class PhotonPorts // Photon 默认端口（Albion 使用的常见配置）
    {
        public static readonly HashSet<ushort> Udp = [5055, 5056, 5058];
        public static readonly HashSet<ushort> Tcp = [4530, 4531, 4533];
    }

    private static string? GetEffectiveFilter() // 返回用户配置的 BPF 过滤器（为空则捕获全部）
    {
        var user = SettingsController.CurrentSettings.PacketFilter;
        return string.IsNullOrWhiteSpace(user) ? null : user;
    }
}
