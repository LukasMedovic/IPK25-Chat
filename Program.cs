// Single file: Program.cs
// Autor      : Lukáš Medovič [xmedovl00/260336]
// Target     : .NET 9.0
// Project    : IPK25-chat client

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// hlavna trieda aplikacie parsuje argumenty a nastavenavuje .net generic host
/// </summary>
public class Program
{
    /// <summary>
    /// Task Main parsuje argumenty, konfiguruje a spusta hosta
    /// </summary>
    public static async Task Main(string[] args)
    {
        // predvolene hodnoty pre konfiguraciu
        TransportType transport = TransportType.Unknown;
        string? server = null;
        int port = 4567;
        string? username = null;
        string? secret = null;
        string? displayName = null;
        int udpTimeoutMs = 250;
        byte udpRetries = 3;
        bool showHelp = false;

        // spracovanie argumentov prikazoveho riadku
        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-h":
                        showHelp = true;
                        break;
                    case "-t":
                        if (i + 1 < args.Length)
                        {
                            string transportStr = args[++i].ToLowerInvariant();
                            if (transportStr == "tcp") transport = TransportType.Tcp;
                            else if (transportStr == "udp") transport = TransportType.Udp;
                            else throw new ArgumentException("invalid value for -t (must be 'tcp' or 'udp')");
                        }
                        else throw new ArgumentException("missing value for -t");
                        break;
                    case "-s":
                        if (i + 1 < args.Length) server = args[++i];
                        else throw new ArgumentException("missing value for -s");
                        break;
                    case "-p":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out port)) { }
                        else throw new ArgumentException("invalid or missing value for -p");
                        break;
                    case "--user":
                        if (i + 1 < args.Length) username = args[++i];
                        else throw new ArgumentException("missing value for --user");
                        break;
                    case "--secret":
                        if (i + 1 < args.Length) secret = args[++i];
                        else throw new ArgumentException("missing value for --secret");
                        break;
                    case "--name":
                        if (i + 1 < args.Length) displayName = args[++i];
                        else throw new ArgumentException("missing value for --name");
                        break;
                    case "-d":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out udpTimeoutMs) && udpTimeoutMs > 0) { }
                        else throw new ArgumentException("invalid or missing value for -d (must be positive integer)");
                        break;
                    case "-r":
                        if (i + 1 < args.Length && byte.TryParse(args[++i], out udpRetries)) { }
                        else throw new ArgumentException("invalid or missing value for -r (must be 0-255)");
                        break;
                    default:
                        throw new ArgumentException($"unknown argument: {args[i]}");
                }
            }

            if (showHelp)
            {
                PrintUsage();
                return;
            }

            // validacia povinnych argumentov
            if (transport == TransportType.Unknown) throw new ArgumentException("transport (-t tcp|udp) must be specified");
            if (string.IsNullOrEmpty(server)) throw new ArgumentException("server (-s) must be specified");

        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"ERROR: Argument error - {ex.Message}"); // format podla specifikacie
            PrintUsage();
            Environment.ExitCode = 1;
            return;
        }

        // konfiguracia .net generic host
        var hostBuilder = Host.CreateApplicationBuilder(args);

        // konfiguracia logovania
        hostBuilder.Services.AddLogging(logging => logging
            .ClearProviders()
            .AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace) // logy od urovne trace idu na stderr
            .AddSimpleConsole(options => {
                options.SingleLine = true;
                options.TimestampFormat = "[HH:mm:ss.fff] ";
                options.UseUtcTimestamp = false;
            })
            .SetMinimumLevel(LogLevel.Trace)
        );

        // registracia hlavnej sluzby ChatService
        hostBuilder.Services.AddSingleton<IHostedService>(sp =>
            new ChatService(
                sp.GetRequiredService<ILogger<ChatService>>(),
                sp.GetRequiredService<IHostApplicationLifetime>(),
                transport,
                server!, port,
                username, secret, displayName,
                udpTimeoutMs, udpRetries
            ));

        // spustenie hosta
        try
        {
            await hostBuilder.Build().RunAsync();
        }
        catch (Exception ex) // zachytenie neocakavanych chyb
        {
            // chyby na stderr
            Console.Error.WriteLine($"\nCRITICAL APPLICATION ERROR: {ex.Message}");
            Console.Error.WriteLine("--- Stack Trace ---");
            Console.Error.WriteLine(ex.StackTrace);
            Environment.ExitCode = 2;
        }
    }

    /// <summary>
    /// vypise navod na pouzitie aplikacie
    /// </summary>
    private static void PrintUsage()
    {
        Console.WriteLine("\nUsage: ipk25chat-client -t <tcp|udp> -s <server> [options]");
        Console.WriteLine("Options:");
        Console.WriteLine("  -t <tcp|udp>            : Transport protocol.");
        Console.WriteLine("  -s <server>             : Server IP address or hostname.");
        Console.WriteLine("  -p <port>               : Server port (default: 4567).");
        Console.WriteLine("  --user <username>       : Username for automatic authentication.");
        Console.WriteLine("  --secret <secret>       : Secret/password for automatic authentication.");
        Console.WriteLine("  --name <displayName>    : Display name for automatic authentication.");
        Console.WriteLine("  -d <timeout_ms>         : UDP confirmation timeout in milliseconds (default: 250).");
        Console.WriteLine("  -r <retries>            : Maximum number of UDP retransmissions (default: 3).");
        Console.WriteLine("  -h                      : Prints this help message and exits.");
        Console.WriteLine("\nExample TCP: ipk25chat-client -t tcp -s 127.0.0.1 --user alice --secret wonderland --name Alice");
        Console.WriteLine("Example UDP: ipk25chat-client -t udp -s anton5.fit.vutbr.cz -d 500 -r 5 --user bob --secret pass --name Bobby");
    }
}

/// <summary>
/// TransportType rozlisuje transportne protokoly
/// </summary>
public enum TransportType { Unknown, Tcp, Udp }

/// <summary>
/// hlavna logika chat klienta implementovana ako hosted service.
/// tato class spracovava pripojenie, uzivatelsky vstup a sietovu komunikaciu pre tcp aj udp.
/// </summary>
public class ChatService : IHostedService
{
    // konstanty a konfiguracie
    private static readonly TimeSpan DefaultReplyTimeoutDuration = TimeSpan.FromSeconds(5); // timeout pre cakanie na auth/join reply
    private const int InputPollIntervalMs = 100; // pauza pri cakani na vstup z konzoly

    // regex pre validaciu formatov parametrov
    private static readonly Regex IdRegex = new("^[a-zA-Z0-9_.-]{1,20}$", RegexOptions.Compiled | RegexOptions.CultureInvariant); // povolenie bodky pre channelid kvoli 'discord.' prefixu na joinovanie channelov 
    private static readonly Regex SecretRegex = new("^[a-zA-Z0-9_-]{1,128}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DisplayNameRegex = new("^[\\x21-\\x7E]{1,20}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private const int MaxMessageContentLength = 60000; // max dlzka obsahu spravy


    // stavy a zavislosti
    private readonly ILogger<ChatService> _logger;
    private readonly IHostApplicationLifetime _appLifetime;
    private readonly TransportType _transport;
    private readonly string _serverAddress;
    private readonly int _serverPort;
    private readonly string? _initialUsername;
    private readonly string? _initialSecret;
    private string _displayName = "user";

    // TCP specificke
    private TcpClient? _tcpClient;
    private NetworkStream? _networkStream;
    private StreamWriter? _writer;
    private StreamReader? _reader;
    private readonly BlockingCollection<string> _tcpNetworkMessages = new(new ConcurrentQueue<string>());

    // UDP specificke
    private UdpClient? _udpClient;
    private readonly int _udpTimeoutMs;
    private readonly byte _udpRetries;
    private int _nextMessageIdRaw = 0;
    private readonly ConcurrentDictionary<ushort, PendingUdpMessage> _pendingConfirmations = new(); // sleduje odoslane udp spravy cakajuce na confirm
    private readonly ConcurrentDictionary<ushort, DateTime> _receivedMessageIds = new(); // sleduje prijate udp id pre detekciu duplikatov
    private Timer? _cleanupTimer;
    private CancellationTokenSource? _udpReaderCts; // token pre ukoncenie udp citaca

    // spolocne sietove a stavove zdroje
    private IPEndPoint? _remoteEndPoint; // endpoint pre udp, info pre tcp
    private volatile ClientState _currentState = ClientState.Disconnected; // stavovy automat klienta
    private readonly BlockingCollection<string> _userInputs = new(new ConcurrentQueue<string>());
    private CancellationTokenSource? _shutdownCts;
    private CancellationTokenSource? _replyTimeoutCts; // casovac pre cakanie na reply

    // stavy klienta podla fsm
    private enum ClientState { Disconnected, Connecting, Start, AuthPending, JoinPending, Open, Closing, End }

    // zaznam pre sledovanie cakajucej udp spravy
    private record PendingUdpMessage(ushort MessageId, byte[] Payload, IPEndPoint Destination, byte RetriesLeft, CancellationTokenSource TimeoutCts);

    // konstruktor
    public ChatService(
        ILogger<ChatService> logger,
        IHostApplicationLifetime appLifetime,
        TransportType transport,
        string server, int port,
        string? username, string? secret, string? displayName,
        int udpTimeoutMs, byte udpRetries)
    {
        _logger = logger;
        _appLifetime = appLifetime;
        _transport = transport;
        _serverAddress = server;
        _serverPort = port;
        _initialUsername = username;
        _initialSecret = secret;
        _udpTimeoutMs = udpTimeoutMs;
        _udpRetries = udpRetries;

        // pouzijeme pociatocne meno, ak je zadane a platne
        if (!string.IsNullOrEmpty(displayName))
        {
            if (DisplayNameRegex.IsMatch(displayName))
            {
                _displayName = displayName;
            }
            else
            {
                _logger.LogWarning("Initial display name '{InitialName}' is invalid. Using default '{DefaultName}'.", displayName, _displayName);
            }
        }
    }

    /// <summary>
    /// StartAsync a StopAsync su volane hostom pri starte sluzby.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Chat service starting ({Transport})...", _transport);
        _shutdownCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _appLifetime.ApplicationStopping);
        var appShutdownToken = _shutdownCts.Token;

        Console.CancelKeyPress += HandleCancelKeyPress; // ctrl+c

        try
        {
            // nadviazanie spojenia / nastavenie podla transportu
            bool setupOk = false;
            if (_transport == TransportType.Tcp) { setupOk = await ConnectTcpServerAsync(appShutdownToken); }
            else { setupOk = await SetupUdpClientAsync(appShutdownToken); }

            if (!setupOk) { RequestShutdown("Failed to connect/setup network client"); return; }

            // spustenie taskov na pozadi pre citanie vstupov
            _ = Task.Run(() => ReadConsoleInputLoopAsync(appShutdownToken), appShutdownToken).ConfigureAwait(false);
            if (_transport == TransportType.Tcp)
            {
                _ = Task.Run(() => ReadTcpMessagesLoopAsync(appShutdownToken), appShutdownToken).ConfigureAwait(false);
                _ = Task.Run(() => ProcessNetworkQueueAsync(_tcpNetworkMessages, appShutdownToken), appShutdownToken).ConfigureAwait(false);
            }
            else // udp
            {
                _udpReaderCts = CancellationTokenSource.CreateLinkedTokenSource(appShutdownToken);
                _ = Task.Run(() => ReadUdpMessagesLoopAsync(_udpReaderCts.Token), _udpReaderCts.Token).ConfigureAwait(false);
                _cleanupTimer = new Timer(CleanupReceivedIds, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5)); // timer pre cistenie prijatych id
            }

            // pokus o automaticku autentifikaciu
            await AttemptAutomaticAuthenticationAsync(appShutdownToken);

            // spustenie hlavneho loopu
            await RunMainMessageLoopAsync(appShutdownToken);

        }
        catch (OperationCanceledException) when (appShutdownToken.IsCancellationRequested)
        {
            _logger.LogInformation("Chat service gracefully stopped by cancellation signal.");
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Unexpected critical error in chat service. Forcing shutdown.");
            Console.Error.WriteLine($"\nCRITICAL ERROR: {ex.Message}");
            await TrySendErrorAsync("internal client failure", CancellationToken.None);
            RequestShutdown("Unexpected critical error");
        }
        finally
        {
            _logger.LogInformation("Chat service stopping...");
            Console.CancelKeyPress -= HandleCancelKeyPress;
            CleanUpNetworkResources(); // uvolnenie zdrojov
            _logger.LogInformation("Chat service stopped.");
        }
    }
    
    public Task StopAsync(CancellationToken cancellationToken)
    {
        // Tato metoda je volana hostom pocas shutdown
        _logger.LogDebug("StopAsync called by host during shutdown.");
        CleanUpNetworkResources(); // cistenie je tu aj s odoslanim BYE
        _logger.LogDebug("StopAsync finished.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// nadviaze tcp spojenie a inicializuje streamy, vrati true pri uspechu. (Connection, Reading, Processing).
    /// </summary>
    private async Task<bool> ConnectTcpServerAsync(CancellationToken cancelToken)
    {
        Debug.Assert(_transport == TransportType.Tcp);
        TransitionState(ClientState.Connecting);
        _logger.LogInformation("Attempting TCP connection to {Server}:{Port}...", _serverAddress, _serverPort);
        try
        {
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_serverAddress, _serverPort, cancelToken);
            _remoteEndPoint = _tcpClient.Client.RemoteEndPoint as IPEndPoint;
            _networkStream = _tcpClient.GetStream();
            _writer = new StreamWriter(_networkStream, Encoding.ASCII, bufferSize: 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
            _reader = new StreamReader(_networkStream, Encoding.ASCII, false, 1024, leaveOpen: true);
            _logger.LogInformation("TCP connection established successfully.");
            TransitionState(ClientState.Start);
            return true;
        }
        catch (OperationCanceledException) { _logger.LogWarning("TCP connection attempt was cancelled."); }
        catch (SocketException ex) { _logger.LogError(ex, "Failed to connect (TCP) to server: {ErrorMessage}", ex.Message); Console.WriteLine($"ERROR: Connection failed to {_serverAddress}:{_serverPort} - {ex.SocketErrorCode}"); }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error during TCP connection attempt."); Console.WriteLine($"ERROR: Unexpected connection error: {ex.Message}"); }

        TransitionState(ClientState.Disconnected);
        return false;
    }

    /// <summary>
    /// nastavi udp klienta, resolvuje adresu servera a bindne lokalny port, vrati true pri uspechu.
    /// </summary>
    private async Task<bool> SetupUdpClientAsync(CancellationToken cancelToken)
    {
        Debug.Assert(_transport == TransportType.Udp);
        TransitionState(ClientState.Connecting);
        _logger.LogInformation("Setting up UDP client for server {Server}:{Port}...", _serverAddress, _serverPort);
        try
        {
            IPAddress[] serverAddresses = await Dns.GetHostAddressesAsync(_serverAddress, cancelToken);
            IPAddress? targetAddress = serverAddresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork); // ipv4

            if (targetAddress == null)
            {
                targetAddress = serverAddresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetworkV6); // pokus o ipv6
                if (targetAddress == null) { _logger.LogError("Failed to resolve server address '{Server}' to any supported IP address.", _serverAddress); throw new SocketException((int)SocketError.HostNotFound); }
                 _logger.LogWarning("Only IPv6 address found for server, specification requires IPv4 support.");
            }

            _remoteEndPoint = new IPEndPoint(targetAddress, _serverPort);
            _udpClient = new UdpClient(targetAddress.AddressFamily);

            // explicitne bindovanie, kvoli receiveasync
            IPAddress localBindAddress = (targetAddress.AddressFamily == AddressFamily.InterNetwork) ? IPAddress.Any : IPAddress.IPv6Any;
            IPEndPoint localEndPoint = new IPEndPoint(localBindAddress, 0); // port 0 = vyberie os
            _udpClient.Client.Bind(localEndPoint);
            _logger.LogInformation("UDP client bound to local endpoint: {LocalEndpoint}", _udpClient.Client.LocalEndPoint);

            _logger.LogInformation("UDP client ready for {Endpoint}.", _remoteEndPoint);
            TransitionState(ClientState.Start);
            return true;
        }
        catch (OperationCanceledException) { _logger.LogWarning("UDP client setup was cancelled."); }
        catch (SocketException ex) { _logger.LogError(ex, "Error setting up UDP client for {Server}: {ErrorMessage}", _serverAddress, ex.Message); Console.WriteLine($"ERROR: Failed to resolve or setup UDP for {_serverAddress} - {ex.SocketErrorCode}"); }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error during UDP client setup."); Console.WriteLine($"ERROR: Unexpected UDP setup error: {ex.Message}"); }

        TransitionState(ClientState.Disconnected);
        return false;
    }


    /// <summary>
    /// AttemptAutomaticAuthenticationAsync sa pokusa o automaticku autentifikaciu.
    /// </summary>
    private async Task AttemptAutomaticAuthenticationAsync(CancellationToken cancelToken)
    {
        bool canAutoAuth = _currentState == ClientState.Start &&
                           !string.IsNullOrEmpty(_initialUsername) &&
                           !string.IsNullOrEmpty(_initialSecret) &&
                           !string.IsNullOrEmpty(_displayName) &&
                           IdRegex.IsMatch(_initialUsername) &&
                           SecretRegex.IsMatch(_initialSecret);

        if (canAutoAuth)
        {
            _logger.LogInformation("Attempting automatic authentication.");
            await SendAuthenticationRequestAsync(_initialUsername!, _initialSecret!, _displayName, cancelToken);
        }
        else if (_currentState == ClientState.Start && (!string.IsNullOrEmpty(_initialUsername) || !string.IsNullOrEmpty(_initialSecret) || !string.IsNullOrEmpty(_displayName)))
        {
            _logger.LogWarning("Incomplete or invalid details provided for auto-authentication. Use /auth command.");
            Console.WriteLine("ERROR: Incomplete or invalid automatic authentication details provided.");
            PrintHelp();
        }
        else if (_currentState == ClientState.Start)
        {
            _logger.LogInformation("No credentials provided for automatic authentication. Use /auth command.");
            PrintHelp();
        }
    }


    /// <summary>
    /// ReadTcpMessagesLoopAsync je loop na pozadi, ktory cita riadky z tcp streamu a pridava ich na spracovanie.
    /// </summary>
    private async Task ReadTcpMessagesLoopAsync(CancellationToken cancelToken)
    {
        Debug.Assert(_transport == TransportType.Tcp);
        _logger.LogDebug("TCP network reader task started.");
        try
        {
            while (!cancelToken.IsCancellationRequested && _reader != null)
            {
                string? tcpReceivedLine = await _reader.ReadLineAsync().WaitAsync(cancelToken);
                if (tcpReceivedLine == null) { _logger.LogInformation("Server (TCP) closed the connection."); break; }
                _logger.LogDebug("<< recv (tcp): {rawmessage}", tcpReceivedLine);
                _tcpNetworkMessages.Add(tcpReceivedLine, cancelToken);
            }
        }
        catch (OperationCanceledException) { _logger.LogDebug("TCP network reader task was cancelled."); }
        catch (IOException ex) { if (!cancelToken.IsCancellationRequested) _logger.LogWarning(ex, "TCP network communication error (IOException). Assuming disconnection."); }
        catch (Exception ex) { if (!cancelToken.IsCancellationRequested) _logger.LogError(ex, "Unexpected error in TCP network reader task."); }
        finally
        {
            _tcpNetworkMessages.CompleteAdding();
            if (!cancelToken.IsCancellationRequested) RequestShutdown("TCP network reading ended unexpectedly");
            _logger.LogDebug("TCP network reader task finished.");
        }
    }

    /// <summary>
    /// loop na pozadi, ktory cita udp, priamo ho spracovava a pridava do cakania.
    /// </summary>
    private async Task ReadUdpMessagesLoopAsync(CancellationToken cancelToken)
    {
        Debug.Assert(_transport == TransportType.Udp && _udpClient != null);
        _logger.LogDebug("UDP network reader task started.");
        try
        {
            while (!cancelToken.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try { result = await _udpClient!.ReceiveAsync(cancelToken); }
                catch (ObjectDisposedException) when(cancelToken.IsCancellationRequested) { _logger.LogDebug("UDP client was disposed while waiting for receive (expected during shutdown)."); break; }

                byte[] receivedDatagram = result.Buffer;
                IPEndPoint sourceEndPoint = result.RemoteEndPoint;
                _logger.LogTrace("<< recv raw bytes ({count}) from {source}: {bytes}", receivedDatagram.Length, sourceEndPoint, Convert.ToHexString(receivedDatagram));

                // aktualizacia remote endpoint
                if (_remoteEndPoint != null && sourceEndPoint.Port != _remoteEndPoint.Port && _currentState < ClientState.Open)
                {
                    if (sourceEndPoint.Address.Equals(_remoteEndPoint.Address)) { _logger.LogInformation("Detected dynamic server port: {NewEndpoint}. Updating target.", sourceEndPoint); _remoteEndPoint = sourceEndPoint; }
                    else { _logger.LogWarning("Received UDP packet from unexpected IP address {SourceAddress} (expected {ExpectedAddress}). Ignoring.", sourceEndPoint.Address, _remoteEndPoint.Address); continue; }
                }
                await HandleRawUdpDatagramAsync(receivedDatagram, sourceEndPoint, cancelToken); // spracovanie datagramu
            }
        }
        catch (OperationCanceledException) { _logger.LogDebug("UDP network reader task was cancelled."); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.Interrupted || cancelToken.IsCancellationRequested) { _logger.LogDebug(ex, "SocketException in UDP reader during shutdown ({ErrorCode}).", ex.SocketErrorCode); }
        catch (Exception ex) { if (!cancelToken.IsCancellationRequested) _logger.LogError(ex, "Unexpected error in UDP network reader task."); }
        finally
        {
            if (!cancelToken.IsCancellationRequested) RequestShutdown("UDP network reading ended unexpectedly");
            _logger.LogDebug("UDP network reader task finished.");
        }
    }


    /// <summary>
    /// ReadConsoleInputLoopAsync je loop na pozadi, ktory cita vstup z konzoly a pridava ho do vstupneho cakania.
    /// </summary>
    private async Task ReadConsoleInputLoopAsync(CancellationToken cancelToken)
    {
        _logger.LogDebug("Console input reader task started.");
        try
        {
            while (!cancelToken.IsCancellationRequested)
            {
                string? userInput = await Task.Run(Console.ReadLine, cancelToken);
                if (userInput == null) { _logger.LogInformation("EOF detected on console input."); break; } // eof
                if (!string.IsNullOrWhiteSpace(userInput)) { _userInputs.Add(userInput, cancelToken); } // pridanie do cakanie
            }
        }
        catch (OperationCanceledException) { _logger.LogDebug("Console input reader task was cancelled."); }
        catch (IOException ex) { if (!cancelToken.IsCancellationRequested) _logger.LogWarning(ex, "Error reading console input (IOException)."); }
        catch (Exception ex) { if (!cancelToken.IsCancellationRequested) _logger.LogError(ex, "Unexpected error in console input reader task."); }
        finally
        {
            _userInputs.CompleteAdding();
            if (!cancelToken.IsCancellationRequested) RequestShutdown("Console input ended unexpectedly");
            _logger.LogDebug("Console input reader task finished.");
        }
    }

    /// <summary>
    /// ProcessNetworkQueueAsync spracovava polozky z cakania sietovych sprav.
    /// </summary>
    private async Task ProcessNetworkQueueAsync(BlockingCollection<string> networkQueue, CancellationToken cancelToken)
    {
        _logger.LogDebug("TCP network queue processor task started.");
        try
        {
            foreach (var tcpMessageLine in networkQueue.GetConsumingEnumerable(cancelToken)) { await HandleServerMessageAsync(tcpMessageLine, cancelToken); }
        }
        catch (OperationCanceledException) { _logger.LogDebug("TCP network queue processing cancelled."); }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error processing TCP network queue."); RequestShutdown("Error processing TCP network queue"); }
        finally { _logger.LogDebug("TCP network queue processor task finished."); }
    }


    /// <summary>
    /// RunMainMessageLoopAsync je hlavny loop, ktory kontroluje timeouty a spracovava polozky z cakania uzivatelskeho vstupu.
    /// </summary>
    private async Task RunMainMessageLoopAsync(CancellationToken cancelToken)
    {
        _logger.LogDebug("Main message processing loop started.");
        try
        {
            while (!cancelToken.IsCancellationRequested)
            {
                // kontrola timeoutov
                if (_replyTimeoutCts != null && _replyTimeoutCts.IsCancellationRequested) { HandleReplyTimeout(); if (cancelToken.IsCancellationRequested) break; }
                if (_transport == TransportType.Udp) { await CheckAndHandleUdpConfirmationTimeoutsAsync(cancelToken); if (cancelToken.IsCancellationRequested) break; }

                // spracovanie uzivatelskeho vstupu
                if (_userInputs.TryTake(out var userInput, InputPollIntervalMs, cancelToken)) { await HandleUserInputAsync(userInput, cancelToken); }
            }
        }
        catch (OperationCanceledException) { _logger.LogInformation("Main message loop was cancelled by signal."); }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error in main message loop."); RequestShutdown("Main message loop error"); }
        finally { RequestShutdown("Main message loop finished"); _logger.LogDebug("Main message processing loop finished."); }
    }

    
    /// <summary>
    /// HandleServerMessageAsync spracuje retazec spravy z tcp servera, urci typ spravy a zavola handler.
    /// </summary>
    private async Task HandleServerMessageAsync(string tcpReceivedLine, CancellationToken cancelToken)
    {
        if (_currentState >= ClientState.Closing) return;
        try
        {
            if (tcpReceivedLine.StartsWith("reply ", StringComparison.OrdinalIgnoreCase)) ParseAndHandleReply(tcpReceivedLine);
            else if (tcpReceivedLine.StartsWith("msg from ", StringComparison.OrdinalIgnoreCase)) ParseAndHandleMessage(tcpReceivedLine);
            else if (tcpReceivedLine.StartsWith("err from ", StringComparison.OrdinalIgnoreCase)) await ParseAndHandleErrorAsync(tcpReceivedLine, cancelToken);
            else if (tcpReceivedLine.StartsWith("bye from ", StringComparison.OrdinalIgnoreCase)) ParseAndHandleBye(tcpReceivedLine);
            else await HandleProtocolViolationAsync($"Received unknown TCP message type from server: {tcpReceivedLine}", cancelToken);
        }
        catch (FormatException ex) { await HandleProtocolViolationAsync($"Malformed TCP server message ({ex.Message}): {tcpReceivedLine}", cancelToken); }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error processing TCP server message: {Message}", tcpReceivedLine); await TrySendErrorAsync($"Internal client error handling TCP server message: {ex.Message}", cancelToken); RequestShutdown("Error processing TCP server message"); }
    }

     /// <summary>
     /// HandleRawUdpDatagramAsync spracuje udp prijaty zo siete, parsuje hlavicku, spracuje confirma alebo ping, kontroluje duplicity, posle confirm a checkuje payload.
     /// </summary>
     private async Task HandleRawUdpDatagramAsync(byte[] receivedDatagram, IPEndPoint sourceEndPoint, CancellationToken cancelToken)
     {
         if (_currentState >= ClientState.Closing) return;
         try
         {
             if (!UdpPacketParser.TryParseHeader(receivedDatagram, out var messageType, out ushort messageId)) { _logger.LogWarning("Received UDP datagram too short ({Length} bytes) from {Source}. Ignoring.", receivedDatagram.Length, sourceEndPoint); return; }
             _logger.LogTrace("Processing UDP datagram: type={Type}, id={Id}, source={Source}", messageType, messageId, sourceEndPoint);

             switch (messageType)
             {
                 case UdpMessageType.Confirm: HandleConfirmMessage(messageId); break; // id je tu refid
                 case UdpMessageType.Ping: _logger.LogDebug("Received PING (id {MessageId}) from {Source}", messageId, sourceEndPoint); await SendConfirmAsync(messageId, sourceEndPoint, cancelToken); break;
                 default:
                     if (IsDuplicateMessage(messageId, sourceEndPoint)) break; // duplicita
                     await SendConfirmAsync(messageId, sourceEndPoint, cancelToken); // posleme confirm
                     await ParseAndHandleUdpPayloadAsync(messageType, messageId, receivedDatagram, sourceEndPoint, cancelToken); // spracujeme obsah
                     break;
             }
         }
         catch (Exception ex) { _logger.LogError(ex, "Unexpected error processing UDP datagram from {Source}", sourceEndPoint); }
     }


    /// <summary>
    /// HandleUserInputAsync spracuje vstup zadany pouzivatelom v konzole, rozhoduje o spracovani prikazu alebo odoslaniu spravy.
    /// </summary>
    private async Task HandleUserInputAsync(string userInput, CancellationToken cancelToken)
    {
        if (_currentState >= ClientState.Closing) return;
        if (userInput.StartsWith("/")) { await ProcessUserCommandAsync(userInput, cancelToken); }
        else { if (_currentState != ClientState.Open) { Console.WriteLine("ERROR: Cannot send message, client is not in 'Open' state."); _logger.LogWarning("Attempted to send message while in invalid state: {State}", _currentState); return; } await SendChatMessageAsync(userInput, cancelToken); } // chat sprava
    }


    /// <summary>
    /// ParseAndHandleReply parsuje a spracuje reply spravu prijatu cez tcp.
    /// </summary>
    private void ParseAndHandleReply(string tcpReceivedLine)
    {
        var match = Regex.Match(tcpReceivedLine, @"^reply\s+(ok|nok)\s+is\s+(.*)", RegexOptions.IgnoreCase);
        if (!match.Success) throw new FormatException("Invalid TCP REPLY format.");
        bool wasSuccess = match.Groups[1].Value.Equals("ok", StringComparison.OrdinalIgnoreCase);
        string messageText = match.Groups[2].Value.TrimEnd();
        HandleReplyLogic(wasSuccess, messageText, 0);
    }

     /// <summary>
     /// ParseAndHandleUdpReply parsuje a spracuje reply payload prijaty cez udp.
     /// </summary>
     private void ParseAndHandleUdpReply(ushort messageId, byte[] receivedDatagram, IPEndPoint source)
     {
         _logger.LogTrace("Entering ParseAndHandleUdpReply for id {Id} from {Source}", messageId, source);
         if (!UdpPacketParser.TryParseReply(receivedDatagram, out bool wasSuccess, out ushort refId, out string messageText)) { _logger.LogWarning("Failed to parse UDP REPLY payload (id {MessageId}) from {Source}", messageId, source); return; }
         HandleReplyLogic(wasSuccess, messageText, refId);
     }

     /// <summary>
     /// HandleReplyLogic spracuvava reply spravy pre oba tcp aj udp a aktualizuje stav klienta authpending alebo joinpending
     /// </summary>
     private void HandleReplyLogic(bool wasSuccess, string messageText, ushort refId)
     {
         Console.WriteLine(wasSuccess ? $"Action Success: {messageText}" : $"Action Failure: {messageText}");
         _logger.LogInformation("Processed REPLY: Success={IsSuccess}, Content='{Content}', RefId={RefId}", wasSuccess, messageText, refId);
         ClientState previousState = _currentState;
         if (previousState == ClientState.AuthPending)
         {
             CancelReplyTimeout();
             if (wasSuccess) { TransitionState(ClientState.Open); _logger.LogInformation("Authentication successful. Client is in Open state."); }
             else { TransitionState(ClientState.Start); _logger.LogWarning("Authentication failed. Reason: {Reason}", messageText); }
         }
         else if (previousState == ClientState.JoinPending)
         {
             CancelReplyTimeout();
             if (wasSuccess) { TransitionState(ClientState.Open); _logger.LogInformation("Successfully joined channel."); }
             else { TransitionState(ClientState.Open); _logger.LogWarning("Failed to join channel. Reason: {Reason}", messageText); } // ostava open
         }
         else { _logger.LogWarning("Received unexpected REPLY message in state {State}. Ignoring.", previousState); }
     }


    /// <summary>
    /// ParseAndHandleMessage parsuje a spracuje prichadzajucu MSG spravu cez tcp.
    /// </summary>
    private void ParseAndHandleMessage(string tcpReceivedLine)
    {
        var match = Regex.Match(tcpReceivedLine, @"^msg\s+from\s+(" + DisplayNameRegex.ToString()[1..^1] + @")\s+is\s+(.*)", RegexOptions.IgnoreCase);
        if (!match.Success) throw new FormatException("Invalid TCP MSG format.");
        string senderDisplayName = match.Groups[1].Value;
        string messageText = match.Groups[2].Value.TrimEnd();
        HandleMessageLogic(senderDisplayName, messageText);
    }

     /// <summary>
     /// ParseAndHandleUdpMessage parsuje a spracuje prichadzajucu MAG spravu cez udp.
     /// </summary>
     private void ParseAndHandleUdpMessage(ushort messageId, byte[] receivedDatagram, IPEndPoint source)
     {
         if (!UdpPacketParser.TryParseMessage(receivedDatagram, out string senderDisplayName, out string messageText)) { _logger.LogWarning("Failed to parse UDP MSG payload (id {MessageId}) from {Source}", messageId, source); return; }
         HandleMessageLogic(senderDisplayName, messageText);
     }

     /// <summary>
     /// HandleMessageLogic zobrazuje prijatie MSG spravy.
     /// </summary>
     private void HandleMessageLogic(string senderDisplayName, string messageText)
     {
         if (!senderDisplayName.Equals(_displayName, StringComparison.Ordinal))
         {
             _logger.LogTrace("Displaying message from '{Sender}': {Content}", senderDisplayName, messageText);
             Console.WriteLine($"{senderDisplayName}: {messageText}"); // vypis spravy
         }
         else { _logger.LogDebug("Received own sent message (loopback), already displayed locally."); }
     }


    /// <summary>
    /// ParseAndHandleErrorAsync parsuje a spracuje prichadzajucu error spravu cez tcp.
    /// </summary>
    private async Task ParseAndHandleErrorAsync(string tcpReceivedLine, CancellationToken cancelToken)
    {
        var match = Regex.Match(tcpReceivedLine, @"^err\s+from\s+(" + DisplayNameRegex.ToString()[1..^1] + @")\s+is\s+(.*)", RegexOptions.IgnoreCase);
        if (!match.Success) throw new FormatException("Invalid TCP ERR format.");
        string senderDisplayName = match.Groups[1].Value;
        string messageText = match.Groups[2].Value.TrimEnd();
        await HandleErrorLogicAsync(senderDisplayName, messageText, cancelToken);
    }

     /// <summary>
     /// ParseAndHandleUdpErrorAsync parsuje a spracuje prichadzajucu error spravu cez udp.
     /// </summary>
     private async Task ParseAndHandleUdpErrorAsync(ushort messageId, byte[] receivedDatagram, IPEndPoint source, CancellationToken cancelToken)
     {
         if (!UdpPacketParser.TryParseError(receivedDatagram, out string senderDisplayName, out string messageText)) { _logger.LogWarning("Failed to parse UDP ERR payload (id {MessageId}) from {Source}", messageId, source); return; }
         await HandleErrorLogicAsync(senderDisplayName, messageText, cancelToken);
     }

     /// <summary>
     /// HandleErrorLogicAsync spracuvava error spravu, zobrazi chybu a inicializuje ukoncenie
     /// </summary>
     private async Task HandleErrorLogicAsync(string senderDisplayName, string messageText, CancellationToken cancelToken)
     {
         Console.WriteLine($"ERROR FROM {senderDisplayName}: {messageText}"); // zobrazime chybu
         _logger.LogError("Received ERR message from {Sender}: {Content}. Initiating shutdown.", senderDisplayName, messageText);
         TransitionState(ClientState.Closing); // ERR = koniec (ach to boli)
         RequestShutdown("Received ERR message");
         await Task.CompletedTask;
     }


    /// <summary>
    /// ParseAndHandleBye parsuje a spracuje prichadzajucu BYE spravu cez tcp.
    /// </summary>
    private void ParseAndHandleBye(string tcpReceivedLine)
    {
        var match = Regex.Match(tcpReceivedLine, @"^bye\s+from\s+(" + DisplayNameRegex.ToString()[1..^1] + @")$", RegexOptions.IgnoreCase);
        if (!match.Success) throw new FormatException("Invalid TCP BYE format.");
        string senderDisplayName = match.Groups[1].Value;
        HandleByeLogic(senderDisplayName);
    }

     /// <summary>
     /// ParseAndHandleUdpBye parsuje a spracuje prichadzajucu BYE spravu cez udp.
     /// </summary>
     private void ParseAndHandleUdpBye(ushort messageId, byte[] receivedDatagram, IPEndPoint source)
     {
         if (!UdpPacketParser.TryParseBye(receivedDatagram, out string senderDisplayName)) { _logger.LogWarning("Failed to parse UDP BYE payload (id {MessageId}) from {Source}", messageId, source); return; }
         HandleByeLogic(senderDisplayName);
     }

     /// <summary>
     /// HandleByeLogic spracuvava BYE spravu, inicializuje ukoncenie.
     /// </summary>
     private void HandleByeLogic(string senderDisplayName)
     {
         _logger.LogInformation("Received BYE message from {Sender}. Closing connection.", senderDisplayName);
         TransitionState(ClientState.Closing); // BYE = koniec
         RequestShutdown("Received BYE message");
     }

     /// <summary>
     /// HandleConfirmMessage spracuje prijate udp CONFIRM, odstrani cakajucu spravu.
     /// </summary>
     private void HandleConfirmMessage(ushort refId)
     {
         if (_pendingConfirmations.TryRemove(refId, out var pendingUdpMsg)) // odstrani cakajucu spravu
         {
             _logger.LogDebug("Received CONFIRM for message id {RefId}.", refId);
             _logger.LogTrace("Successfully removed message id {RefId} from pending confirmations.", refId);
             pendingUdpMsg.TimeoutCts.Cancel();
             try { pendingUdpMsg.TimeoutCts.Dispose(); } catch { }
         }
         else { _logger.LogWarning("Received CONFIRM for unknown or already confirmed message id {RefId}.", refId); } 
     }

     /// <summary>
     /// ParseAndHandleUdpPayloadAsync parsuje a spracuje payload prijatej udp spravy, rozhoduje o spracovani urcitym handlerom podla typu spravy
     /// </summary>
     private async Task ParseAndHandleUdpPayloadAsync(UdpMessageType messageType, ushort messageId, byte[] receivedDatagram, IPEndPoint source, CancellationToken cancelToken)
     {
         switch (messageType)
         {
             case UdpMessageType.Reply: ParseAndHandleUdpReply(messageId, receivedDatagram, source); break;
             case UdpMessageType.Message: ParseAndHandleUdpMessage(messageId, receivedDatagram, source); break;
             case UdpMessageType.Error: await ParseAndHandleUdpErrorAsync(messageId, receivedDatagram, source, cancelToken); break;
             case UdpMessageType.Bye: ParseAndHandleUdpBye(messageId, receivedDatagram, source); break;
             case UdpMessageType.Authenticate: case UdpMessageType.JoinChannel:
                  _logger.LogWarning("Received unexpected UDP message type {MessageType} (id {MessageId}) from server {Source}", messageType, messageId, source);
                 await HandleProtocolViolationAsync($"Received unexpected message type {messageType} from server", cancelToken); break;
             default: _logger.LogWarning("Received unknown/unhandled UDP payload type ({MessageType}) id {MessageId} from {Source}", messageType, messageId, source); break;
         }
     }

     
    /// <summary>
    /// ProcessUserCommandAsync spracuje prikaz, ktory zacina s '/'.
    /// </summary>
    private async Task ProcessUserCommandAsync(string commandLine, CancellationToken cancelToken)
    {
        var commandTokens = commandLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (commandTokens.Length == 0) return;
        string command = commandTokens[0].ToLowerInvariant();

        switch (command)
        {
            case "/help": PrintHelp(); return;
            case "/rename": HandleRenameCommand(commandTokens); return;
        }

        switch (command) // prikazy zavisle od stavu
        {
            case "/auth": if (_currentState != ClientState.Start) { Console.WriteLine("ERROR: /auth command not possible in current state."); return; } await HandleAuthCommandAsync(commandTokens, cancelToken); break;
            case "/join": if (_currentState != ClientState.Open) { Console.WriteLine("ERROR: /join command only possible in 'Open' state."); return; } await HandleJoinCommandAsync(commandTokens, cancelToken); break;
            default: Console.WriteLine($"ERROR: Unknown command '{command}'."); break;
        }
    }

    /// <summary>
    /// HandleAuthCommandAsync spracuje prikaz /auth a vstup, posle auth poziadavku.
    /// </summary>
    private async Task HandleAuthCommandAsync(string[] commandTokens, CancellationToken cancelToken)
    {
        if (commandTokens.Length != 4) { Console.WriteLine("ERROR: Invalid argument count for /auth."); return; }
        string username = commandTokens[1]; string secret = commandTokens[2]; string displayName = commandTokens[3];
        if (!IdRegex.IsMatch(username)) { Console.WriteLine("ERROR: Invalid Username format or length."); return; }
        if (!SecretRegex.IsMatch(secret)) { Console.WriteLine("ERROR: Invalid Secret format or length."); return; }
        if (!DisplayNameRegex.IsMatch(displayName)) { Console.WriteLine("ERROR: Invalid DisplayName format or length."); return; }
        await SendAuthenticationRequestAsync(username, secret, displayName, cancelToken); // odoslanie
    }

    /// <summary>
    /// HandleJoinCommandAsync spracuje prikaz /join a vstup, posle join poziadavku.
    /// </summary>
    private async Task HandleJoinCommandAsync(string[] commandTokens, CancellationToken cancelToken)
    {
        if (commandTokens.Length != 2) { Console.WriteLine("ERROR: Invalid argument count for /join."); return; }
        string targetChannelId = commandTokens[1];
        if (!IdRegex.IsMatch(targetChannelId)) { Console.WriteLine("ERROR: Invalid ChannelID format or length."); return; }
        _logger.LogInformation("Requesting to join channel '{ChannelId}'.", targetChannelId);
        TransitionState(ClientState.JoinPending); // cakanie na reply
        if (_transport == TransportType.Tcp) { string message = $"join {targetChannelId} as {_displayName}"; await SendMessageTcpAsync(message, cancelToken); StartReplyTimeout(DefaultReplyTimeoutDuration, cancelToken); }
        else { byte[] udpMessageBody = UdpPacketBuilder.CreateJoinPayload(targetChannelId, _displayName); await SendMessageUdpWithConfirmationAsync(UdpMessageType.JoinChannel, udpMessageBody, cancelToken); StartReplyTimeout(DefaultReplyTimeoutDuration, cancelToken); }
    }

    /// <summary>
    /// HandleRenameCommand spracuje prikaz /rename a zmeni zobrazovane meno lokalne.
    /// </summary>
    private void HandleRenameCommand(string[] commandTokens)
    {
        if (_currentState < ClientState.Start || _currentState >= ClientState.Closing) { Console.WriteLine("ERROR: Cannot rename in current state."); return; } // kontrola stavu
        if (commandTokens.Length != 2) { Console.WriteLine("ERROR: Invalid argument count for /rename."); return; }
        string newDisplayName = commandTokens[1];
        if (!DisplayNameRegex.IsMatch(newDisplayName)) { Console.WriteLine("ERROR: Invalid new DisplayName format or length."); return; }
        _displayName = newDisplayName; // lokalna zmena
        _logger.LogInformation("User changed display name to '{DisplayName}'.", _displayName);
    }
    
    /// <summary>
    /// SendAuthenticationRequestAsync odosle auth poziadavku na server.
    /// </summary>
    private async Task SendAuthenticationRequestAsync(string username, string secret, string displayName, CancellationToken cancelToken)
    {
        _displayName = displayName;
        _logger.LogInformation("Sending authentication request for user '{Username}'.", username);
        TransitionState(ClientState.AuthPending);
        if (_transport == TransportType.Tcp) { string message = $"auth {username} as {displayName} using {secret}"; await SendMessageTcpAsync(message, cancelToken); StartReplyTimeout(DefaultReplyTimeoutDuration, cancelToken); }
        else { byte[] udpMessageBody = UdpPacketBuilder.CreateAuthPayload(username, displayName, secret); await SendMessageUdpWithConfirmationAsync(UdpMessageType.Authenticate, udpMessageBody, cancelToken); StartReplyTimeout(DefaultReplyTimeoutDuration, cancelToken); }
    }

    /// <summary>
    /// SendChatMessageAsync odosle chat spravu MSG a zobrazi ju lokalne ECHO.
    /// </summary>
    private async Task SendChatMessageAsync(string messageContent, CancellationToken cancelToken)
    {
        if (messageContent.Length > MaxMessageContentLength) { messageContent = messageContent[..MaxMessageContentLength]; Console.WriteLine($"ERROR: Message too long, truncated to {MaxMessageContentLength} characters."); _logger.LogWarning("Message content was truncated."); }
        if (messageContent.Any(c => (c < ' ' && c != '\n') || c > '~')) { Console.WriteLine("ERROR: Message contains invalid characters."); _logger.LogWarning("Attempted to send message with invalid characters."); return; }

        Console.WriteLine($"{_displayName}: {messageContent}"); // echo

        // odoslanie
        if (_transport == TransportType.Tcp) { string messageToSend = $"msg from {_displayName} is {messageContent}"; await SendMessageTcpAsync(messageToSend, cancelToken); }
        else { byte[] udpMessageBody = UdpPacketBuilder.CreateMessagePayload(_displayName, messageContent); await SendMessageUdpWithConfirmationAsync(UdpMessageType.Message, udpMessageBody, cancelToken); }
    }

    /// <summary>
    /// SendMessageTcpAsync odosiela spravy cez tcp.
    /// </summary>
    private async Task SendMessageTcpAsync(string message, CancellationToken cancelToken)
    {
        Debug.Assert(_transport == TransportType.Tcp);
        if (_writer == null || _currentState >= ClientState.End) { _logger.LogWarning("Attempted to send TCP message, but writer is null or client is stopped. Message: {Message}", message); return; }
        bool isClosing = _currentState == ClientState.Closing; bool isCriticalMessage = message.StartsWith("bye", StringComparison.OrdinalIgnoreCase) || message.StartsWith("err", StringComparison.OrdinalIgnoreCase);
        if (isClosing && !isCriticalMessage) { _logger.LogWarning("Attempted to send non-critical TCP message during shutdown: {Message}", message); return; }

        try { _logger.LogDebug(">> sent (tcp): {Message}", message); await _writer.WriteLineAsync(message.AsMemory(), cancelToken); }
        catch (OperationCanceledException) { _logger.LogWarning("TCP message send was cancelled. Message: {Message}", message); throw; }
        catch (IOException ex) { _logger.LogError(ex, "IOException during TCP message send. Assuming disconnection. Message: {Message}", message); RequestShutdown("Network error during TCP send"); throw; }
        catch (ObjectDisposedException ex) { _logger.LogError(ex, "Attempted to send TCP message on closed stream/writer. Message: {Message}", message); if (!isClosing && _currentState != ClientState.End) RequestShutdown("Stream closed during TCP send"); throw; }
        catch (Exception ex) { _logger.LogError(ex, "Unexpected error sending TCP message: {Message}", message); await TrySendErrorAsync($"Client TCP send failure: {ex.Message}", CancellationToken.None); RequestShutdown("Unexpected error during TCP send"); throw; }
    }

     /// <summary>
     /// SendMessageUdpWithConfirmationAsync odosle udp datagram, ktory vyzaduje potvrdenie, taktiez riesi opakovania.
     /// </summary>
     private async Task SendMessageUdpWithConfirmationAsync(UdpMessageType type, byte[] udpMessageBody, CancellationToken cancelToken)
     {
         Debug.Assert(_transport == TransportType.Udp && _udpClient != null && _remoteEndPoint != null);
         if (_currentState >= ClientState.Closing && type != UdpMessageType.Bye && type != UdpMessageType.Error) { _logger.LogWarning("Attempted to send UDP message type {Type} during shutdown.", type); return; }

         int nextIdRaw = Interlocked.Increment(ref _nextMessageIdRaw); // ziskanie id
         ushort messageId = (ushort)(nextIdRaw - 1);
         byte[] datagramToSend = UdpPacketBuilder.Serialize(type, messageId, udpMessageBody);
         var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancelToken);
         var pendingUdpMsg = new PendingUdpMessage(messageId, datagramToSend, _remoteEndPoint!, _udpRetries, timeoutCts); // priprava na sledovanie

         if (!_pendingConfirmations.TryAdd(messageId, pendingUdpMsg)) { _logger.LogError("Failed to add UDP message {MessageId} to pending confirmations (ID already exists?).", messageId); try { timeoutCts.Dispose(); } catch { } return; } // pridanie do zoznamu

         _logger.LogDebug("Sending UDP message {MessageType} (id {MessageId}) awaiting confirmation.", type, messageId);
         await SendUdpDatagramAsync(pendingUdpMsg, cancelToken); // prvy pokus
     }

     /// <summary>
     /// SendUdpDatagramAsync odosle udp datagram a naplanuje kontrolu timeoutu pre opakovanie
     /// </summary>
     private async Task SendUdpDatagramAsync(PendingUdpMessage pendingUdpMsg, CancellationToken cancelToken)
     {
         if (_udpClient == null || pendingUdpMsg.Destination == null || cancelToken.IsCancellationRequested || pendingUdpMsg.TimeoutCts.IsCancellationRequested) // kontrola pred odoslanim
         {
              _logger.LogWarning("UDP datagram send (id {MessageId}) skipped (client null or cancelled).", pendingUdpMsg.MessageId);
              if (pendingUdpMsg.TimeoutCts.IsCancellationRequested && _pendingConfirmations.ContainsKey(pendingUdpMsg.MessageId)) { if (_pendingConfirmations.TryRemove(pendingUdpMsg.MessageId, out var r)) { try { r.TimeoutCts.Dispose(); } catch { } } } // upratanie
              return;
         }

         try
         {
             _logger.LogDebug(">> sent (udp to {Destination}): {MessageType} (id {MessageId}), retries left: {Retries}", pendingUdpMsg.Destination, (UdpMessageType)pendingUdpMsg.Payload[0], pendingUdpMsg.MessageId, pendingUdpMsg.RetriesLeft); // logovanie
             await _udpClient.SendAsync(pendingUdpMsg.Payload, pendingUdpMsg.Destination, cancelToken); // odoslanie

             // planovanie timeoutu
             bool isLastRetry = pendingUdpMsg.RetriesLeft == 0;
             if ((pendingUdpMsg.RetriesLeft > 0 || isLastRetry) && !cancelToken.IsCancellationRequested && !pendingUdpMsg.TimeoutCts.IsCancellationRequested)
             {
                 _ = Task.Delay(_udpTimeoutMs, pendingUdpMsg.TimeoutCts.Token).ContinueWith(t => { if (!t.IsCanceled && !pendingUdpMsg.TimeoutCts.IsCancellationRequested) { try { pendingUdpMsg.TimeoutCts.Cancel(); } catch { } } }, TaskContinuationOptions.NotOnCanceled);
             }
         }
         catch (OperationCanceledException) { _logger.LogWarning("UDP datagram send (id {MessageId}) was cancelled.", pendingUdpMsg.MessageId); }
         catch (SocketException ex) { _logger.LogError(ex, "SocketException during UDP datagram send (id {MessageId}).", pendingUdpMsg.MessageId); }
         catch (Exception ex) { _logger.LogError(ex, "Unexpected error during UDP datagram send (id {MessageId}).", pendingUdpMsg.MessageId); }
     }

    /// <summary>
    /// CheckAndHandleUdpConfirmationTimeoutsAsync kontroluje udp spravy cakajuce na potvrdenie a spracuje ich retry alebo chyba.
    /// </summary>
    private async Task CheckAndHandleUdpConfirmationTimeoutsAsync(CancellationToken cancelToken)
    {
        var currentPendingIds = _pendingConfirmations.Keys.ToList();
        foreach (ushort id in currentPendingIds)
        {
            if (_pendingConfirmations.TryGetValue(id, out var pendingUdpMsg) && pendingUdpMsg.TimeoutCts.IsCancellationRequested && !cancelToken.IsCancellationRequested)
            {
                await HandleUdpConfirmationTimeoutAsync(id, pendingUdpMsg, cancelToken); // spracovanie timeoutu
            }
        }
    }

    /// <summary>
    /// HandleUdpConfirmationTimeoutAsync spracuje timeout potvrdenia pre jednu konkretnu udp spravu a odstrani spravu, bud zopakuje odoslanie alebo oznami chybu.
    /// </summary>
    private async Task HandleUdpConfirmationTimeoutAsync(ushort messageId, PendingUdpMessage expiredUdpMsg, CancellationToken cancelToken)
    {
        if (_pendingConfirmations.TryRemove(messageId, out _)) // odstranime zo zoznamu
        {
             _logger.LogTrace("Processing confirmation timeout for message id {MessageId}.", messageId);
             try { expiredUdpMsg.TimeoutCts.Dispose(); } catch { }

            if (expiredUdpMsg.RetriesLeft > 0 && !cancelToken.IsCancellationRequested)
            {
                _logger.LogWarning("Confirmation timeout for UDP message id {MessageId}. Retries left: {Retries}. Retrying send.", messageId, expiredUdpMsg.RetriesLeft);
                var nextTryMessage = expiredUdpMsg with { RetriesLeft = (byte)(expiredUdpMsg.RetriesLeft - 1), TimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancelToken) }; // priprava na retry
                if (_pendingConfirmations.TryAdd(messageId, nextTryMessage)) { _ = Task.Run(() => SendUdpDatagramAsync(nextTryMessage, cancelToken), cancelToken).ConfigureAwait(false); } // odosleme znova
                else { _logger.LogError("Failed to re-add UDP message {MessageId} to pending list after timeout (ID already exists?).", messageId); try { nextTryMessage.TimeoutCts.Dispose(); } catch { } }
            }
            else // koniec pokusov alebo shutdown
            {
                if (!cancelToken.IsCancellationRequested)
                {
                    UdpMessageType failedType = (UdpMessageType)expiredUdpMsg.Payload[0];
                    Console.WriteLine($"ERROR: Confirmation timeout for sent message (type: {failedType}, id: {messageId}).");
                    _logger.LogError("Retries exhausted for UDP message {MessageType} (id {MessageId}). Shutting down.", failedType, messageId);
                    TransitionState(ClientState.Closing); RequestShutdown("UDP confirmation timeout"); // ukoncenie klienta
                }
                else { _logger.LogWarning("Confirmation timeout for UDP message id {MessageId} during shutdown.", messageId); }
            }
        }
        else if (expiredUdpMsg?.TimeoutCts != null) // ak bola medzitym potvrdena
        {
             _logger.LogTrace("Message id {MessageId} was already confirmed before processing timeout. Cleaning up original CTS.", messageId);
             try { expiredUdpMsg.TimeoutCts.Dispose(); } catch { }
        }
        await Task.CompletedTask;
    }


     /// <summary>
     /// SendConfirmAsync odosle udp CONFIRM spravu pre dane referencne id spravy.
     /// </summary>
     private async Task SendConfirmAsync(ushort referencedMessageId, IPEndPoint destination, CancellationToken cancelToken)
     {
         Debug.Assert(_transport == TransportType.Udp && _udpClient != null);
         byte[] confirmDatagram = UdpPacketBuilder.SerializeConfirm(referencedMessageId);
         try
         {
             _logger.LogTrace(">> sending udp confirm to {Destination}: refid={RefId}, bytes={Bytes}", destination.ToString(), referencedMessageId, Convert.ToHexString(confirmDatagram));
             _logger.LogDebug(">> sent (udp confirm to {Destination}): refid={RefId}", destination.ToString(), referencedMessageId);
             await _udpClient!.SendAsync(confirmDatagram, destination, cancelToken);
         }
         catch (Exception ex) { _logger.LogWarning(ex, "Failed to send UDP confirm for id {RefId} to {Destination}.", referencedMessageId, destination); } // chybu logujeme
     }


    /// <summary>
    /// TrySendErrorAsync pokusa sa odoslat error spravu serveru.
    /// </summary>
    private async Task TrySendErrorAsync(string errorMessage, CancellationToken cancelToken)
    {
        if (_currentState >= ClientState.End) return;
        if (errorMessage.Length > 100) errorMessage = errorMessage[..100] + "...";
        errorMessage = Regex.Replace(errorMessage, @"[\r\n\x00-\x1f\x7f]", "?");
        string finalDisplayName = _displayName ?? "client";

        if (_transport == TransportType.Tcp && _writer != null)
        {
             string message = $"err from {finalDisplayName} is {errorMessage}";
             try { using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancelToken); cts.CancelAfter(TimeSpan.FromSeconds(1)); _logger.LogDebug("Attempting to send final TCP ERR message."); _logger.LogDebug(">> sent (tcp err attempt): {Message}", message); await _writer.WriteLineAsync(message.AsMemory(), cts.Token); }
             catch (Exception ex) { _logger.LogWarning(ex, "Failed to send final TCP ERR message."); }
        }
        else if (_transport == TransportType.Udp && _udpClient != null && _remoteEndPoint != null)
        {
             byte[] payload = UdpPacketBuilder.CreateErrorPayload(finalDisplayName, errorMessage);
             int nextIdRaw = Interlocked.Increment(ref _nextMessageIdRaw); ushort messageId = (ushort)(nextIdRaw - 1); // generujeme id, ale necakame confirm
             byte[] datagramToSend = UdpPacketBuilder.Serialize(UdpMessageType.Error, messageId, payload);
             try { using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancelToken); cts.CancelAfter(TimeSpan.FromSeconds(1)); _logger.LogDebug("Attempting to send final UDP ERR message (id {MessageId}).", messageId); _logger.LogDebug(">> sent (udp err attempt to {Destination}): id={MessageId}", _remoteEndPoint.ToString(), messageId); await _udpClient.SendAsync(datagramToSend, _remoteEndPoint, cts.Token); }
              catch (Exception ex) { _logger.LogWarning(ex, "Failed to send final UDP ERR message (id {MessageId}).", messageId); }
        }
    }

    /// <summary>
    /// SendByeAsync odosle BYE spravu serveru pocas ukoncenia.
    /// </summary>
    private async Task SendByeAsync(CancellationToken cancelToken)
    {
        if (!string.IsNullOrEmpty(_displayName) && _currentState < ClientState.End) // odosleme len ak mame meno a sme pripojeni
        {
            _logger.LogInformation("Sending BYE message.");
            if (_transport == TransportType.Tcp && _writer != null)
            {
                 string message = $"bye from {_displayName}";
                 try
                 {
                     // pouzijeme kratky timeout
                     using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                     // pouzijeme token z argumentu, ak je to CancellationToken.None, tak kratky timeout nema efekt
                     // ak by bol token zruseny externe, SendMessageTcpAsync by mal vyhodit OperationCanceledException
                     await SendMessageTcpAsync(message, cancelToken.CanBeCanceled ? CancellationTokenSource.CreateLinkedTokenSource(cancelToken, cts.Token).Token : cts.Token);
                 }
                 catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is OperationCanceledException)
                 {
                     // ocakavane vynimky pocas vypnutia, ak sa nepodari odoslat BYE
                     _logger.LogWarning(ex, "Failed to send TCP BYE message during shutdown (expected if connection closed concurrently).");
                 }
            }
            else if (_transport == TransportType.Udp && _udpClient != null && _remoteEndPoint != null)
            {
                 byte[] payload = UdpPacketBuilder.CreateByePayload(_displayName);
                 int nextIdRaw = Interlocked.Increment(ref _nextMessageIdRaw); ushort messageId = (ushort)(nextIdRaw - 1);
                 byte[] datagramToSend = UdpPacketBuilder.Serialize(UdpMessageType.Bye, messageId, payload);
                 try
                 {
                      using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                      await _udpClient.SendAsync(datagramToSend, _remoteEndPoint, cancelToken.CanBeCanceled ? CancellationTokenSource.CreateLinkedTokenSource(cancelToken, cts.Token).Token : cts.Token);
                      _logger.LogDebug(">> sent (udp bye to {Destination}): id={MessageId}", _remoteEndPoint.ToString(), messageId);
                 }
                 catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException || ex is OperationCanceledException)
                 {
                      _logger.LogWarning(ex, "Failed to send UDP BYE message during shutdown (expected if connection closed concurrently).");
                 }
            }
        } else { _logger.LogWarning("Cannot send BYE - missing display name or connection already closed/ended."); }
    }
    
    /// <summary>
    /// StartReplyTimeout spusti casovac pre cakanie na reply spravu pre tcp alebo udp
    /// </summary>
    private void StartReplyTimeout(TimeSpan timeout, CancellationToken linkedToken)
    {
        CancelReplyTimeout(); // zrusime predchadzajuci
        _replyTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(linkedToken);
        _replyTimeoutCts.CancelAfter(timeout);
        _logger.LogDebug("Reply timer started ({Timeout}s).", timeout.TotalSeconds);
    }

    /// <summary>
    /// CancelReplyTimeout zrusi a uvolni aktualny reply casovac.
    /// </summary>
    private void CancelReplyTimeout()
    {
        if (_replyTimeoutCts != null) { _logger.LogDebug("Cancelling active reply timer."); if (!_replyTimeoutCts.IsCancellationRequested) { _replyTimeoutCts.Cancel(); } try { _replyTimeoutCts.Dispose(); } catch { } _replyTimeoutCts = null; }
    }

    /// <summary>
    /// HandleReplyTimeout spracuje vyprsanie reply casovaca, volane z hlavneho loopu.
    /// </summary>
    private void HandleReplyTimeout()
    {
        ClientState stateWhenTimedOut = _currentState;
        if (stateWhenTimedOut != ClientState.AuthPending && stateWhenTimedOut != ClientState.JoinPending) { _logger.LogWarning("Reply timeout detected, but client was not in a waiting state ({State}). Resetting timer.", stateWhenTimedOut); CancelReplyTimeout(); return; } // overime stav
        CancelReplyTimeout(); // potvrdime timeout
        Console.WriteLine($"ERROR: Timeout waiting for server reply (state: {stateWhenTimedOut})"); // informujeme uzivatela
        _logger.LogError("Timeout ({Timeout}s) waiting for server REPLY in state {State}. Initiating shutdown.", DefaultReplyTimeoutDuration.TotalSeconds, stateWhenTimedOut);
        TransitionState(ClientState.Closing); RequestShutdown("Reply timeout"); // koncime podla specifikacie
    }
    
    /// <summary>
    /// HandleProtocolViolationAsync spracuje porusenie protokolu, posle error a inicializuje ukoncenie.
    /// </summary>
    private async Task HandleProtocolViolationAsync(string description, CancellationToken cancelToken)
    {
        if (_currentState >= ClientState.Closing) return;
        Console.WriteLine($"ERROR: Protocol violation - {description}");
        _logger.LogError("Protocol violation: {Description}", description);
        TransitionState(ClientState.Closing);
        await TrySendErrorAsync($"Protocol violation: {description}", CancellationToken.None); // posledny pokus
        RequestShutdown("Protocol violation");
    }

     /// <summary>
     /// IsDuplicateMessage skontroluje, ci prijata udp sprava s danym id je duplicitna.
     /// </summary>
     private bool IsDuplicateMessage(ushort messageId, IPEndPoint source)
     {
         if (_receivedMessageIds.ContainsKey(messageId)) // pouzijeme concurrentdictionary
         {
             _logger.LogWarning("Duplicate UDP message detected (id {MessageId}) from {Source}. Ignoring payload.", messageId, source);
             _receivedMessageIds[messageId] = DateTime.UtcNow; // aktualizujeme cas
             return true;
         }
         else { _receivedMessageIds.TryAdd(messageId, DateTime.UtcNow); return false; } // pridame nove id
     }

     /// <summary>
     /// CleanupReceivedIds metoda volana casovacom na precistenie starych zaznamov o prijatych udp id.
     /// </summary>
     private void CleanupReceivedIds(object? state)
     {
         var cutoff = DateTime.UtcNow.AddMinutes(-10); // hranica pre stare zaznamy
         var keysToRemove = _receivedMessageIds.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList();
         if (keysToRemove.Count > 0)
         {
             _logger.LogDebug("Cleaning up {Count} old received UDP message ID records.", keysToRemove.Count);
             foreach (var key in keysToRemove) { _receivedMessageIds.TryRemove(key, out _); }
         }
     }
     
    /// <summary>
    /// TransitionState je prechod medzi stavmi klienta, loguje zmenu.
    /// </summary>
    private void TransitionState(ClientState newState)
    {
        if (_currentState == newState) return; // ziadna zmena
        ClientState previousState = _currentState; _currentState = newState;
        _logger.LogDebug("State changed: {OldState} -> {NewState}", previousState, newState);
        if ((previousState == ClientState.AuthPending || previousState == ClientState.JoinPending) && newState != ClientState.AuthPending && newState != ClientState.JoinPending) { CancelReplyTimeout(); } // zrusime reply casovac
        if ((newState == ClientState.End || newState == ClientState.Disconnected) && _shutdownCts != null && !_shutdownCts.IsCancellationRequested) { _logger.LogInformation("Reached terminal state ({State}), ensuring shutdown is requested.", newState); RequestShutdown("Reached terminal state"); } // zaistime shutdown
    }

    /// <summary>
    /// RequestShutdown vyziaduje ukoncenie aplikacie cez cancellationtokensource.
    /// </summary>
    private void RequestShutdown(string reason = "Unknown")
    {
        _logger.LogInformation("Requesting shutdown. Reason: {Reason}", reason);
        if (_shutdownCts != null && !_shutdownCts.IsCancellationRequested) { _shutdownCts.Cancel(); } // zrusime token
        if (_udpReaderCts != null && !_udpReaderCts.IsCancellationRequested) { _udpReaderCts.Cancel(); } // zrusime aj udp citaci token
    }

    /// <summary>
    /// HandleCancelKeyPress checkuje udalost console.cancelkeypress (ctrl+c).
    /// </summary>
    private void HandleCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        _logger.LogInformation("Ctrl+C detected. Requesting graceful shutdown via host.");
        e.Cancel = true; // zabranime os ukoncit proces hned
        // StopAsync sa teraz pokusi odoslat BYE pred cistenim
        _appLifetime.StopApplication();
    }

    /// <summary>
    /// CleanUpNetworkResources uvolni sietove zdroje
    /// </summary>
    private void CleanUpNetworkResources()
    {
        _logger.LogDebug("Cleaning up network resources...");

        // Pokus o odoslanie BYE na zaciatku cistenia
        _logger.LogDebug("Attempting to send BYE from CleanUpNetworkResources...");
        using (var byeCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300)))
        {
            try
            {
                // spustime a pockame velmi kratko, spoliehame sa na error handling v SendByeAsync
                var byeTask = Task.Run(() => SendByeAsync(byeCts.Token), byeCts.Token);
                byeTask.Wait(TimeSpan.FromMilliseconds(200), CancellationToken.None);
            }
            catch(Exception ex)
            {
                 _logger.LogTrace(ex, "Ignoring exception during brief wait for SendByeAsync in cleanup.");
            }
        }

        // a na koniec pokracujem s cistenim
        TransitionState(ClientState.End); // finalny stav
        CancelReplyTimeout(); // zrusime casovace
        _cleanupTimer?.Dispose(); _cleanupTimer = null;

        // zrusime cakajuce potvrdenia
        var pendingIds = _pendingConfirmations.Keys.ToList();
        foreach(var id in pendingIds) { if (_pendingConfirmations.TryRemove(id, out var pending)) { try { pending.TimeoutCts.Cancel(); } catch { } try { pending.TimeoutCts.Dispose(); } catch { } } }
        _pendingConfirmations.Clear();

        // bezpecne zatvorime a uvolnime sietove objekty
        try { _writer?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during StreamWriter dispose."); }
        try { _reader?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during StreamReader dispose."); }
        try { _networkStream?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during NetworkStream dispose."); }
        try { _tcpClient?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during TcpClient dispose."); }
        try { _udpClient?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during UdpClient dispose."); }
        try { _replyTimeoutCts?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during ReplyTimeoutCts dispose."); }
        try { _udpReaderCts?.Dispose(); } catch (Exception ex) { _logger.LogTrace(ex, "Exception during UdpReaderCts dispose."); }

        // oznacime cakanie ako ukoncene
        if (!_userInputs.IsAddingCompleted) _userInputs.CompleteAdding();
        if (!_tcpNetworkMessages.IsAddingCompleted) _tcpNetworkMessages.CompleteAdding();

        // vynulujeme referencie
        _writer = null; _reader = null; _networkStream = null; _tcpClient = null; _udpClient = null;
        _logger.LogDebug("Network resources cleanup finished.");
    }
    
    /// <summary>
    /// PrintHelp vypise napovedu pre prikazy.
    /// </summary>
    private static void PrintHelp()
    {
        Console.WriteLine("\n--- IPK25-CHAT Client Help ---");
        Console.WriteLine("Commands (enter text starting with /):");
        Console.WriteLine("  /auth <Username> <Secret> <DisplayName> - Authenticate with the server.");
        Console.WriteLine("  /join <ChannelID>                   - Join a specific chat channel.");
        Console.WriteLine("  /rename <DisplayName>                 - Change your display name locally.");
        Console.WriteLine("  /help                               - Display this help message.");
        Console.WriteLine("------------------------------\n");
    }
}

/// <summary>
/// UdpMessageType definuje typy udp sprav podla specifikacie.
/// </summary>
public enum UdpMessageType : byte
{
    Confirm = 0x00, Reply = 0x01, Authenticate = 0x02, JoinChannel = 0x03, Message = 0x04, Ping = 0xFD, Error = 0xFE, Bye = 0xFF
}

/// <summary>
/// UdpPacketBuilder dava spravy do udp datagramov.
/// </summary>
public static class UdpPacketBuilder
{
    private static readonly Encoding Ascii = Encoding.ASCII;
    
    public static byte[] Serialize(UdpMessageType type, ushort messageId, byte[] udpMessageBody)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        writer.Write((byte)type); writer.Write(IPAddress.HostToNetworkOrder((short)messageId)); writer.Write(udpMessageBody);
        return ms.ToArray();
    }
    
    // dava confirm spravu, len hlavicku
    public static byte[] SerializeConfirm(ushort referencedMessageId)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        writer.Write((byte)UdpMessageType.Confirm); writer.Write(IPAddress.HostToNetworkOrder((short)referencedMessageId));
        return ms.ToArray();
    }
    
    // vytvori payload pre auth spravu
    public static byte[] CreateAuthPayload(string username, string displayName, string secret)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        WriteStringz(writer, username); WriteStringz(writer, displayName); WriteStringz(writer, secret);
        return ms.ToArray();
    }
    
    // vytvori payload pre join spravu
    public static byte[] CreateJoinPayload(string channelId, string displayName)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        WriteStringz(writer, channelId); WriteStringz(writer, displayName);
        return ms.ToArray();
    }
    
    // vytvori payload pre msg spravu
    public static byte[] CreateMessagePayload(string displayName, string content)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        WriteStringz(writer, displayName); WriteStringz(writer, content);
        return ms.ToArray();
    }
    
     // vytvori payload pre error spravu
    public static byte[] CreateErrorPayload(string displayName, string content) { return CreateMessagePayload(displayName, content); }
    
    // vytvori payload pre bye spravu
    public static byte[] CreateByePayload(string displayName)
    {
        using var ms = new MemoryStream(); using var writer = new BinaryWriter(ms, Ascii);
        WriteStringz(writer, displayName);
        return ms.ToArray();
    }

    // ukoncenie nulou
    private static void WriteStringz(BinaryWriter writer, string value) { byte[] bytes = Ascii.GetBytes(value); writer.Write(bytes); writer.Write((byte)0); }
}

/// <summary>
/// UdpPacketParser parsuje ipk25-chat spravy z udp datagramov.
/// </summary>
public static class UdpPacketParser
{
    private static readonly Encoding Ascii = Encoding.ASCII;
    
    // pokusi sa parsovat udp a tcp hlavicku
    public static bool TryParseHeader(byte[] receivedDatagram, out UdpMessageType type, out ushort messageId)
    {
        type = default; messageId = default; if (receivedDatagram == null || receivedDatagram.Length < 3) return false;
        using var ms = new MemoryStream(receivedDatagram); using var reader = new BinaryReader(ms, Ascii);
        try { type = (UdpMessageType)reader.ReadByte(); messageId = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()); return true; }
        catch { return false; }
    }
    
    // pokusi sa parsovat payload reply spravy
    public static bool TryParseReply(byte[] receivedDatagram, out bool wasSuccess, out ushort refId, out string messageText)
    {
        wasSuccess = false; refId = 0; messageText = string.Empty; if (receivedDatagram == null || receivedDatagram.Length < 7) return false; // min dlzka
        using var ms = new MemoryStream(receivedDatagram); using var reader = new BinaryReader(ms, Ascii);
        try { reader.BaseStream.Position = 3; wasSuccess = reader.ReadByte() == 1; refId = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()); messageText = ReadStringz(reader); return true; }
        catch { return false; }
    }

     // pokusi sa parsovat payload msg spravy
    public static bool TryParseMessage(byte[] receivedDatagram, out string senderDisplayName, out string messageText)
    {
        senderDisplayName = string.Empty; messageText = string.Empty; if (receivedDatagram == null || receivedDatagram.Length < 5) return false; // min dlzka
        using var ms = new MemoryStream(receivedDatagram); using var reader = new BinaryReader(ms, Ascii);
        try { reader.BaseStream.Position = 3; senderDisplayName = ReadStringz(reader); messageText = ReadStringz(reader); return true; }
        catch { return false; }
    }
    
     // pokusi sa parsovat payload error spravy
    public static bool TryParseError(byte[] receivedDatagram, out string senderDisplayName, out string messageText) { return TryParseMessage(receivedDatagram, out senderDisplayName, out messageText); }

     // pokusi sa parsovat payload bye spravy
    public static bool TryParseBye(byte[] receivedDatagram, out string senderDisplayName)
    {
        senderDisplayName = string.Empty; if (receivedDatagram == null || receivedDatagram.Length < 4) return false; // min dlzka
        using var ms = new MemoryStream(receivedDatagram); using var reader = new BinaryReader(ms, Ascii);
        try { reader.BaseStream.Position = 3; senderDisplayName = ReadStringz(reader); return true; }
        catch { return false; }
    }

    // citanie retazca ukonceneho nulou
    private static string ReadStringz(BinaryReader reader)
    {
        var bytes = new List<byte>(); byte currentByte;
        while (reader.BaseStream.Position < reader.BaseStream.Length && (currentByte = reader.ReadByte()) != 0) { bytes.Add(currentByte); }
        // ak narazime na koniec streamu pred null terminatorom, moze to byt chyba, ale vratime co mame
        return Ascii.GetString(bytes.ToArray());
    }
}
