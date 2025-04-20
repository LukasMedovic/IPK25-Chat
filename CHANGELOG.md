# Changelog: ipk25-chat Klient (C#)

## [v1] - Prvotny plan
* Vytvorena zakladna struktura projektu (.NET Host).
* Nastavene spracovanie prikazovych riadkov (CLI argumenty).
* Nakonfigurovane logovanie (`Microsoft.Extensions.Logging`) na `stderr`.
* Pripravena hlavna trieda `ChatService` ako `IHostedService`.

## [v2] - TCP Pripojenie a FSM Automat
* Implementovana metoda `ConnectTcpServerAsync` pre TCP spojenia.
* Definovanene zakladne stavy stavoveho automatu (`Disconnected`, `Connecting`, `Start`).
* Nastavene TCP streamy (`StreamReader`, `StreamWriter`).

## [v3] - TCP Komunikacia - prijmanie
* Implementovany loop `ReadTcpMessagesLoopAsync` pre citanie riadkov z TCP streamu.
* Pridana `BlockingCollection` (`_tcpNetworkMessages`) a `ProcessNetworkQueueAsync` na spracovanie prijatych sprav.
* Implementovana metoda `HandleServerMessageAsync` na parsovanie a spracovanie TCP sprav (REPLY, MSG, ERR, BYE).

## [v4] - TCP Komunikacia - odosielanie
* Implementovana metoda `SendMessageTcpAsync` pre odosielanie formatovanych sprav cez TCP.
* Pridane metody pre odosielanie specifickych sprav (`SendAuthenticationRequestAsync`, `SendJoinRequestAsync`, `SendChatMessageAsync`.

## [v5] - TCP Prikazy a FSM Automat
* Implementovane spracovanie uzivatelskych prikazov (`/auth`, `/join`, `/rename`, `/help`) a odosielanie chat sprav v `HandleUserInputAsync`.
* Dokoncena logika stavoveho automatu pre TCP (`AuthPending`, `Open`, `JoinPending`).
* Pridany casovac (`_replyTimeoutCts`) a logika (`StartReplyTimeout`, `HandleReplyTimeout`) pre cakanie na `REPLY` spravy Auth a Join.

## [v6] - TCP Ukoncenie
* Implementovany handler `HandleCancelKeyPress` pre `Ctrl+C`.
* Pridany prvy pokus o odoslanie `BYE` spravy v `SendByeAsync` pre TCP pri ukonceni.
* *Poznamka:* Az pri finalnom testovani sa ukazalo, ze toto pociatocne riesenie malo problemy s casovanim (race condition) a BYE sa nie vzdy odoslalo.

## [v7] - Pridanie Zakladov UDP
* Rozsirene CLI argumenty o `-d` (timeout) a `-r` (retries).
* Pridany enum `TransportType` na rozlisenie TCP/UDP.
* Implementovana metoda `SetupUdpClientAsync` pre inicializaciu `UdpClient`.
* Upravena `StartAsync` logika pre vyber medzi TCP a UDP.

## [v8] - Oprava UDP Bind
* **Opravena chyba:** Aplikacia padala pri starte UDP (`InvalidOperationException`), pretoze chybalo explicitne volanie `_udpClient.Client.Bind()` pred `ReceiveAsync`. Doplnene do `SetupUdpClientAsync`.

## [v9] - UDP Citanie a Parsovanie
* Implementovany loop `ReadUdpMessagesLoopAsync` pre citanie UDP datagramov.
* Vytvorene pomocne triedy `UdpPacketBuilder` a `UdpPacketParser` pre pracu s binarnym formatom UDP sprav.
* Implementovana metoda `HandleRawUdpDatagramAsync` na zakladne spracovanie prijateho UDP datagramu.

## [v10] - UDP Spolahlivost (Confirm, Retry, Timeout)
* Implementovana metoda `SendMessageUdpWithConfirmationAsync` pre odosielanie UDP sprav, ktore vyzaduju potvrdenie.
* Implementovana metoda `SendUdpDatagramAsync` pre odoslanie a planovanie timeoutu.
* Pridana logika pre sledovanie cakajucich sprav (`_pendingConfirmations`).
* Implementovana metoda `HandleConfirmMessage` pre spracovanie prijateho `CONFIRM`.
* Implementovane metody `CheckAndHandleUdpConfirmationTimeoutsAsync` a `HandleUdpConfirmationTimeoutAsync` pre detekciu timeoutu a opakovane odoslanie (`retry`).

## [v11] - UDP Spolahlivost (Duplikaty, Cleanup)
* Implementovana metoda `IsDuplicateMessage` s pouzitim `ConcurrentDictionary` (`_receivedMessageIds`) na detekciu a ignorovanie duplicitnych UDP sprav.
* Pridany `Timer` (`_cleanupTimer`) a metoda `CleanupReceivedIds` na odstranovanie starych zaznamov o prijatych ID.

## [v12] - Oprava UDP Message ID
* **Opravena chyba:** Identifikovany a **opraveny** zavazny problem s nespravnym (nesekvencnym) cislovanim odchadzajucich UDP `MessageID`. Predchadzajuce pokusy o opravu (`lock`, property) boli neuspesne. Finalne riesenie pouziva `Interlocked.Increment(ref _nextMessageIdRaw)` priamo v metodach, ktore generuju novu spravu (`SendMessageUdpWithConfirmationAsync`, `TrySendErrorAsync`, `SendByeAsync`).

## [v13] - Integracia UDP do Prikazov
* Upravene metody `HandleAuthCommandAsync`, `HandleJoinCommandAsync`, `SendChatMessageAsync`, `TrySendErrorAsync`, `SendByeAsync`, aby pouzivali podmienku `if (_transport == ...)` a volali spravnu logiku pre TCP alebo UDP.

## [v14] - Refaktoring Logiky pre UDP a TCP
* Vytvorene spolocne metody `HandleReplyLogic`, `HandleMessageLogic`, `HandleErrorLogic`, `HandleByeLogic` na zdielanie logiky spracovania sprav medzi TCP a UDP variantom, kde to bolo mozne.

## [v15] - Diagnostika UDP REPLY (NAT/VPN)
* **Rieseny problem:** UDP klient nedostaval `REPLY` spravy od referencneho servera `anton5`, aj ked `CONFIRM` na `AUTH` presiel. Timeout cakania na `REPLY` vzdy vyprsal.
* **Diagnostika:** Pridane detailne logovanie. Testovanie pomocou jednoducheho lokalneho Python UDP servera ukazalo, ze klient **dokaze** prijat `REPLY` z dynamickeho portu.
* **Zaver:** Problem bol identifikovany ako **sietovy problem suvisiaci s NAT/firewallom**, ktory blokuje prichadzajuce UDP pakety na dynamicky port servera. Informacia potvrdena aj na diskusnom fore IPK.
* **Workaround:** Pre uspesne testovanie UDP voci `anton5` je potrebne pouzit **VPN (napr. FIT VPN)** alebo sa pripojit zo skolskej siete.

## [v16] - Finalna Oprava TCP Ctrl+C
* **Opravena chyba:** Vyrieseny pretrvavajuci problem s neodosielanim `BYE` spravy pri ukonceni cez `Ctrl+C` v TCP. Logika bola presunuta z `HandleCancelKeyPress` do `CleanUpNetworkResources`, ktora sa vola pocas `StopAsync`. Pokus o odoslanie `BYE` sa teraz deje na zaciatku cistenia s kratkym timeoutom.

## [v17] - Finalizacia a Cistenie
* Finalne upravy kodu pre itatelnost.
* Uprava vsetkych komentarov.
* Finalizacia `README.md` a `Changelog.md`.
