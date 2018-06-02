using System;
public class SourceRcon
{
    public SourceRcon(string address, int port, string rconPassword, int debugFlag = 0) {
        Console.Out.WriteLine("Sending SourceRcon to {0}:{1}", address, port);

        // Set up TCP socket
        tcpClient = new System.Net.Sockets.TcpClient();
        tcpClient.Client.SendTimeout = 500;
        tcpClient.Client.ReceiveTimeout = 500;

        // Connect the TCP Socket (Async yet sync) - Now there's a socket timeout
        var result = tcpClient.BeginConnect(System.Net.IPAddress.Parse(address), port, null, null);
        bool success = result.AsyncWaitHandle.WaitOne(System.TimeSpan.FromSeconds(2));
        if (!success) {
            throw new Exception(String.Format("Could not connect to remote host: {0}:{1}", address, port));
        }
        if (!tcpClient.Connected) {
            throw new Exception(String.Format("Could not connect to remote host: {0}:{1}", address, port));
        }

        // Set up Network stream
        stream = tcpClient.GetStream();
        stream.ReadTimeout = 500;
        stream.WriteTimeout = 500;

        // Set rcon properties
        rcon_password = rconPassword;

        debug = debugFlag;
    }

    // TCP Socket Properties
    private System.Net.Sockets.TcpClient tcpClient;
    private System.Text.Encoding enc = System.Text.Encoding.UTF8;
    // TCP Client Network stream Property
    private System.Net.Sockets.NetworkStream stream;

    // Rcon Protocol Properties
    private const int SERVERDATA_AUTH = 3;
    private const int SERVERDATA_EXECCOMMAND = 2;
    private const int SERVERDATA_AUTH_RESPONSE = 2;
    private const int SERVERDATA_RESPONSE_VALUE = 0;
    private int auth = 0;
    private int packetID_Auth = 1;
    private int packetID = 10;
    private string rcon_password;

    // Debug
    private int debug;

    // Methods
    private byte[] IntToBytes (int integer) {
        byte[] bytes = BitConverter.GetBytes(integer);
        if (!BitConverter.IsLittleEndian) {
            Array.Reverse(bytes);
        }
        return bytes;
    }
    private int BytesToInt32(byte[] bytes) {
        return BitConverter.ToInt32(bytes, 0);
    }
    private byte[] BuildPacket(int ID, int TYPE, string BODY) {
        byte[] packID = IntToBytes(ID);
        byte[] packTYPE = IntToBytes(TYPE);
        byte[] packBODY = enc.GetBytes(BODY + Char.MinValue + Char.MinValue);
        byte[] packEND = { 0x00 };

        int size = packID.Length + packTYPE.Length + packBODY.Length + packEND.Length;
        byte[] packSIZE = IntToBytes(size);
        if ((debug & 2) == 2) { Console.WriteLine("[BuildPacket] SIZE: " + BytesToInt32(packSIZE)); }
        if ((debug & 2) == 2) { Console.WriteLine("[BuildPacket] ID: " + BytesToInt32(packID)); }
        if ((debug & 2) == 2) { Console.WriteLine("[BuildPacket] TYPE: " + BytesToInt32(packTYPE)); }
        if ((debug & 2) == 2) { Console.WriteLine("[BuildPacket] BODY: " + enc.GetString(packBODY)); }
        if ((debug & 2) == 2) { Console.WriteLine(String.Format("[BuildPacket] packSIZE.Length: {0}, packID.Length: {1}, packTYPE.Length: {2}, packBODY.Length: {3}, packEND.Length: {4}", packSIZE.Length, packID.Length, packTYPE.Length, packBODY.Length, packEND.Length)); }
        byte[] pack = new byte[packSIZE.Length + size];
        System.Buffer.BlockCopy(packSIZE, 0, pack, 0, packSIZE.Length);
        System.Buffer.BlockCopy(packID, 0, pack, packSIZE.Length, packID.Length);
        System.Buffer.BlockCopy(packTYPE, 0, pack, packSIZE.Length + packID.Length, packTYPE.Length);
        System.Buffer.BlockCopy(packBODY, 0, pack, packSIZE.Length + packID.Length + packTYPE.Length, packBODY.Length);
        System.Buffer.BlockCopy(packEND, 0, pack, packSIZE.Length + packID.Length + packTYPE.Length + packBODY.Length, packEND.Length);
        return pack;
    }
    private void SendPacket(byte[] pack) {
        if ((debug & 1) == 1) { Console.WriteLine( String.Format("[SendPacket] size: {0}, pack: {1}", pack.Length, enc.GetString(pack)) ); }
        stream.Write(pack, 0, pack.Length);
    }
    private byte[] ReceivePacket(int packetSize) {
        byte[] pack = new byte[packetSize];
        var memStream = new System.IO.MemoryStream();
        var bytes = 0;
        if ((debug & 1) == 1) { Console.WriteLine("[ReceivePacket](in)"); }
        do {
            try {
                bytes = stream.Read(pack, 0, pack.Length);
                memStream.Write(pack, 0, bytes);
                if ((debug & 1) == 1) { Console.WriteLine( String.Format("[ReceivePacket] bytes: {0}, pack: {1}, length: {2}", bytes, enc.GetString(pack), pack.Length) ); }
                if (bytes > 0) {
                    break;
                }
            }catch (System.IO.IOException ex) {
                var socketExept = ex.InnerException as System.Net.Sockets.SocketException;
                if (socketExept == null || socketExept.ErrorCode != 10060) {
                    throw ex;
                }
            }catch {
                throw;
            }
        }while(bytes > 0);
        memStream.Dispose();
        return pack;
    }
    private byte[] GetBytesRange(byte[] bytes, int start, int end) {
        byte[] range = new byte[end-start+1];
        if ((debug & 1) == 2) { Console.WriteLine(String.Format("[GetBytesRange] Length: {0}, start: {1}, rangesize: {2}", bytes.Length, start, end-start+1)); }
        System.Buffer.BlockCopy(bytes, start, range, 0, range.Length);
        return range;
    }
    private System.Collections.Hashtable ParsePacket(byte[] pack) {
        return new System.Collections.Hashtable() {
            { "Size", BytesToInt32(GetBytesRange(pack, 0, 3)) },
            { "Id", BytesToInt32(GetBytesRange(pack, 4, 7)) },
            { "Type", BytesToInt32(GetBytesRange(pack, 8, 11)) },
            { "Body", enc.GetString(GetBytesRange(pack, 12, pack.Length-1)) },
            { "Bytes", pack }
        };
    }
    private int Auth() {
        var pack = BuildPacket(packetID_Auth, SERVERDATA_AUTH, rcon_password);
        SendPacket(pack);
        var emptyPack = ReceivePacket(4+10);
        var authPack = ReceivePacket(4+10);
        int ID = BytesToInt32( GetBytesRange(authPack, 4, 7) );
        return ID;
    }
    private string SendReceive(string command) {
        var multipack = 0;
        packetID++;
        var pack = BuildPacket(packetID, SERVERDATA_EXECCOMMAND, command);
        SendPacket(pack);
        var rPack = ReceivePacket(4096);
        if (rPack.Length == 0) {
            return "";
        }

        var mainPacket = ParsePacket(rPack);
        if ((debug & 1) == 1) { Console.WriteLine( String.Format("[first]\nreceived body: {0} \nsize: {1} \nend: {2}", (string)mainPacket["Body"], (int)mainPacket["Size"], BytesToInt32(GetBytesRange((byte[])mainPacket["Bytes"], 12, 15))) ); }
        string body = ((string)mainPacket["Body"]).Trim();

        // Always send one dummy empty response packet to determine if there's multipack
        if (multipack == 0) {
            pack = BuildPacket(packetID, SERVERDATA_RESPONSE_VALUE, "");
            SendPacket(pack);
            rPack = ReceivePacket(4+10);
            var pollPacket = ParsePacket(rPack);
            if ((debug & 1) == 1) { Console.WriteLine( String.Format("[dummy]\nreceived body: {0} \nsize: {1}", (string)pollPacket["Body"], (int)pollPacket["Size"]) ); }
            if ((int)mainPacket["Size"] > 10) {
                // The last two bytes are actually the start of the multipack
                multipack = 1;
                body += enc.GetString( GetBytesRange((byte[])pollPacket["Bytes"], 12, 13) );
            }
        }

        // Only for multipack cases
        if (multipack > 0) {
            string body_continued = "";
            while (multipack > 0) {
                try {
                    rPack = ReceivePacket(4096);
                    var multiPack = ParsePacket(rPack);
                    if ( BytesToInt32(GetBytesRange((byte[])multiPack["Bytes"], 12, 15)) == 256 ) {
                        if ((debug & 1) == 1) { Console.WriteLine("No more multipack!"); }
                        break;
                    }
                    body_continued = enc.GetString(rPack);
                    body += body_continued.Trim();
                    if ((debug & 1) == 1) { Console.WriteLine("Continued:`n {0}", body_continued); }
                }catch {
                    if ((debug & 1) == 1) { Console.WriteLine("No more packets."); }
                    break;
                }
            }
        }
        return body;
    }
    public string Command(string command) {
        string response = "";
        try {
            if (auth == 0) {
                var success = Auth();
                if (success > 0) {
                    auth = 1;
                }
            }
            if (auth == 0) {
                throw new Exception("Bad rcon password.");
            }else {
                if ((debug & 1) == 1) { Console.WriteLine("[Command] Auth: " + auth); }
                response = SendReceive(command);
            }
        }catch {
            throw;
        }
        return response;
    }
}