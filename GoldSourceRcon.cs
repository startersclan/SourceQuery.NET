using System;
public class GoldSourceRcon
{
    public GoldSourceRcon(string address, int port, string rconPassword, int debugFlag = 0) {
        Console.Out.WriteLine("Sending GoldSourceRcon to {0}:{1}", address, port);

        var remoteEP = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(address), port);

        udpClient = new System.Net.Sockets.UdpClient();
        udpClient.Client.SendTimeout = 500;
        udpClient.Client.ReceiveTimeout = 500;
        udpClient.Connect(remoteEP);

        rcon_password = rconPassword;
        debug = debugFlag;
    }

    // UDP Socket Properties
    private System.Net.IPEndPoint remoteEP;
    private System.Net.Sockets.UdpClient udpClient;
    private System.Text.Encoding enc = System.Text.Encoding.UTF8;

    // Rcon Protocol Properties
    private int challengeID  = 0;
    private string rcon_password;

    // Debug
    private int debug;

    // Methods
    private byte[] BuildPacket(string command) {
        byte[] head = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
        byte[] body = enc.GetBytes(command + Char.MinValue);
        byte[] pack = new byte[head.Length + body.Length];
        System.Buffer.BlockCopy(head, 0, pack, 0, head.Length);
        System.Buffer.BlockCopy(body, 0, pack, head.Length, body.Length);
        if ((debug & 1) == 1) { Console.WriteLine("[BuildPacket] head: " + enc.GetString(head)); }
        if ((debug & 1) == 1) { Console.WriteLine("[BuildPacket] body: " + enc.GetString(body)); }
        if ((debug & 1) == 1) { Console.WriteLine("[BuildPacket] pack: " + enc.GetString(pack)); }
        return pack;
    }
    private void SendPacket(byte[] pack) {
        if ((debug & 1) == 1) { Console.WriteLine("[SendPacket] " + enc.GetString(pack)); }
        udpClient.Send(pack, pack.Length);
    }
    private byte[] ReceivePacket() {
        byte[] pack = udpClient.Receive(ref remoteEP);
        if ((debug & 1) == 1) { Console.WriteLine("[ReceivePacket] " + enc.GetString(pack)); }
        return pack;
    }
    private string GetResponse(byte[] pack) {
        if ((debug & 1) == 1) { Console.WriteLine("[GetResponse]"); }
        if (pack.Length > 5) {
            int numItems = pack.Length - 5;
            byte[] body = new byte[numItems];
            System.Buffer.BlockCopy(pack, 5, body, 0, numItems);
            var response = enc.GetString(body);
            return response;
        }
        return "";
    }
    private int InitGetChallenge() {
        if ((debug & 1) == 1) { Console.WriteLine("[InitGetChallenge]"); }
        var pack = BuildPacket("challenge rcon\n");
        var response = SendReceive(pack);
        var match = System.Text.RegularExpressions.Regex.Match(response, @"(\d+)");
        if (match.Success) {
            challengeID = int.Parse(match.Groups[1].Value);
        }
        return challengeID;
    }
    private string SendReceive(byte[] pack) {
        SendPacket(pack);
        var rPack = ReceivePacket();
        var response = GetResponse(rPack);
        return response;
    }
    public string Command(string command) {
        string response = "";
        try {
            if (challengeID == 0) {
                challengeID = InitGetChallenge();
                if ((debug & 1) == 1) { Console.WriteLine("[Command] Got challengeID: " + challengeID); }
            }else {
                if ((debug & 1) == 1) { Console.WriteLine("[Command] Using existing challengeID: " + challengeID); }
            }
            if (challengeID > 0) {
                var pack = BuildPacket(String.Format("rcon {0} {1} {2}", challengeID, rcon_password, command));
                response = SendReceive(pack);
            }
        }catch(Exception ex) {
            challengeID = 0;
            throw ex;
        }
        return response;
    }
}