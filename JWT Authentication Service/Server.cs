using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace JWT_Authentication_Service
{
    public class Server
    {
        private string ERRORED = "";

        private HttpListener _httpListener;
        private Authenticator auth = new Authenticator("2Develop&Beyond!");

        public void Go(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Port parameter required");
                return;
            }
            var ip = GetLocalIPAddress();
            if (ip == ERRORED)
            {
                Console.WriteLine("Local IP address not found");
                return;
            }
            
            _httpListener = new HttpListener();
            var host = "http://" + ip + ":" + args[0] + "/";
            _httpListener.Prefixes.Add(host);
            _httpListener.Start();
            new Thread(ListenToRequests).Start();
            Console.WriteLine("Hosting server at " + host);
        }

        private void ListenToRequests()
        {
            while (true)
            {
                HttpListenerContext context = _httpListener.GetContext();
                new Thread(() => ResponseToRequest(context)).Start();
            }
        }

        private void ResponseToRequest(HttpListenerContext context)
        {
            Console.WriteLine("Incoming request from " + context.Request.RemoteEndPoint.ToString());
            var x = auth.Authenticate(context.Request.Headers.Get("Authorization"));
            Console.WriteLine(x.Item1.ToString());
            if(x.Item2 != null)
                Console.Write(x.Item2.ToString());
            context.Response.StatusCode = 204;
            context.Response.OutputStream.Write(new byte[0], 0, 0);
            context.Response.KeepAlive = false;
            context.Response.Close();
            Console.WriteLine("Request Finished");
        }

        private bool IsDigitsOnly(string str)
        {
            foreach (char c in str)
                if (c < '0' || c > '9')
                    return false;
            return true;
        }

        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    return ip.ToString();
            return ERRORED;
        }
    }
}
