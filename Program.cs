using System;
using System.Net;
using DnsClient;
using McMaster.Extensions.CommandLineUtils;
using System.Linq;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;
using System.Net.Security;
using DnsClient.Protocol;
using System.IO;
using SslLabsLib;
using SslLabsLib.Enums;
using SslLabsLib.Objects;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace Bitfrickler.CheckCert
{
    public class Host
    {
        public string Name { get; set; }
        public string DnsServer { get; set; }
        public List<EndPoint> EndPoints { get; set; }
    }

    public class EndPoint
    {
        public string IPAddress { get; set; }
        public X509Certificate2 Certificate { get; set; }
    }

    public static class ExtensionMethods
    {
        public static IEnumerable<string> GetSubjectAlternativeNames(this X509Certificate2 certificate)
        {
            Regex sanRex = new Regex(@"^DNS-Name=(.*)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

            var sanList = from X509Extension ext in certificate.Extensions
                        where ext.Oid.Value.Equals("2.5.29.17")
                        let data = new AsnEncodedData(ext.Oid, ext.RawData)
                        let text = data.Format(true)
                        from line in text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        let match = sanRex.Match(line)
                        where match.Success && match.Groups.Count > 0 && !string.IsNullOrEmpty(match.Groups[1].Value)
                        select match.Groups[1].Value;

            return sanList;
        }
    }

    class Program
    {
        static List<string> _dnsServers = null;
        static List<string> _hostnames = null;

        [Option("-h|--hostname")]
        [Required]
        static string Hostname { get; set; }
        
        [Option("-d|--dns-server")]
        [Required]
        static string DnsServer { get; set; }

        [Option("-s|--ssl-scan")]
        static bool SslScan { get; set; }

        [Option("-c|--use-cache")]
        static bool UseCache { get; set; }

        public static int Main(string[] args) => CommandLineApplication.Execute<Program>(args);

        private void OnExecute()
        {
            _hostnames = Hostname.Split(",".ToCharArray()).ToList();
            _dnsServers = DnsServer.Split(",".ToCharArray()).ToList();

            foreach(string hostname in _hostnames)
            {
                foreach(string dnsServer in _dnsServers)
                {
                    var host = _getHostInfo(hostname, dnsServer);

                    _printResult(host);
                }

                if(SslScan)
                {
                    Console.WriteLine();
                    Console.WriteLine($"Analyzing security via SslLabs...");

                    Analysis analysis = _getSslLabsResult(hostname, UseCache);

                    Console.WriteLine($"Grade (via SslLabs): {analysis.Endpoints[0].Grade}");
                }
            }

            //Console.ReadLine();
        }

        private void _printResult(Host host)
        {
            Console.WriteLine();
            Console.WriteLine($"Resolved host(s): {host.Name} via DNS server {host.DnsServer}:");

            Console.WriteLine();

            if(host.EndPoints.Count() == 0)
            {
                Console.WriteLine("HOST NOT FOUND");
            }

            foreach(EndPoint endpoint in host.EndPoints)
            {                
                Console.WriteLine($"IP address: {endpoint.IPAddress}");

                Console.WriteLine();
                if(endpoint.Certificate == null)
                {
                    Console.WriteLine($"NO CERTIFICATE AVAILABLE");
                }
                else
                {
                    Console.WriteLine($"Certificate:");
                    Console.WriteLine($"Subject: {endpoint.Certificate.Subject}");

                    Console.WriteLine("Subject alternative names:");
                    endpoint.Certificate.GetSubjectAlternativeNames().ToList().ForEach(s => Console.WriteLine($"\t{s}"));

                    Console.WriteLine($"Issuer: {endpoint.Certificate.Issuer}");
                    Console.WriteLine($"Serial number: {endpoint.Certificate.SerialNumber}");
                    Console.WriteLine($"Thumbprint: {endpoint.Certificate.Thumbprint}");
                    
                    if(endpoint.Certificate.NotBefore > DateTime.Now)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                    }
                    
                    Console.WriteLine($"Not before: {endpoint.Certificate.NotBefore.ToString("yyyy-MM-dd hh:mm:ss")}");
                    Console.ResetColor();
                    
                    if(endpoint.Certificate.NotAfter < DateTime.Now)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                    }

                    Console.WriteLine($"Not after: {endpoint.Certificate.NotAfter.ToString("yyyy-MM-dd hh:mm:ss")}");
                    Console.ResetColor();

                    Console.WriteLine($"Signature algorithm: {endpoint.Certificate.SignatureAlgorithm.FriendlyName}");
                }
            }
        }

        private Host _getHostInfo(string hostname, string dnsServer)
        {
            var host = _resolveName(hostname, dnsServer);

            host = _getCertificates(host);

            return host;
        }

        private Host _resolveName(string name, string dnsServer)
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(dnsServer), 53);
            var dns = new LookupClient(endpoint);
            
            dns.UseCache = false;
            
            var query = dns.Query(name, QueryType.A);

            var resolvedName = new Host {
                Name = name,
                DnsServer = dnsServer
            };

            resolvedName.EndPoints = new List<EndPoint>();

            foreach(ARecord record in query.Answers.ARecords())
            {
                resolvedName.EndPoints.Add( new EndPoint { IPAddress = record.Address.ToString() });
            }           

            return resolvedName;
        }

        private Host _getCertificates(Host host)
        {
            host.EndPoints.ForEach( e => 
            {
                var client = new TcpClient(e.IPAddress, 443);

                var certValidation = new RemoteCertificateValidationCallback(delegate (object snd,
                            X509Certificate certificate, X509Chain chainLocal, SslPolicyErrors sslPolicyErrors)
                {
                    return true;
                });
            
                using (var sslStream = new SslStream(client.GetStream(), true, certValidation))
                {
                    try
                    {
                        sslStream.AuthenticateAsClient(host.Name);

                        e.Certificate = new X509Certificate2(sslStream.RemoteCertificate);
                    }
                    catch(IOException) {}
                }
            });

            return host;
        }

        private static Analysis _getSslLabsResult(string host, bool useCache)
        {
            SslLabsClient labs = new SslLabsClient();

            Analysis analysis = null;

            if(useCache)
            {
                analysis = labs.GetAnalysisBlocking(host, 24, AnalyzeOptions.FromCache);
            }
            else 
            {
                analysis = labs.GetAnalysisBlocking(host, 24, AnalyzeOptions.StartNew);
            }
            
            return analysis;
        }
    }
}
