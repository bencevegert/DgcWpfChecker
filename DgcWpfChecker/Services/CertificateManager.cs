using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DGC;
using DGCValidator.Services.CWT.Certificates;
using DGCValidator.Services.DGC.ValueSet;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.X509;
using X509CertNet = System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;



namespace DGCValidator.Services
{
    /**
     * An implementation for finding certificates that may be used to verify a HCERT (see {@link HCertVerifier}).
     * 
     * @author Henrik Bengtsson (henrik@sondaica.se)
     * @author Martin Lindström (martin@idsec.se)
     * @author Henric Norlander (extern.henric.norlander@digg.se)
     */
    public class CertificateManager : ICertificateProvider
    {
        private readonly IRestService _restService;
        public static Dictionary<string, ValueSet> ValueSets { get; private set; }
        public static DSC_TL TrustList { get; private set; }
        private readonly string TrustListFileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DscTrustList.json");
        private readonly string ValueSetPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        public string ATJson { get; private set; }
        public static Dictionary<string, string> ATDictionary { get; private set; }
        public CertificateManager(IRestService service)
        {
            _restService = service;
        }
        public async Task RefreshTrustListAsync(string pUrl)
        {
            DSC_TL trustList = await _restService.RefreshTrustListAsync(pUrl);
            if (trustList != null && trustList.DscTrustList != null && trustList.DscTrustList.Count > 0 && trustList.Exp > GetSecondsFromEpoc())
            {
                trustList.DscTrustList = trustList.DscTrustList.OrderBy(x => x.Key).ToDictionary(x => x.Key, x => x.Value);
                TrustList = trustList;
            }
        }

        public async Task<string> RefreshTrustListATAsync(string pUrl)
        {
            var trustList = await _restService.RefreshTrustListAsyncAT(pUrl);
            ATJson = trustList;
            ATDictionary = JsonConvert.DeserializeObject<List<JObject>>(trustList).ToDictionary(x => x.Last.First.ToString(), y => y.First.Last.ToString());
            return trustList;
        }


        public async Task RefreshValueSetsAsync()
        {
            if (ValueSets == null)
            {
                ValueSets = new Dictionary<string, ValueSet>();
            }
            Dictionary<string, string> valueSets = await _restService.RefreshValueSetAsync();
            if (valueSets != null && valueSets.Keys != null && valueSets.Keys.Count > 0)
            {
                foreach (KeyValuePair<string, string> entry in valueSets)
                {
                                        ValueSets[entry.Key] = ValueSet.FromJson(entry.Value);
                }
            }
        }

        private long GetSecondsFromEpoc()
        {
            return DateTimeOffset.Now.ToUnixTimeSeconds();
        }

        public List<AsymmetricKeyParameter> GetCertificates(string country, byte[] kid)
        {
            List<AsymmetricKeyParameter> publicKeys = new List<AsymmetricKeyParameter>();

            // No TrustList means no keys to match with
            if (TrustList == null)
            {
                return publicKeys;
            }

            List<DscTrust> trusts = new List<DscTrust>();
            if (country != null)
            {
                DscTrust dscTrust;

                TrustList.DscTrustList.TryGetValue(country, out dscTrust);
                if (dscTrust != null)
                {
                    trusts.Add(dscTrust);
                }
            }
            else
            {
                trusts.AddRange(TrustList.DscTrustList.Values);
            }

            foreach (DscTrust trust in trusts)
            {
                foreach (Key key in trust.Keys)
                {
                    string kidStr = Convert.ToBase64String(kid)
                        .Replace('+', '-')
                        .Replace('/', '_');
                    if (kid == null || key.Kid == null || key.Kid.Equals(kidStr))
                    {

                        if (key.Kty.Equals("EC"))
                        {
                            X9ECParameters x9 = ECNamedCurveTable.GetByName(key.Crv);
                            ECPoint point = x9.Curve.CreatePoint(Base64UrlDecodeToBigInt(key.X), Base64UrlDecodeToBigInt(key.Y));

                            ECDomainParameters dParams = new ECDomainParameters(x9);
                            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, dParams);
                            publicKeys.Add(pubKey);
                        }
                        else if (key.Kty.Equals("RSA"))
                        {
                            RsaKeyParameters pubKey = new RsaKeyParameters(false, Base64UrlDecodeToBigInt(key.N), Base64UrlDecodeToBigInt(key.E));
                            publicKeys.Add(pubKey);
                        }
                    }
                }
            }
            return publicKeys;
        }

        public List<AsymmetricKeyParameter> GetCertificatesAT(string pKid)
        {
            List<AsymmetricKeyParameter> vPublicKeys = new List<AsymmetricKeyParameter>();

            // No TrustList means no keys to match with
            if (ATDictionary == null) return vPublicKeys;

            pKid = pKid?.Replace('+', '-').Replace('/', '_').Replace("=", "");
            //string kidStr = Convert.ToBase64String(kid).Replace('+', '-').Replace('/', '_').Replace("=", "");

            ATDictionary.TryGetValue(pKid, out var vCertData);

            if (vCertData != null)
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                //builder.AppendLine(vCertData);
                builder.AppendLine(vCertData.Replace('-', '+').Replace('_', '/'));
                //Convert.ToBase64String(x5c, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");

                var pemString = builder.ToString();
                byte[] pemBytes = Encoding.ASCII.GetBytes(pemString);
                X509CertNet.X509Certificate2 x = new X509CertNet.X509Certificate2(pemBytes);
                
                //Make bouncyCastle cert, and after public key from cert
                var parser = new X509CertificateParser();
                X509Certificate bouncyCertificate = parser.ReadCertificate(x.GetRawCertData());
                var publicKey = bouncyCertificate.GetPublicKey();
                vPublicKeys.Add(publicKey);

            }
            return vPublicKeys;
        }

        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPEM(X509CertNet.X509Certificate2 cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509CertNet.X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        internal BigInteger Base64UrlDecodeToBigInt(String value)
        {
            value = value.Replace('-', '+');
            value = value.Replace('_', '/');
            switch (value.Length % 4)
            {
                case 0: break;
                case 2: value += "=="; break;
                case 3: value += "="; break;
                default:
                    throw new Exception("Illegal base64url string!");
            }
            return new BigInteger(1, Convert.FromBase64String(value));
        }
    }
}
