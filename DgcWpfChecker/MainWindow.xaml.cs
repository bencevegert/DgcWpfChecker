using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using DGC;
using DGCValidator.Services;
using DGCValidator.Services.CWT.Certificates;
using DGCValidator.Services.DGC.ValueSet;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.X509;
using PeterO.Cbor;
using Key = DGCValidator.Services.CWT.Certificates.Key;
using Path = System.IO.Path;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace WpfApp12
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        public static CertificateManager CertificateManager { get; private set; }

        public MainWindow()
        {
            InitializeComponent();
            BtnGetKeysATClick(this, null);
            BtnGetKeysSWClick(this, null);

            CbQrCodes.ItemsSource = ReadAllQrCodes();
            CbQrCodes.SelectedIndex = 0;

            BtnAnalyzeClick(this, null);
        }

        private CWT CreateCWT()
        {
            var tests = new List<TestEntry>
            {
                //new TestEntry
                //{
                //    CountryOfTest = "AT",
                //    TestName = "",
                //    TestNameAndManufacturer = "1333",
                //    Disease = "840539006",
                //    SampleTakenDate = new DateTimeOffset(2021,06,18,11,52,48,0,TimeSpan.Zero),
                //    Issuer = "Ministry of Health, Austria",
                //    CertificateIdentifier = "URN:UVCI:01:AT:DW4UM9G5KCGYS0LVJRSB91BAG#P",
                //    TestResult = "260415000",
                //    TestType = "LP217198-3",
                //    TestingCenter = "Bären-Apotheke"
                //}
            };

            var vacs = new List<VaccinationEntry>
            {
                new VaccinationEntry
                {
                    Issuer = "Ministry of Health, Austria",
                    CertificateIdentifier = "URN:UVCI:01:AT:DRRBJRSQVXW9XBZLMA3YWXGD8#1",
                    CountryOfVaccination = "AT",
                    Disease = "840539006",
                    TotalDoses = 2,
                    DoseNumber = 2,
                    Vaccine = "J07BX03",
                    Manufacturer = "ORG-100031184",
                    MedicalProduct = "EU/1/20/1507",
                    VaccinationDate = new DateTimeOffset(2021,05,18,0,0,0,0,TimeSpan.Zero)
                }
            };

            CWT cwt = new CWT();
            cwt.DGCv1 = new DgCertificate
            {
                Version = "1.0.0",
                DateOfBirth = new DateTimeOffset(1947, 11, 2, 0, 0, 0, TimeSpan.Zero),
                Name = new Nam
                {
                    FamilyName = "Tischer",
                    GivenName = "Ernst",
                    FamilyNameTransliterated = "TISCHER",
                    GivenNameTraslitaerated = "ERNST"
                },
                Test = tests.ToArray(),
                Vaccination = vacs.ToArray()
            };

            cwt.ExpiarationTime = new DateTime(2022, 05, 13, 22, 00, 00);
            cwt.IssueAt = new DateTime(2021, 06, 19, 14, 24, 42);
            cwt.Issuer = "AT";
            return cwt;
        }

        private List<QrEntry> ReadAllQrCodes()
        {
            List<QrEntry> qrs = new List<QrEntry>();
            var files = Directory.GetFiles(System.IO.Path.Combine(Environment.CurrentDirectory,"QRs"), "*.txt");
            foreach (var vFile in files)
            {
                var vContent = File.ReadAllText(vFile).Replace(Environment.NewLine,"");
                QrEntry qr = new QrEntry()
                {
                    Name = Path.GetFileName(vFile),
                    Qr = vContent,
                };
                qrs.Add(qr);
            }
            return qrs;
        }

        private async void BtnGetKeysSWClick(object pSender, RoutedEventArgs pE)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                CertificateManager = new CertificateManager(new RestService());
                var vUrl = TbPublicKeyUrlSW.Text;
                await CertificateManager.RefreshTrustListAsync(vUrl);
                var vJsonString = DSC_TLSerialize.ToJson(CertificateManager.TrustList);

                JsonCerts.Load(vJsonString);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }

        }

        private void BtnCheckSWCertsClick(object sender, RoutedEventArgs e)
        {
            try
            {

                var vOutputStr = string.Empty;

                foreach (var trust in CertificateManager.TrustList.DscTrustList)
                {

                    foreach (Key key in trust.Value.Keys)
                    {
                        string vKeyText = string.Empty;

                        if (key.Kty.Equals("EC"))
                        {
                            X9ECParameters x9 = ECNamedCurveTable.GetByName(key.Crv);
                            ECPoint point = x9.Curve.CreatePoint(CertificateManager.Base64UrlDecodeToBigInt(key.X), CertificateManager.Base64UrlDecodeToBigInt(key.Y));

                            ECDomainParameters dParams = new ECDomainParameters(x9);
                            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, dParams);
                            vKeyText = pubKey.ToString();
                        }
                        else if (key.Kty.Equals("RSA"))
                        {
                            RsaKeyParameters pubKey = new RsaKeyParameters(false, CertificateManager.Base64UrlDecodeToBigInt(key.N), CertificateManager.Base64UrlDecodeToBigInt(key.E));
                            vKeyText = pubKey.ToString();
                        }

                        vOutputStr += string.Format("{0}: {1}", key.Kid, vKeyText) + Environment.NewLine;

                    }


                    //byte[] x5c = Encoding.UTF8.GetBytes(cert.Value.Keys);

                    //using (var readCertStream = new MemoryStream(x5c))
                    //{
                    //    readCertStream.Position = 0;


                    //    string vKeyText = string.Empty;
                    //    try
                    //    {
                    //        System.Security.Cryptography.X509Certificates.X509Certificate vCertificate =
                    //            new System.Security.Cryptography.X509Certificates.X509Certificate(x5c);

                    //        //Make bouncyCastle cert, and after public key from cert
                    //        var parser = new X509CertificateParser();
                    //        X509Certificate bouncyCertificate = parser.ReadCertificate(vCertificate.GetRawCertData());

                    //        AsymmetricKeyParameter publicKey = bouncyCertificate.GetPublicKey();

                    //        vKeyText = publicKey.ToString();
                    //    }
                    //    catch (Exception ex)
                    //    {
                    //        vKeyText = ex.ToString();


                    //    }
                    //    vOutputStr += string.Format("{0}: {1}", cert.Key, vKeyText) + Environment.NewLine;
                    //}

                    TbPublicKeys.Text = vOutputStr;

                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }


        private async void BtnGetKeysATClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                CertificateManager = new CertificateManager(new RestService());
                var vUrl = TbPublicKeyUrlAT.Text;
                var vJson = await CertificateManager.RefreshTrustListATAsync(vUrl);
                JsonCerts.Load(vJson);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        //private void BtnAnalyzeAndVerifyClick(object sender, RoutedEventArgs e)
        //{
        //    try
        //    {
        //        if (CertificateManager?.TrustList == null)
        //        {
        //            MessageBox.Show("Please take the public keys first!");
        //            return;
        //        }

        //        Mouse.OverrideCursor = Cursors.Wait;

        //        var vCwt = DecodeQrAndMapDataToUi();

        //        //when try with other public key, the result is wrong
        //        //var vEncodedTextBytes = Convert.FromBase64String("MrT00mhDxLQ=");

        //        List<AsymmetricKeyParameter> certs = CertificateManager.GetCertificates(vCwt.Issuer, vCwt.CoseMessage.KIDBytes);
        //        //List<AsymmetricKeyParameter> certs = CertificateManager.GetCertificates("LV", vEncodedTextBytes);

        //        bool vResult = false;
        //        foreach (var vAsymmetricKeyParameter in certs)
        //        {
        //            vResult = vCwt.CoseMessage.VerifySignature(vAsymmetricKeyParameter, vCwt.CoseMessage.ContextSignature1, vCwt.CoseMessage.ProtectedMap, vCwt.CoseMessage.Content, vCwt.CoseMessage.Signature);
        //            if (vResult) break;
        //        }

        //        if (certs.Count == 0)
        //            MessageBox.Show($@"No cert found for KID: {vCwt.CoseMessage.KID}!");
        //        //TbVerifyResult.Text = result.ToString();

        //        resImg.Source = vResult ? new BitmapImage(new Uri(@"pack://application:,,,/yes.png")) : new BitmapImage(new Uri(@"pack://application:,,,/no.png"));

        //        //var res2 = VerificationService.VerifyData(coseBase45);

        //    }
        //    catch (Exception ex)
        //    {
        //        MessageBox.Show(ex.Message);
        //    }
        //    finally
        //    {
        //        Mouse.OverrideCursor = null;
        //    }
        //}

        //private void BtnAnalyzeAndVerifyAtClick(object sender, RoutedEventArgs e)
        //{
        //    try
        //    {
        //        if (String.IsNullOrEmpty(CertificateManager?.ATJson))
        //        {
        //            MessageBox.Show("Please take the AT public keys first!");
        //            return;
        //        }

        //        Mouse.OverrideCursor = Cursors.Wait;

        //        var vCwt = DecodeQrAndGetData();

        //        //when try with other public key, the result is wrong
        //        //var vEncodedTextBytes = Convert.FromBase64String("MrT00mhDxLQ=");

        //        List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificatesAT(vCwt.CoseMessage.KIDBytes);
        //        //List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificates("LV", vEncodedTextBytes);

        //        VerifyAtWay(vCerts, vCwt);

        //        //var res2 = VerificationService.VerifyData(coseBase45);

        //    }
        //    catch (Exception ex)
        //    {
        //        MessageBox.Show(ex.Message);
        //    }
        //    finally
        //    {
        //        Mouse.OverrideCursor = null;
        //    }
        //}

        private CWT _cwt = null;
        private void BtnAnalyzeClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                _cwt = DecodeQrAndMapDataToUi();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void BtnJsonAtClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                //take the original payload
                var vContentBytes = Convert.FromBase64String(TbCosePayload.Text);
                //make cbor
                var cbor = CBORObject.DecodeFromBytes(vContentBytes);
                //make json from cbor
                var vJsonOfTheAllContent = cbor.ToJSONString();

                #region Not equal testing
                //CBORObject vCborObject = CBORObject.FromJSONString(vJsonOfTheAllContent);

                //var modifiedByteArray=vCborObject.EncodeToBytes();
                //var jsonBackToBase64 = Convert.ToBase64String(modifiedByteArray);

                //var isBase64Equal = jsonBackToBase64 == TbCosePayload.Text;
                //var isByteArrayEqual=_cwt.CoseMessage.Content.SequenceEqual(modifiedByteArray);
                //var isJsonEqual=vJsonOfTheAllContent==vCborObject.ToJSONString();

                //var cbor2 = (CBORObject.DecodeFromBytes(modifiedByteArray)).ToJSONString();

                //var cbor3=CBORObject.FromJSONString(cbor2).EncodeToBytes();

                //var ccc=modifiedByteArray.SequenceEqual(cbor3);

                //var item = vJsonOfTheAllContent == cbor2; 
                #endregion

                TbQRObjectData.Text = vJsonOfTheAllContent;
                JsonOriginalQr?.Load(vJsonOfTheAllContent);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void BtnJsonAtBackClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                CBORObject vCborObject = CBORObject.FromJSONString(TbQRObjectData.Text);
                TbCosePayloadModified.Text = Convert.ToBase64String(vCborObject.EncodeToBytes());

                JsonModifiedContent?.Load(TbQRObjectData.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void BtnVerifyAtClick(object sender, RoutedEventArgs e)
        {
            try
            {
                resImg.Source = null;
                var protectedMap = CBORObject.DecodeFromBytes(Convert.FromBase64String(TbProtectedMap.Text));
                var kidBytes = protectedMap[CBORObject.FromObject(4)].GetByteString();
                var vKID = Convert.ToBase64String(kidBytes);
                List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificatesAT(vKID);

                var vContent = Convert.FromBase64String(TbCosePayload.Text);
                var vSignature = Convert.FromBase64String(TbCoseSignature.Text);

                var vRes = Verify(vCerts, _cwt.CoseMessage, protectedMap, vContent, vSignature,true);
                ShowImage(vRes);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }

        }

        private void BtnCheckATCertsClick(object sender, RoutedEventArgs e)
        {
            try
            {

                var vOutputStr = string.Empty;
                
                foreach (var cert in CertificateManager.ATDictionary)
                {

                    byte[] x5c = Encoding.UTF8.GetBytes(cert.Value);

                    using (var readCertStream = new MemoryStream(x5c))
                    {
                        readCertStream.Position = 0;
                        string vKeyText = string.Empty;
                        try
                        {
                            StringBuilder builder = new StringBuilder();
                            builder.AppendLine("-----BEGIN CERTIFICATE-----");
                            //builder.AppendLine(vCertData);
                            builder.AppendLine(cert.Value.Replace('-', '+').Replace('_', '/'));
                            //Convert.ToBase64String(x5c, Base64FormattingOptions.InsertLineBreaks));
                            builder.AppendLine("-----END CERTIFICATE-----");

                            var pemString=builder.ToString();
                            byte[] pemBytes = Encoding.ASCII.GetBytes(pemString);
                            X509Certificate2 x = new X509Certificate2(pemBytes);

                            //System.Security.Cryptography.X509Certificates.X509Certificate vCertificate =
                            //                    new System.Security.Cryptography.X509Certificates.X509Certificate(x5c);
                            //Make bouncyCastle cert, and after public key from cert
                            var parser = new X509CertificateParser();
                            X509Certificate bouncyCertificate = parser.ReadCertificate(x.GetRawCertData());

                            AsymmetricKeyParameter publicKey = bouncyCertificate.GetPublicKey();

                            vKeyText = publicKey.ToString();
                        }
                        catch (Exception ex)
                        {
                            vKeyText = ex.ToString();


                        }
                        vOutputStr += string.Format("{0}: {1}", cert.Key, vKeyText) + Environment.NewLine;
                    }
                    TbPublicKeys.Text = vOutputStr;

                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }


        private void BtnVerifyModifiedJson(object sender, RoutedEventArgs e)
        {
            try
            {
                var protectedMap = CBORObject.DecodeFromBytes(Convert.FromBase64String(TbProtectedMap.Text));
                var kidBytes = protectedMap[CBORObject.FromObject(4)].GetByteString();
                var vKID = Convert.ToBase64String(kidBytes);
                List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificatesAT(vKID);

                //This line is the only different
                var vContent = Convert.FromBase64String(TbCosePayloadModified.Text);
                var vSignature = Convert.FromBase64String(TbCoseSignature.Text);

                var vResult = Verify(vCerts, _cwt.CoseMessage, protectedMap, vContent, vSignature,true);

                ShowImage(vResult);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }


        decimal Counter = 0;
        private bool StopBruteForce = false;

        private async void BtnBruteForceClick(object sender, RoutedEventArgs e)
        {

            try
            {
                btnBruteForce.IsEnabled = false;
                StopBruteForce = false;
                var protectedMap = CBORObject.DecodeFromBytes(Convert.FromBase64String(TbProtectedMap.Text));
                var kidBytes = protectedMap[CBORObject.FromObject(4)].GetByteString();
                var vKID = Convert.ToBase64String(kidBytes);
                List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificatesAT(vKID);

                //This line is the only different
                var vContent = Convert.FromBase64String(TbCosePayloadModified.Text);

                //var vSignature = Convert.FromBase64String(TbCoseSignature.Text);

                TbQRObjectData.Text = "Starting Brute Force!";

                Task<byte[]> vSignature = Task.Run(() => vBruteForce(vCerts, protectedMap, vContent));

                await vSignature;

                if (vSignature.Result != null)
                {
                    TbQRObjectData.Text = Convert.ToBase64String(vSignature.Result);
                }
                else
                {
                    TbQRObjectData.Text = "Brute Force suspended!";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                btnBruteForce.IsEnabled = true;
                Mouse.OverrideCursor = null;
            }
        }

        private async void BtnBruteForceParallelClick(object sender, RoutedEventArgs e)
        {
            try
            {
                btnBruteForceParallel.IsEnabled = false;
                StopBruteForce = false;
                var protectedMap = CBORObject.DecodeFromBytes(Convert.FromBase64String(TbProtectedMap.Text));
                var kidBytes = protectedMap[CBORObject.FromObject(4)].GetByteString();
                var vKID = Convert.ToBase64String(kidBytes);
                List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificatesAT(vKID);

                //This line is the only different
                var vContent = Convert.FromBase64String(TbCosePayloadModified.Text);

                //var vSignature = Convert.FromBase64String(TbCoseSignature.Text);

                TbQRObjectData.Text = "Starting Brute Force Parallel!";

                var tasks = new List<Task>();
                var random = new Random();
                byte[] vSignature = new byte[64];

                var found = false;
                byte[] foundCert = null;

                await Task.Run(() =>
                {
                    while (!found)
                    {
                        random.NextBytes(vSignature);

                        Counter++;
                        if (StopBruteForce)
                        {
                            break;
                        }

                        var t =
                            Task.Run(() => Verify(vCerts, _cwt.CoseMessage, protectedMap, vContent, vSignature))
                                .ContinueWith(x =>
                                {
                                    if (x.Result)
                                    {
                                        found = x.Result;
                                        foundCert = vSignature;
                                    }
                                });

                        tasks.Add(t);

                        if (tasks.Count > Environment.ProcessorCount * 2)
                        {
                            Task.WaitAll(tasks.ToArray());
                            tasks.Clear();
                        }
                    }
                });

                TbQRObjectData.Text = found ?
                    Convert.ToBase64String(foundCert) : "Brute Force suspended!";

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                btnBruteForceParallel.IsEnabled = true;
                Mouse.OverrideCursor = null;
            }
        }

        private byte[] vBruteForce(List<AsymmetricKeyParameter> vCerts, CBORObject protectedMap, byte[] vContent)
        {
            var random = new Random();
            var vSignature = new byte[64];
            random.NextBytes(vSignature);
            Counter = 0;

            while (!Verify(vCerts, _cwt.CoseMessage, protectedMap, vContent, vSignature))
            {
                random.NextBytes(vSignature);
                Counter += 1;

                if (StopBruteForce)
                    return null;
            }

            return vSignature;
        }

        private void BtnShowCounter(object sender, RoutedEventArgs e)
        {
            try
            {
                TbQRObjectData.Text = Counter.ToString();
            }
            catch (Exception ex)
            {
                TbQRObjectData.Text = ex.ToString();
                MessageBox.Show(ex.Message);
            }
            
        }


        private bool Verify(List<AsymmetricKeyParameter> vCerts,
            Sign1CoseMessage pSign1CoseMessage, CBORObject pProtectedMap, byte[] pContent, byte[] pSignature, bool pNeedExpirationChecking=false)
        {
            if (vCerts.Count == 0)
            {
                MessageBox.Show($@"No cert found for KID: {pSign1CoseMessage.KID}!");
                return false;
            }

            bool vResult = false;
            foreach (var vAsymmetricKeyParameter in vCerts)
            {
                vResult = pSign1CoseMessage.VerifySignature(vAsymmetricKeyParameter,
                    pSign1CoseMessage.ContextSignature1,
                    pProtectedMap,
                    pContent, pSignature,pSign1CoseMessage.ProtectedMapBytes);
                if (vResult) break;
            }

            if (pNeedExpirationChecking)
            {
                // OK, before we are done - let's ensure that the HCERT hasn't expired.
               DateTime? expiration = _cwt.ExpiarationTime;
                if (expiration.HasValue)
                {
                    if (DateTime.UtcNow.CompareTo(expiration) >= 0)
                    {
                        MessageBox.Show($"DCC has expired {expiration.Value}");
                        return false;
                    }
                }
            }
            
            return vResult;
        }

        private string MakeStringFromCwt(CWT pCwt)
        {
            var vPayload = pCwt.DGCv1;

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("KID: " + pCwt.CoseMessage.KID);
            sb.AppendLine("Issuer: " + pCwt.Issuer);
            sb.AppendLine("IssueAt: " + pCwt.IssueAt);
            sb.AppendLine("Expiration Time: " + pCwt.ExpiarationTime);


            sb.AppendLine("Version: " + vPayload.Version);
            sb.AppendLine("Family Name: " + vPayload.Name.FamilyName);
            sb.AppendLine("Given Name: " + vPayload.Name.GivenName);
            sb.AppendLine("Family Name Transliterated: " + vPayload.Name.FamilyNameTransliterated);
            sb.AppendLine("Given Name Trasliterated: " + vPayload.Name.GivenNameTraslitaerated);
            sb.AppendLine("Date Of Birth: " + vPayload.DateOfBirth);

            if (vPayload.Vaccination != null && vPayload.Vaccination.Any())
            {
                sb.AppendLine("Vaccination details: ");
                sb.AppendLine("");
                for (var vIndex = 0; vIndex < vPayload.Vaccination.Length; vIndex++)
                {
                    var vVaccinationEntry = vPayload.Vaccination[vIndex];
                    sb.AppendLine("Vaccine data " + vIndex + 1 + ": ");
                    sb.AppendLine("         Issuer: " + vVaccinationEntry.Issuer);
                    sb.AppendLine("         Certificate Identifier: " + vVaccinationEntry.CertificateIdentifier);
                    sb.AppendLine("         Country Of Vaccination: " + vVaccinationEntry.CountryOfVaccination);
                    sb.AppendLine("         Disease: " + vVaccinationEntry.Disease);
                    sb.AppendLine("         Total Doses: " + vVaccinationEntry.TotalDoses);
                    sb.AppendLine("         Dose Number: " + vVaccinationEntry.DoseNumber);
                    sb.AppendLine("         Manufacturer: " + vVaccinationEntry.Manufacturer);
                    sb.AppendLine("         Medical Product: " + vVaccinationEntry.MedicalProduct);
                    sb.AppendLine("         Vaccination Date: " + vVaccinationEntry.VaccinationDate);
                    sb.AppendLine("         Vaccine: " + vVaccinationEntry.Vaccine);
                }
            }

            if (vPayload.Test != null && vPayload.Test.Any())
            {
                sb.AppendLine("Test details: ");
                sb.AppendLine("");
                for (var vIndex = 0; vIndex < vPayload.Test.Length; vIndex++)
                {
                    var vTestEntry = vPayload.Test[vIndex];
                    sb.AppendLine("Test data " + vIndex + 1 + ": ");
                    sb.AppendLine("         Issuer: " + vTestEntry.Issuer);
                    sb.AppendLine("         Certificate Identifier: " + vTestEntry.CertificateIdentifier);
                    sb.AppendLine("         Country Of Test: " + vTestEntry.CountryOfTest);
                    sb.AppendLine("         Disease: " + vTestEntry.Disease);
                    sb.AppendLine("         Sample Taken Date: " + vTestEntry.SampleTakenDate);
                    sb.AppendLine("         Test Name: " + vTestEntry.TestName);
                    sb.AppendLine("         Test Name And Manufacturer: " + vTestEntry.TestNameAndManufacturer);
                    sb.AppendLine("         Test Result: " + vTestEntry.TestResult);
                    sb.AppendLine("         Test Result Date: " + vTestEntry.TestResutDate);
                    sb.AppendLine("         Test Type: " + vTestEntry.TestType);
                    sb.AppendLine("         Testing Center: " + vTestEntry.TestingCenter);
                }
            }

            if (vPayload.Recovery != null && vPayload.Recovery.Any())
            {
                sb.AppendLine("Recovery details: ");
                sb.AppendLine("");
                for (var vIndex = 0; vIndex < vPayload.Recovery.Length; vIndex++)
                {
                    var vRecoveryElement = vPayload.Recovery[vIndex];
                    sb.AppendLine("Recovery data " + vIndex + 1 + ": ");
                    sb.AppendLine("         Issuer: " + vRecoveryElement.Issuer);
                    sb.AppendLine("         Certificate Identifier: " + vRecoveryElement.CertificateIdentifier);
                    sb.AppendLine("         Country Of Test: " + vRecoveryElement.CountryOfTest);
                    sb.AppendLine("         Disease: " + vRecoveryElement.Disease);
                    sb.AppendLine("         First Positive Test Result: " + vRecoveryElement.FirstPositiveTestResult);
                    sb.AppendLine("         Valid From: " + vRecoveryElement.ValidFrom);
                    sb.AppendLine("         Valid Until: " + vRecoveryElement.ValitUntil);
                }
            }

            return sb.ToString();
        }

        private CWT DecodeQrAndMapDataToUi()
        {
            string vCoseBase45 = TbQrCode.Text;
            var vDecoder = new GreenCertificateDecoder();
            CWT vCwt = vDecoder.Decode(vCoseBase45);

            TbQRObjectData.Text = MakeStringFromCwt(vCwt);
            JsonOriginalQr?.Load(vCwt.DGCv1Json);

            var vSign1CoseMessage = vCwt.CoseMessage;
            TbProtectedMap.Text = Convert.ToBase64String(vSign1CoseMessage.ProtectedMapBytes);
            TbCosePayload.Text = Convert.ToBase64String(vSign1CoseMessage.Content);
            TbCoseSignature.Text = Convert.ToBase64String(vSign1CoseMessage.Signature);

            return vCwt;
        }

        private void BtnClearClick(object sender, RoutedEventArgs e)
        {
            TbQrCode.Text = "";
        }

        private void BtnBruteForceStopClick(object sender, RoutedEventArgs e)
        {
            StopBruteForce = true;
        }

        private void BtnVerifySwClick(object sender, RoutedEventArgs e)
        {
            try
            {
                resImg.Source = null;
                var protectedMap = CBORObject.DecodeFromBytes(Convert.FromBase64String(TbProtectedMap.Text));
                var kidBytes = protectedMap[CBORObject.FromObject(4)].GetByteString();
                
                List<AsymmetricKeyParameter> vCerts = CertificateManager.GetCertificates(_cwt.Issuer, kidBytes);
                var vContent = Convert.FromBase64String(TbCosePayload.Text);
                var vSignature = Convert.FromBase64String(TbCoseSignature.Text);
                var vResult = Verify(vCerts, _cwt.CoseMessage, _cwt.CoseMessage.ProtectedMap, vContent, vSignature,true);
                
                //string vCoseBase45 = TbQrCode.Text;
                //var res2 = VerificationService.VerifyData(vCoseBase45);
               
                ShowImage(vResult);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
            
        }

        private void ShowImage(bool vResult)
        {
            resImg.Source = vResult
                ? new BitmapImage(new Uri(@"pack://application:,,,/Resources/yes.png"))
                : new BitmapImage(new Uri(@"pack://application:,,,/Resources/no.png"));
        }


        //private void BtnSWProofClick(object sender, RoutedEventArgs e)
        //{
        //    try
        //    {
        //        TbQRObjectData.Text = string.Empty;

        //        var vCert = CertificateManager.TrustList.DscTrustList.FirstOrDefault(x => x.Key == _cwt.Issuer);
        //        var vCertInfo = vCert.Value.Keys.First(x => x.Kid == _cwt.CoseMessage.KID);

        //        TbQRObjectData.Text = vCert.Key + " : " + vCert.Value.Keys.Length + Environment.NewLine;
        //        TbQRObjectData.Text += vCertInfo.Kid + Environment.NewLine + vCertInfo.Kty;
        //    }
        //    catch (Exception ex)
        //    {
        //        MessageBox.Show(ex.Message);
        //    }
        //    finally
        //    {
        //        Mouse.OverrideCursor = null;
        //    }
        //}
        
        private void CbQrCodes_OnSelectionChanged(object pSender, SelectionChangedEventArgs pE)
        {
            TbQrCode.Text = (CbQrCodes.SelectedItem as QrEntry)?.Qr;
        }
        

        private void CbValueSets_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var json = CertificateManager.ValueSets[(string)cbValueSets.SelectedValue];
            JsonViewerValueSets.Load(json.ToJson());
        }

        private bool Init = true;
        private async void Selector_OnSelectionChanged(object pSender, SelectionChangedEventArgs pE)
        {
            if (TabCertMaker.IsSelected)
            {
                if (Init)
                {
                    await CertificateManager.RefreshValueSetsAsync();
                    cbValueSets.ItemsSource = CertificateManager.ValueSets.Keys;
                    Init = false;
                }
                
            }
        }
    }

    internal class QrEntry
    {
        public string Name { get; set; }
        public string Qr { get; set; }
    }
}
