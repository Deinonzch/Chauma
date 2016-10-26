using System;
using System.ComponentModel;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace ServerClient
{
    public partial class Form1 : Form
    {
        private TcpClient client;
        public StreamReader STR;
        public StreamWriter STW;
        public string receive;
        public string text_to_send;
        public string message;
        public RSAParameters RSAKeyInfo;
        public long publicKeyE;
        public long publicKeyN;
        public long w;
        public long step;
        private bool getE = false;
        private bool getN = false;
        private bool podpis = false;
        private bool odkrycie = false;
        long mess;
        long Z;
        long Y;
        long S;

        public Form1()
        {
            InitializeComponent();

            IPAddress[] localIP = Dns.GetHostAddresses(Dns.GetHostName());      //get my own IP
            foreach (IPAddress address in localIP)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    textBox4.Text = address.ToString();
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)      //start server
        {
            TcpListener listener = new TcpListener(IPAddress.Any, int.Parse(textBox3.Text));
            listener.Start();
            textBox2.AppendText("The server is running at port:" + textBox3.Text + "\n");
            client = listener.AcceptTcpClient();
            STR = new StreamReader(client.GetStream());
            STW = new StreamWriter(client.GetStream());
            STW.AutoFlush = true;

            backgroundWorker1.RunWorkerAsync(); //start receiving data
            backgroundWorker2.WorkerSupportsCancellation = true; //Ability to cancel this thread
        }

        private void button3_Click(object sender, EventArgs e)
        {
            client = new TcpClient();
            IPEndPoint IP_End = new IPEndPoint(IPAddress.Parse(textBox5.Text), int.Parse(textBox6.Text));

            try
            {
                client.Connect(IP_End);
                if(client.Connected)
                {
                    textBox2.AppendText("Connected to server" + "\n");
                    STW = new StreamWriter(client.GetStream());
                    STR = new StreamReader(client.GetStream());
                    STW.AutoFlush = true;

                    backgroundWorker1.RunWorkerAsync(); //start receiving data
                    backgroundWorker2.WorkerSupportsCancellation = true; //Ability to cancel this thread
                }
            }
            catch (Exception x)
            {
                MessageBox.Show(x.Message.ToString());
            }
        }

        private void button1_Click(object sender, EventArgs e)  //Send button
        {
            if(textBox1.Text != "")
            {
                text_to_send = textBox1.Text;
                backgroundWorker2.RunWorkerAsync();
            }           
            textBox1.Text = "";
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e) //receive data
        {
            while (client.Connected)
            {
                try
                {
                    receive = STR.ReadLine();
                    if (receive == "s")
                    {
                        step = 0;
                        //generacja kluczy
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSAKeyInfo = RSA.ExportParameters(true);
                        //wysłanie E
                        step = 1;
                        STW.WriteLine(step.ToString());
                        StringBuilder en = new StringBuilder();
                        foreach (byte b in RSAKeyInfo.Exponent.ToString())
                            en.Append(b.ToString("X2"));
                        STW.WriteLine(en.ToString());
                        //wysłanie N
                        step = 2;
                        STW.WriteLine(step.ToString());
                        StringBuilder n = new StringBuilder();
                        foreach (byte b in RSAKeyInfo.Modulus.ToString())
                            n.Append(b.ToString("X2"));
                        STW.WriteLine(n.ToString());
                    }
                    //Dostanie E
                    if (getE == true)
                    {
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Jestem w GetE\n"); }));
                        byte[] publicKeyEByte = GetBytes(receive);
                        publicKeyE = BitConverter.ToInt32(publicKeyEByte, 0);
                        getE = false;
                    }

                    if (receive == "1")
                    {
                        getE = true;
                    }
                    //Dostanie N
                    if (getN == true)
                    {
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Jestem w GetN\n"); }));
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(receive + "\n"); }));
                        byte[] publicKeyNByte = GetBytes(receive);
                        publicKeyN = BitConverter.ToInt32(publicKeyNByte, 0);
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(publicKeyN.ToString() + "\n"); }));
                        //Losowanie w
                        w = GetW(publicKeyN);
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(w.ToString() + "\n"); }));
                        getN = false;
                        //Ustala M
                        long M = 262952750;
                        mess = M;
                        Z = M*Oblicz(w,publicKeyE,publicKeyN);
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(Z.ToString() + "\n"); }));
                        step = 3;
                        STW.WriteLine(step.ToString());
                        STW.WriteLine(Z.ToString());
                    }                

                    if (receive == "2")
                    {
                        getN = true;
                    }

                    //podpis
                    if (podpis == true)
                    {
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Jestem w Podpisie\n"); }));
                        Z = long.Parse(receive);
                        StringBuilder en = new StringBuilder();
                        foreach (byte b in RSAKeyInfo.D.ToString())
                            en.Append(b.ToString("X2"));
                        byte[] publicKeyDByte = GetBytes(en.ToString());
                        StringBuilder n = new StringBuilder();
                        foreach (byte b in RSAKeyInfo.Modulus.ToString())
                            n.Append(b.ToString("X2"));
                        byte[] publicKeyNByte = GetBytes(n.ToString());
                        long D = BitConverter.ToInt32(publicKeyDByte, 0);
                        long N = BitConverter.ToInt32(publicKeyNByte, 0);
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(D.ToString() + "\n"); }));
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(N.ToString() + "\n"); }));
                        Y = Oblicz(Z, D, N);
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(Y.ToString() + "\n"); }));
                        step = 4;
                        STW.WriteLine(step.ToString());
                        STW.WriteLine(Y.ToString());
                        podpis = false;
                    }

                    if (receive == "3")
                    {
                        podpis = true;
                    }

                    //Odkrycie
                    if (odkrycie == true)
                    {
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Jestem w Odkryciu\n"); }));
                        Y = long.Parse(receive);
                        S = (Y / w) % publicKeyN;
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(Z.ToString() + "\n"); }));
                        this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(S.ToString() + "\n"); }));
                        long spr = Oblicz(S, publicKeyE, publicKeyN);
                        if (spr == mess)
                        {
                            this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Ok: " + mess + " : " + spr + "\n"); }));
                        }
                        else
                        {
                            this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText("Wrong: " + mess + " : " + spr + "\n"); }));
                        }
                        odkrycie = false;
                    }

                    if (receive == "4")
                    {
                        odkrycie = true;
                    }
                }
                catch (Exception x)
                {
                    MessageBox.Show(x.Message.ToString());
                }
            }
        }

        private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e) //send data
        {
            if (client.Connected)
            {
                STW.WriteLine(text_to_send);
                this.textBox2.Invoke(new MethodInvoker(delegate () { textBox2.AppendText(text_to_send + "\n"); }));
            }
            else
            {
                MessageBox.Show("Send failed!");
            }
            backgroundWorker2.CancelAsync();
        }

        public static long GetW(long inputInt)
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAKeyInfo = RSA.ExportParameters(true);
            long w = BitConverter.ToInt32(RSAKeyInfo.P, 0);
            while ((inputInt < w || w < 1))
            {
                RSA = new RSACryptoServiceProvider();
                RSAKeyInfo = RSA.ExportParameters(true);
                w = BitConverter.ToInt32(RSAKeyInfo.P, 0);
            }
            return w;
        }

        public static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static long Oblicz(long w, long e, long n)
        {
            long wynik=0;
            long dlugosc = e.ToString().Length;
            long[] liczba2 = new long[dlugosc];
            for(int i = 0; i<dlugosc; i++)
            {
                liczba2[i] = e % 2;
            }
            for(long j = dlugosc-1; j>-1; j--)
            {
                if(j==dlugosc-1)
                    wynik = w % n;
                else
                {
                    if(liczba2[j] == 0)
                    {
                        wynik = (wynik * wynik) % n;
                    }
                    if (liczba2[j] == 1)
                    {
                        wynik = (((wynik * wynik) % n ) * wynik) % n;
                    }
                }

            }
            return wynik;
        }
    }
}