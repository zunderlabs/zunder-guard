using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class ZunderNative {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int info,IntPtr data,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint id);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
  [StructLayout(LayoutKind.Sequential)] struct Basic { public long processTime,jobTime;public uint flags;public UIntPtr minimum,maximum;public uint active;public UIntPtr affinity;public uint priority,scheduling; }
  [StructLayout(LayoutKind.Sequential)] struct Counters { public ulong read,write,other,readBytes,writeBytes,otherBytes; }
  [StructLayout(LayoutKind.Sequential)] struct Extended { public Basic basic;public Counters counters;public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime {public uint low,high;}
  [StructLayout(LayoutKind.Sequential)] struct FileInfo {public uint attributes;public FileTime creation,access,write;public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
  public static void SingleLink(string path) {using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){FileInfo info;if(!GetFileInformationByHandle(file.SafeFileHandle,out info)||info.links!=1)throw new InvalidOperationException("Linked private file");}}
  static IntPtr ownedJob=IntPtr.Zero;
  public static void OwnControllerJob() {
    if(ownedJob!=IntPtr.Zero)throw new InvalidOperationException("Job already admitted");
    IntPtr job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Win32Exception();
    Extended info=new Extended();info.basic.flags=0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
    IntPtr data=Marshal.AllocHGlobal(Marshal.SizeOf<Extended>());
    try {Marshal.StructureToPtr(info,data,false);if(!SetInformationJobObject(job,9,data,(uint)Marshal.SizeOf<Extended>())||!AssignProcessToJobObject(job,Process.GetCurrentProcess().Handle))throw new Win32Exception();ownedJob=job;job=IntPtr.Zero;}
    finally {Marshal.FreeHGlobal(data);if(job!=IntPtr.Zero)CloseHandle(job);}
    // Deliberately retained until kernel process teardown: closing it terminates
    // this controller and every descendant. Receipt writing precedes teardown.
  }
  public static void SuspendOwned(int pid) {
    using(Process process=Process.GetProcessById(pid)) {
      foreach(ProcessThread thread in process.Threads) {
        IntPtr handle=OpenThread(0x0002,false,(uint)thread.Id);if(handle==IntPtr.Zero)throw new Win32Exception();
        try{if(SuspendThread(handle)==0xffffffff)throw new Win32Exception();}finally{CloseHandle(handle);}
      }
    }
  }
  public static bool InteractiveLogon(string user,string password) {
    IntPtr token;if(!LogonUser(user,".",password,2,0,out token))throw new Win32Exception();
    try{return token!=IntPtr.Zero;}finally{if(token!=IntPtr.Zero)CloseHandle(token);}
  }
  static async Task<string> Drain(StreamReader reader) {
    char[] buffer=new char[4096];var value=new System.Text.StringBuilder();int count;
    while((count=await reader.ReadAsync(buffer,0,buffer.Length))>0){if(value.Length+count>2097152)throw new InvalidOperationException("Native output bound");value.Append(buffer,0,count);}
    return value.ToString();
  }
  public static string Execute(string exe,string[] words,byte[] input,int timeout) {
    var info=new ProcessStartInfo(exe);info.UseShellExecute=false;info.CreateNoWindow=true;
    foreach(string word in words)info.ArgumentList.Add(word);
    info.RedirectStandardOutput=true;info.RedirectStandardError=true;info.RedirectStandardInput=true;
    using(var child=new Process()){child.StartInfo=info;if(!child.Start())throw new InvalidOperationException();
      try{Task<string> output=Drain(child.StandardOutput),error=Drain(child.StandardError);
        if(input!=null)child.StandardInput.BaseStream.Write(input,0,input.Length);child.StandardInput.Close();
        if(!child.WaitForExit(timeout*1000))throw new InvalidOperationException("Native command deadline");
        if(!Task.WaitAll(new Task[]{output,error},5000)||child.ExitCode!=0)throw new InvalidOperationException("Native command refused");
        return output.Result;
      }finally{if(!child.HasExited){child.Kill(true);if(!child.WaitForExit(5000))throw new InvalidOperationException("Native children survive");}}
    }
  }
  public static Process StartOwned(string exe,string[] words) {
    var info=new ProcessStartInfo(exe);info.UseShellExecute=false;info.CreateNoWindow=true;
    foreach(string word in words)info.ArgumentList.Add(word);
    info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
    var child=new Process();child.StartInfo=info;if(!child.Start())throw new InvalidOperationException();child.StandardInput.Close();
    Task<string> output=Drain(child.StandardOutput),error=Drain(child.StandardError);
    foreach(Task<string> task in new[]{output,error})task.ContinueWith(failed=>{try{if(!child.HasExited)child.Kill(true);}catch{}},TaskContinuationOptions.OnlyOnFaulted);
    return child;
  }
  public static byte[] ReadDuplicateFrames() {
    byte[] bytes=new byte[130];Stream input=Console.OpenStandardInput();int at=0;
    try{while(at<bytes.Length){Task<int> read=input.ReadAsync(bytes,at,bytes.Length-at);if(!read.Wait(10000)||read.Result==0)throw new InvalidOperationException("Bounded native frame missing");at+=read.Result;}
      byte[] extra=new byte[1];Task<int> eof=input.ReadAsync(extra,0,1);if(!eof.Wait(10000)||eof.Result!=0)throw new InvalidOperationException("Trailing private frame");
      for(int n=0;n<64;n++){byte b=bytes[n];bool hex=(b>=(byte)'0'&&b<=(byte)'9')||(b>=(byte)'a'&&b<=(byte)'f')||(b>=(byte)'A'&&b<=(byte)'F');if(!hex||b!=bytes[n+65])throw new InvalidOperationException("Duplicate bounded frame differs");}
      if(bytes[64]!=10||bytes[129]!=10)throw new InvalidOperationException("Private LF frame required");return bytes;
    }catch{Array.Clear(bytes,0,bytes.Length);throw;}
  }
  public static string Fingerprint(byte[] frames,bool binary) {
    byte[] value=new byte[binary?32:64];
    try{for(int n=0;n<64;n++){byte b=frames[n];if(b>=65&&b<=70)b+=32;if(!binary)value[n]=b;else{int digit=b<=57?b-48:b-87;if(n%2==0)value[n/2]=(byte)(digit<<4);else value[n/2]|=(byte)digit;}}
      using(SHA256 hash=SHA256.Create())return Convert.ToHexString(hash.ComputeHash(value)).ToLowerInvariant();
    }finally{Array.Clear(value,0,value.Length);}
  }
}
