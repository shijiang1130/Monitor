# ###################################################################################
# 
# Xymon client for Windows
#
# This is a client implementation for Windows systems that support the
# Powershell scripting language.
#
# Copyright (C) 2010 Henrik Storner <henrik@hswn.dk>
# Copyright (C) 2010 David Baldwin
# Copyright (c) 2014-2017 Accenture (zak.beck@accenture.com)
#
#   Contributions to this project were made by Accenture starting from June 2014.
#   For a list of modifications, please see the SVN change log.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# ###################################################################################

# -----------------------------------------------------------------------------------
# User configurable settings
# -----------------------------------------------------------------------------------

$xymonservers = @( "xymonhost" )    # List your Xymon servers here
# $clientname  = "winxptest"    # Define this to override the default client hostname

$xymonsvcname = "XymonPSClient"
$xymondir = split-path -parent $MyInvocation.MyCommand.Definition

# -----------------------------------------------------------------------------------
# adding hyper-v and modify the origal version to 2.35

$Version = '2.34'
$XymonClientVersion = "${Id}: xymonclient.ps1  $Version 2018-12-06 zak.beck@accenture.com"
# detect if we're running as 64 or 32 bit
$XymonRegKey = $(if([System.IntPtr]::Size -eq 8) { "HKLM:\SOFTWARE\Wow6432Node\XymonPSClient" } else { "HKLM:\SOFTWARE\XymonPSClient" })
$XymonClientCfg = join-path $xymondir 'xymonclient_config.xml'
$ServiceChecks = @{}
$MaintChecks = @{}

$UnixEpochOriginUTC = New-Object DateTime 1970,1,1,0,0,0,([DateTimeKind]::Utc)

Add-Type -AssemblyName System.Web

#region dotNETHelperTypes
function AddHelperTypes
{
$getprocessowner = @'
// see: http://www.codeproject.com/Articles/14828/How-To-Get-Process-Owner-ID-and-Current-User-SID
// adapted slightly and bugs fixed
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class GetProcessOwner
{

    public const int TOKEN_QUERY = 0X00000008;

    const int ERROR_NO_MORE_ITEMS = 259;

    enum TOKEN_INFORMATION_CLASS                           
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER
    {
        public _SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [DllImport("advapi32")]
    static extern bool OpenProcessToken(
        IntPtr ProcessHandle, // handle to process
        int DesiredAccess, // desired access to process
        ref IntPtr TokenHandle // handle to open access token
    );

    [DllImport("kernel32")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32", CharSet = CharSet.Auto)]
    static extern bool GetTokenInformation(
        IntPtr hToken,
        TOKEN_INFORMATION_CLASS tokenInfoClass,
        IntPtr TokenInformation,
        int tokeInfoLength,
        ref int reqLength
    );

    [DllImport("kernel32")]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32", CharSet = CharSet.Auto)]
    static extern bool ConvertSidToStringSid(
        IntPtr pSID,
        [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid
    );

    [DllImport("advapi32", CharSet = CharSet.Auto)]
    static extern bool ConvertStringSidToSid(
        [In, MarshalAs(UnmanagedType.LPTStr)] string pStringSid,
        ref IntPtr pSID
    );

    /// <span class="code-SummaryComment"><summary></span>
    /// Collect User Info
    /// <span class="code-SummaryComment"></summary></span>
    /// <span class="code-SummaryComment"><param name="pToken">Process Handle</param></span>
    public static bool DumpUserInfo(IntPtr pToken, out IntPtr SID)
    {
        int Access = TOKEN_QUERY;
        IntPtr procToken = IntPtr.Zero;
        bool ret = false;
        SID = IntPtr.Zero;
        try
        {
            if (OpenProcessToken(pToken, Access, ref procToken))
            {
                ret = ProcessTokenToSid(procToken, out SID);
                CloseHandle(procToken);
            }
            return ret;
        }
        catch //(Exception err)
        {
            return false;
        }
    }

    private static bool ProcessTokenToSid(IntPtr token, out IntPtr SID)
    {
        TOKEN_USER tokUser;
        const int bufLength = 256;            
        IntPtr tu = Marshal.AllocHGlobal(bufLength);
        bool ret = false;
        SID = IntPtr.Zero;
        try
        {
            int cb = bufLength;
            ret = GetTokenInformation(token, 
                    TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);
            if (ret)
            {
                tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof(TOKEN_USER));
                SID = tokUser.User.Sid;
            }
            return ret;
        }
        catch //(Exception err)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(tu);
        }
    }

    public static string GetProcessOwnerByPId(int PID)
    {                                                                  
        IntPtr _SID = IntPtr.Zero;                                       
        string SID = String.Empty;                                             
        try                                                             
        {                                                                
            Process process = Process.GetProcessById(PID);
            if (DumpUserInfo(process.Handle, out _SID))
            {                                                                    
                ConvertSidToStringSid(_SID, ref SID);
            }

            // convert SID to username
            string account = new System.Security.Principal.SecurityIdentifier(SID).Translate(typeof(System.Security.Principal.NTAccount)).ToString();

            return account;                                          
        }                                                                           
        catch
        {                                                                           
            return "Unknown";
        }
    }
}
'@

$type = Add-Type $getprocessowner

$getprocesscmdline = @'
    // ZB adapted from ProcessHacker (http://processhacker.sf.net)
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    public class ProcessInformation
    {
        [DllImport("ntdll.dll")]
        internal static extern int NtQueryInformationProcess(
            [In] IntPtr ProcessHandle,
            [In] int ProcessInformationClass,
            [Out] out ProcessBasicInformation ProcessInformation,
            [In] int ProcessInformationLength,
            [Out] [Optional] out int ReturnLength
            );

        [DllImport("ntdll.dll")]
        public static extern int NtReadVirtualMemory(
            [In] IntPtr processHandle,
            [In] [Optional] IntPtr baseAddress,
            [In] IntPtr buffer,
            [In] IntPtr bufferSize,
            [Out] [Optional] out IntPtr returnLength
            );

        private const int FLS_MAXIMUM_AVAILABLE = 128;
        
        //Win32
        //private const int GDI_HANDLE_BUFFER_SIZE = 34;
        //Win64
        private const int GDI_HANDLE_BUFFER_SIZE = 60;

        private enum PebOffset
        {
            CommandLine,
            CurrentDirectoryPath,
            DesktopName,
            DllPath,
            ImagePathName,
            RuntimeData,
            ShellInfo,
            WindowTitle
        }

        [Flags]
        public enum RtlUserProcessFlags : uint
        {
            ParamsNormalized = 0x00000001,
            ProfileUser = 0x00000002,
            ProfileKernel = 0x00000004,
            ProfileServer = 0x00000008,
            Reserve1Mb = 0x00000020,
            Reserve16Mb = 0x00000040,
            CaseSensitive = 0x00000080,
            DisableHeapDecommit = 0x00000100,
            DllRedirectionLocal = 0x00001000,
            AppManifestPresent = 0x00002000,
            ImageKeyMissing = 0x00004000,
            OptInProcess = 0x00020000
        }

        [Flags]
        public enum StartupFlags : uint
        {
            UseShowWindow = 0x1,
            UseSize = 0x2,
            UsePosition = 0x4,
            UseCountChars = 0x8,
            UseFillAttribute = 0x10,
            RunFullScreen = 0x20,
            ForceOnFeedback = 0x40,
            ForceOffFeedback = 0x80,
            UseStdHandles = 0x100,
            UseHotkey = 0x200
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ListEntry
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Peb
        {
            public static readonly int ImageSubsystemOffset =
                Marshal.OffsetOf(typeof(Peb), "ImageSubsystem").ToInt32();
            public static readonly int LdrOffset =
                Marshal.OffsetOf(typeof(Peb), "Ldr").ToInt32();
            public static readonly int ProcessHeapOffset =
                Marshal.OffsetOf(typeof(Peb), "ProcessHeap").ToInt32();
            public static readonly int ProcessParametersOffset =
                Marshal.OffsetOf(typeof(Peb), "ProcessParameters").ToInt32();

            [MarshalAs(UnmanagedType.I1)]
            public bool InheritedAddressSpace;
            [MarshalAs(UnmanagedType.I1)]
            public bool ReadImageFileExecOptions;
            [MarshalAs(UnmanagedType.I1)]
            public bool BeingDebugged;
            [MarshalAs(UnmanagedType.I1)]
            public bool BitField;
            public IntPtr Mutant;

            public IntPtr ImageBaseAddress;
            public IntPtr Ldr; // PebLdrData*
            public IntPtr ProcessParameters; // RtlUserProcessParameters*
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;
            public IntPtr AtlThunkSListPtr;
            public IntPtr SparePrt2;
            public int EnvironmentUpdateCount;
            public IntPtr KernelCallbackTable;
            public int SystemReserved;
            public int SpareUlong;
            public IntPtr FreeList;
            public int TlsExpansionCounter;
            public IntPtr TlsBitmap;
            public unsafe fixed int TlsBitmapBits[2];
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr ReadOnlySharedMemoryHeap;
            public IntPtr ReadOnlyStaticServerData;
            public IntPtr AnsiCodePageData;
            public IntPtr OemCodePageData;
            public IntPtr UnicodeCaseTableData;

            public int NumberOfProcessors;
            public int NtGlobalFlag;

            public long CriticalSectionTimeout;
            public IntPtr HeapSegmentReserve;
            public IntPtr HeapSegmentCommit;
            public IntPtr HeapDeCommitTotalFreeThreshold;
            public IntPtr HeapDeCommitFreeBlockThreshold;

            public int NumberOfHeaps;
            public int MaximumNumberOfHeaps;
            public IntPtr ProcessHeaps;

            public IntPtr GdiSharedHandleTable;
            public IntPtr ProcessStarterHelper;
            public int GdiDCAttributeList;
            public IntPtr LoaderLock;

            public int OSMajorVersion;
            public int OSMinorVersion;
            public short OSBuildNumber;
            public short OSCSDVersion;
            public int OSPlatformId;
            public int ImageSubsystem;
            public int ImageSubsystemMajorVersion;
            public int ImageSubsystemMinorVersion;
            public IntPtr ImageProcessAffinityMask;
            public unsafe fixed byte GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
            public IntPtr PostProcessInitRoutine;

            public IntPtr TlsExpansionBitmap;
            public unsafe fixed int TlsExpansionBitmapBits[32];

            public int SessionId;

            public long AppCompatFlags;
            public long AppCompatFlagsUser;
            public IntPtr pShimData;
            public IntPtr AppCompatInfo;

            public UnicodeString CSDVersion;

            public IntPtr ActivationContextData;
            public IntPtr ProcessAssemblyStorageMap;
            public IntPtr SystemDefaultActivationContextData;
            public IntPtr SystemAssemblyStorageMap;

            public IntPtr MinimumStackCommit;

            public IntPtr FlsCallback;
            public ListEntry FlsListHead;
            public IntPtr FlsBitmap;
            public unsafe fixed int FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(int) * 8)];
            public int FlsHighIndex;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RtlUserProcessParameters
        {
            public static readonly int CurrentDirectoryOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "CurrentDirectory").ToInt32();
            public static readonly int DllPathOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "DllPath").ToInt32();
            public static readonly int ImagePathNameOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "ImagePathName").ToInt32();
            public static readonly int CommandLineOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "CommandLine").ToInt32();
            public static readonly int EnvironmentOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "Environment").ToInt32();
            public static readonly int WindowTitleOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "WindowTitle").ToInt32();
            public static readonly int DesktopInfoOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "DesktopInfo").ToInt32();
            public static readonly int ShellInfoOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "ShellInfo").ToInt32();
            public static readonly int RuntimeDataOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "RuntimeData").ToInt32();
            public static readonly int CurrentDirectoriesOffset =
                Marshal.OffsetOf(typeof(RtlUserProcessParameters), "CurrentDirectories").ToInt32();

            public struct CurDir
            {
                public UnicodeString DosPath;
                public IntPtr Handle;
            }

            public struct RtlDriveLetterCurDir
            {
                public ushort Flags;
                public ushort Length;
                public uint TimeStamp;
                public IntPtr DosPath;
            }

            public int MaximumLength;
            public int Length;

            public RtlUserProcessFlags Flags;
            public int DebugFlags;

            public IntPtr ConsoleHandle;
            public int ConsoleFlags;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;

            public CurDir CurrentDirectory;
            public UnicodeString DllPath;
            public UnicodeString ImagePathName;
            public UnicodeString CommandLine;
            public IntPtr Environment;

            public int StartingX;
            public int StartingY;
            public int CountX;
            public int CountY;
            public int CountCharsX;
            public int CountCharsY;
            public int FillAttribute;

            public StartupFlags WindowFlags;
            public int ShowWindowFlags;
            public UnicodeString WindowTitle;
            public UnicodeString DesktopInfo;
            public UnicodeString ShellInfo;
            public UnicodeString RuntimeData;

            public RtlDriveLetterCurDir CurrentDirectories;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessBasicInformation
        {
            public int ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private static string GetProcessCommandLine(IntPtr handle)
        {
            ProcessBasicInformation pbi;

            int returnLength;
            int status = NtQueryInformationProcess(handle, 0, out pbi, Marshal.SizeOf(typeof(ProcessBasicInformation)), out returnLength);

            if (status != 0) throw new InvalidOperationException(string.Format("Exception: status = {0}, expecting 0", status));

            string result = GetPebString(PebOffset.CommandLine, pbi.PebBaseAddress, handle);

            return result;
        }

        private static string GetProcessImagePath(IntPtr handle)
        {
            ProcessBasicInformation pbi;

            int returnLength;
            int status = NtQueryInformationProcess(handle, 0, out pbi, Marshal.SizeOf(typeof(ProcessBasicInformation)), out returnLength);

            if (status != 0) throw new InvalidOperationException(string.Format("Exception: status = {0}, expecting 0", status));

            string result = GetPebString(PebOffset.ImagePathName, pbi.PebBaseAddress, handle);

            return result;
        }

        private static IntPtr IncrementPtr(IntPtr ptr, int value)
        {
            return IntPtr.Size == sizeof(Int32) ? new IntPtr(ptr.ToInt32() + value) : new IntPtr(ptr.ToInt64() + value);
        }

        private static unsafe string GetPebString(PebOffset offset, IntPtr pebBaseAddress, IntPtr handle)
        {
            byte* buffer = stackalloc byte[IntPtr.Size];

            ReadMemory(IncrementPtr(pebBaseAddress, Peb.ProcessParametersOffset), buffer, IntPtr.Size, handle);

            IntPtr processParameters = *(IntPtr*)buffer;
            int realOffset = GetPebOffset(offset);

            UnicodeString pebStr;
            ReadMemory(IncrementPtr(processParameters, realOffset), &pebStr, Marshal.SizeOf(typeof(UnicodeString)), handle);

            string str = System.Text.Encoding.Unicode.GetString(ReadMemory(pebStr.Buffer, pebStr.Length, handle), 0, pebStr.Length);

            return str;
        }

        private static int GetPebOffset(PebOffset offset)
        {
            switch (offset)
            {
                case PebOffset.CommandLine:
                    return RtlUserProcessParameters.CommandLineOffset;
                case PebOffset.CurrentDirectoryPath:
                    return RtlUserProcessParameters.CurrentDirectoryOffset;
                case PebOffset.DesktopName:
                    return RtlUserProcessParameters.DesktopInfoOffset;
                case PebOffset.DllPath:
                    return RtlUserProcessParameters.DllPathOffset;
                case PebOffset.ImagePathName:
                    return RtlUserProcessParameters.ImagePathNameOffset;
                case PebOffset.RuntimeData:
                    return RtlUserProcessParameters.RuntimeDataOffset;
                case PebOffset.ShellInfo:
                    return RtlUserProcessParameters.ShellInfoOffset;
                case PebOffset.WindowTitle:
                    return RtlUserProcessParameters.WindowTitleOffset;
                default:
                    throw new ArgumentException("offset");
            }
        }

        private static byte[] ReadMemory(IntPtr baseAddress, int length, IntPtr handle)
        {
            byte[] buffer = new byte[length];

            ReadMemory(baseAddress, buffer, length, handle);

            return buffer;
        }

        private static unsafe int ReadMemory(IntPtr baseAddress, byte[] buffer, int length, IntPtr handle)
        {
            fixed (byte* bufferPtr = buffer) return ReadMemory(baseAddress, bufferPtr, length, handle);
        }

        private static unsafe int ReadMemory(IntPtr baseAddress, void* buffer, int length, IntPtr handle)
        {
            return ReadMemory(baseAddress, new IntPtr(buffer), length, handle);
        }

        private static int ReadMemory(IntPtr baseAddress, IntPtr buffer, int length, IntPtr handle)
        {
            int status;
            IntPtr retLengthIntPtr;

            if ((status = NtReadVirtualMemory(handle, baseAddress, buffer, new IntPtr(length), out retLengthIntPtr)) > 0)
            {
                throw new InvalidOperationException(string.Format("Exception: status = {0}, expecting 0", status));
            }
            return retLengthIntPtr.ToInt32();
        }

        public static string GetCommandLineByProcessId(int PID)
        {
            string commandLine = "";
            try
            {
                Process process = Process.GetProcessById(PID);
                commandLine = GetProcessCommandLine(process.Handle);
                commandLine = commandLine.Replace((char)0, ' ');
            }
            catch
            {
            }
            return commandLine;
        }
    }
'@

$cp = new-object System.CodeDom.Compiler.CompilerParameters
$cp.CompilerOptions = "/unsafe"
$dummy = $cp.ReferencedAssemblies.Add('System.dll')

$type = Add-Type -TypeDefinition $getprocesscmdline -CompilerParameters $cp

$volumeinfo = @'
    using System;
    using System.Collections;
    using System.Runtime.InteropServices;
    using System.Text;
    using Microsoft.Win32.SafeHandles;

    public class VolumeInfo
    {
        [DllImport("kernel32.dll")]
        public static extern DriveType GetDriveType([MarshalAs(UnmanagedType.LPStr)] string lpRootPathName);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
            out ulong lpFreeBytesAvailable,
            out ulong lpTotalNumberOfBytes,
            out ulong lpTotalNumberOfFreeBytes);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private extern static bool GetVolumeInformation(
            string RootPathName,
            StringBuilder VolumeNameBuffer,
            int VolumeNameSize,
            out uint VolumeSerialNumber,
            out uint MaximumComponentLength,
            out uint FileSystemFlags, // FileSystemFeature
            StringBuilder FileSystemNameBuffer,
            int nFileSystemNameSize);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetVolumePathNamesForVolumeNameW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpszVolumeName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpszVolumePathNames,
            uint cchBuferLength,
            ref UInt32 lpcchReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern FindVolumeSafeHandle FindFirstVolume([Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindNextVolume(FindVolumeSafeHandle hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindVolumeClose(IntPtr hFindVolume);

        private static readonly ulong KB = 1024;

        public enum DriveType : uint
        {
            Unknown = 0,    //DRIVE_UNKNOWN
            Error = 1,        //DRIVE_NO_ROOT_DIR
            Removable = 2,    //DRIVE_REMOVABLE
            Fixed = 3,        //DRIVE_FIXED
            Remote = 4,        //DRIVE_REMOTE
            CDROM = 5,        //DRIVE_CDROM
            RAMDisk = 6        //DRIVE_RAMDISK
        }

        private class FindVolumeSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private FindVolumeSafeHandle()
            : base(true)
            {
            }

            public FindVolumeSafeHandle(IntPtr preexistingHandle, bool ownsHandle)
            : base(ownsHandle)
            {
                SetHandle(preexistingHandle);
            }

            protected override bool ReleaseHandle()
            {
                return FindVolumeClose(handle);
            }
        }

        public class Volume
        {            
            public string VolumeGUID;            
            public string FileSys;
            public DriveType DriveType;
            public uint DriveTypeId;

            public string MountPoint;
            public string FileSystemName;
            public string VolumeName;
            
            public ulong TotalBytes;
            public ulong FreeBytes;
            public ulong UsedBytes;
            public int UsedPercent;

            public ulong TotalBytesKB;
            public ulong FreeBytesKB;
            public ulong UsedBytesKB;

            public uint SerialNumber;
        }

        private static void GetVolumeDetails(string drive, Volume v)
        {
            ulong FreeBytesToCallerDummy;
            if (GetDiskFreeSpaceEx(drive, out FreeBytesToCallerDummy, out v.TotalBytes, out v.FreeBytes))
            {
                StringBuilder volname = new StringBuilder(261);
                StringBuilder fsname = new StringBuilder(261);
                uint flagsDummy, maxlenDummy;
                GetVolumeInformation(drive, volname, volname.Capacity, 
                    out v.SerialNumber, out maxlenDummy, out flagsDummy, fsname, fsname.Capacity);
                v.FileSystemName = fsname.ToString();
                v.VolumeName = volname.ToString();

                if (v.TotalBytes > 0)
                {
                    double used = ((double)(v.TotalBytes - v.FreeBytes) / (double)v.TotalBytes);
                    v.UsedPercent = (int)Math.Round(used * 100.0);
                }

                v.UsedBytes = v.TotalBytes - v.FreeBytes;
                v.TotalBytesKB = v.TotalBytes / KB;
                v.FreeBytesKB = v.FreeBytes / KB;
                v.UsedBytesKB = v.UsedBytes / KB;
            }
        }

        private static void GetVolumeMountPoints(string volumeDeviceName, ArrayList volumes)
        {
            string buffer = "";
            uint lpcchReturnLength = 0;
            GetVolumePathNamesForVolumeNameW(volumeDeviceName, buffer, (uint)buffer.Length, ref lpcchReturnLength);
            if (lpcchReturnLength == 0)
            {
                return;
            }

            buffer = new string(new char[lpcchReturnLength]);

            if (!GetVolumePathNamesForVolumeNameW(volumeDeviceName, buffer, lpcchReturnLength, ref lpcchReturnLength))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());                
            }

            string[] mounts = buffer.Split('\0');
            if (buffer.Length > 1)
            {
                foreach (string mount in mounts)
                {
                    if (mount.Length > 0)
                    {
                        Volume v = new Volume();
                        v.VolumeGUID = volumeDeviceName;
                        v.MountPoint = mount;
                        v.DriveType = GetDriveType(mount);                        
                        v.DriveTypeId = (uint)v.DriveType;
                        if (mount[0] >= 'A' && mount[0] <= 'Z')
                        {
                            v.FileSys = mount[0].ToString();
                        }
                        if (mount.Length > 3)
                        {
                            // per BBWin, replace spaces with underscore in mountpoint name
                            v.FileSys = mount.Substring(3, mount.LastIndexOf('\\') - 3).Replace(' ', '_');                            
                        }
                        GetVolumeDetails(mount, v);
                        volumes.Add(v);
                    }
                }
            }
            else
            {
                // unmounted volume - only add details once
                Volume v = new Volume();
                v.VolumeGUID = volumeDeviceName;
                v.MountPoint = "";
                v.DriveType = GetDriveType(volumeDeviceName);                
                v.DriveTypeId = 99; // special value for unmounted
                v.FileSys = "unmounted";

                GetVolumeDetails(volumeDeviceName, v);
                volumes.Add(v);
            }
        }

        public static Volume[] GetVolumes()
        {
            const uint bufferLength = 1024;
            StringBuilder volume = new StringBuilder((int)bufferLength, (int)bufferLength);
            ArrayList ret = new ArrayList();

            using (FindVolumeSafeHandle volumeHandle = FindFirstVolume(volume, bufferLength))
            {
                if (volumeHandle.IsInvalid)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                do
                {
                    GetVolumeMountPoints(volume.ToString(), ret);
                } while (FindNextVolume(volumeHandle, volume, bufferLength));

                return (Volume[])ret.ToArray(typeof(Volume));
            }
        }
    }
'@
$type = Add-Type $volumeinfo

}
#endregion 

function SetIfNot($obj,$key,$value)
{
    if($obj.$key -eq $null) { $obj | Add-Member -MemberType noteproperty -Name $key -Value $value }
}

function XymonConfig($startedWithArgs)
{
    if (Test-Path $XymonClientCfg)
    {
        XymonInitXML $startedWithArgs
        $script:XymonCfgLocation = "XML: $XymonClientCfg"
    }
    else
    {
        XymonInitRegistry
        $script:XymonCfgLocation = "Registry"
    }
    XymonInit
}
#'
function XymonInitXML($startedWithArgs)
{
    $xmlconfig = [xml](Get-Content $XymonClientCfg)
    $script:XymonSettings = $xmlconfig.XymonSettings

    # if serverhttppassword is populated and not encrypted, encrypt it
    # only if we were started without arguments - so don't do it for
    # service installation mode
    if ($startedWithArgs -eq $false -and
        $xmlconfig.XymonSettings.serverHttpPassword -ne $null -and
        $xmlconfig.XymonSettings.serverHttpPassword -ne '' -and
        $xmlconfig.XymonSettings.serverHttpPassword -notlike '{SecureString}*')
    {
        WriteLog 'Attempting to encrypt password in config file'
        try
        {
            $securePass = ConvertTo-SecureString -AsPlainText -Force $xmlconfig.XymonSettings.serverHttpPassword
            $encryptedPass = ConvertFrom-SecureString -SecureString $securePass
            $xmlSecPass = "{SecureString}$($encryptedPass)"
            $xmlconfig.XymonSettings.serverHttpPassword = $xmlSecPass
            $xmlconfig.Save($XymonClientCfg)
        }
        catch
        {
            WriteLog "Exception encrypting config file password: $_"
        }
    }
}

function XymonInitRegistry
{
    $script:XymonSettings = Get-ItemProperty -ErrorAction:SilentlyContinue $XymonRegKey
}

function XymonInit
{
    if($script:XymonSettings -eq $null) {
        $script:XymonSettings = New-Object Object
    } 

    $servers = $script:XymonSettings.servers
    SetIfNot $script:XymonSettings serversList $servers
    if ($script:XymonSettings.servers -match " ") 
    {
        $script:XymonSettings.serversList = $script:XymonSettings.servers.Split(" ")
    }
    if ($script:XymonSettings.serversList -eq $null)
    {
        $script:XymonSettings.serversList = $xymonservers
    }

    SetIfNot $script:XymonSettings serverUrl ''
    SetIfNot $script:XymonSettings serverHttpUsername ''
    SetIfNot $script:XymonSettings serverHttpPassword ''
    SetIfNot $script:XymonSettings serverHttpTimeoutMs 100000

    $wanteddisks = $script:XymonSettings.wanteddisks
    SetIfNot $script:XymonSettings wanteddisksList $wanteddisks
    if ($script:XymonSettings.wanteddisks -match " ") 
    {
        $script:XymonSettings.wanteddisksList = $script:XymonSettings.wanteddisks.Split(" ")
    }
    if ($script:XymonSettings.wanteddisksList -eq $null)
    {
        $script:XymonSettings.wanteddisksList = @( 3 ) # 3=Local disks, 4=Network shares, 2=USB, 5=CD
    }

    # Params for default clientname
    SetIfNot $script:XymonSettings clientfqdn 1 # 0 = unqualified, 1 = fully-qualified
    SetIfNot $script:XymonSettings clientlower 1 # 0 = unqualified, 1 = fully-qualified
    
    if ($script:XymonSettings.clientname -eq $null -or $script:XymonSettings.clientname -eq "") 
    { 
        # set name based on rules; first try IP properties
        $ipProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $clname  = $ipProperties.HostName
        if ($clname -ne '' -and $script:XymonSettings.clientfqdn -eq 1 -and ($ipProperties.DomainName -ne $null)) 
        { 
            $clname += "." + $ipProperties.DomainName
        }
        if ($clname -eq '')
        {
            # try environment
            $clname = $Env:COMPUTERNAME
            if ($clname -ne '' -and $script:XymonSettings.clientfqdn -eq 1 -and ($Env:USERDNSDOMAIN -ne $null)) 
            {
                $clname += '.' + $Env:USERDNSDOMAIN
            }
        }
        if ($script:XymonSettings.clientlower -eq 1) { $clname = $clname.ToLower() }
        SetIfNot $script:XymonSettings clientname $clname
        $script:clientname = $clname
    }
    else
    {
        $script:clientname = $script:XymonSettings.clientname
    }

    # Params for various client options
    SetIfNot $script:XymonSettings clientbbwinmembug 1 # 0 = report correctly, 1 = page and virtual switched
    SetIfNot $script:XymonSettings clientremotecfgexec 0 # 0 = don't run remote config, 1 = run remote config
    SetIfNot $script:XymonSettings clientconfigfile "$env:TEMP\xymonconfig.cfg" # path for saved client-local.cfg section from server
    SetIfNot $script:XymonSettings clientlogfile "$env:TEMP\xymonclient.log" # path for logfile
    SetIfNot $script:XymonSettings clientsoftware "powershell" # powershell / bbwin
    SetIfNot $script:XymonSettings clientclass "powershell" # 'class' value (default powershell)
    SetIfNot $script:XymonSettings loopinterval 300 # seconds to repeat client reporting loop
    SetIfNot $script:XymonSettings maxlogage 60 # minutes age for event log reporting
    SetIfNot $script:XymonSettings MaxEvents 5000 # maximum number of events per event log
    SetIfNot $script:XymonSettings slowscanrate 72 # repeats of main loop before collecting slowly changing information again
    SetIfNot $script:XymonSettings reportevt 1 # scan eventlog and report (can be very slow)
    SetIfNot $script:XymonSettings EnableWin32_Product 0 # 0 = do not use Win32_product, 1 = do
                        # see http://support.microsoft.com/kb/974524 for reasons why Win32_Product is not recommended!
    SetIfNot $script:XymonSettings EnableWin32_QuickFixEngineering 0 # 0 = do not use Win32_QuickFixEngineering, 1 = do
    SetIfNot $script:XymonSettings EnableWMISections 0 # 0 = do not produce [WMI: sections (OS, BIOS, Processor, Memory, Disk), 1 = do
    SetIfNot $script:XymonSettings EnableIISSection 1 # 0 = do not produce iis_sites section, 1 = do
    SetIfNot $script:XymonSettings ClientProcessPriority 'Normal' # possible values Normal, Idle, High, RealTime, BelowNormal, AboveNormal

    $clientlogpath = Split-Path -Parent $script:XymonSettings.clientlogfile
    SetIfNot $script:XymonSettings clientlogpath $clientlogpath

    SetIfNot $script:XymonSettings clientlogretain 0

    SetIfNot $script:XymonSettings XymonAcceptUTF8 0 # messages sent to Xymon 0 = convert to ASCII, 1 = convert to UTF8
    SetIfNot $script:XymonSettings GetProcessInfoCommandLine 1 # get process command line 1 = yes, 0 = no
    SetIfNot $script:XymonSettings GetProcessInfoOwner 1 # get process owner 1 = yes, 0 = no

    $extscript = Join-Path $xymondir 'ext'
    $extdata = Join-Path $xymondir 'tmp'
    $localdata = Join-Path $xymondir 'local'
    SetIfNot $script:XymonSettings externalscriptlocation $extscript
    SetIfNot $script:XymonSettings externaldatalocation $extdata
    SetIfNot $script:XymonSettings localdatalocation $localdata
    SetIfNot $script:XymonSettings servergiflocation '/xymon/gifs/'
    $script:clientlocalcfg = ""
    $script:logfilepos = @{}
    $script:externals = @{}
    $script:diskpartData = ''
    $script:LastTransmissionMethod = 'Unknown'

    $script:HaveCmd = @{}
    foreach($cmd in "query","qwinsta") {
        $script:HaveCmd.$cmd = (get-command -ErrorAction:SilentlyContinue $cmd) -ne $null
    }

    @("cpuinfo","totalload","numcpus","numcores","numvcpus","osinfo","svcs","procs","disks",`
    "netifs","svcprocs","localdatetime","uptime","usercount",`
    "XymonProcsCpu","XymonProcsCpuTStart","XymonProcsCpuElapsed") `
    | %{ if (get-variable -erroraction SilentlyContinue $_) { Remove-Variable $_ }}
    
}

function XymonProcsCPUUtilisation
{
    # XymonProcsCpu is a table with 6 elements:
    #   0 = process object
    #   1 = last tick value
    #   2 = ticks used since last poll
    #   3 = activeflag
    #   4 = command line
    #   5 = owner

    # ZB - got a feeling XymonProcsCpuElapsed should be multiplied by number of cores
    if ((get-variable -erroraction SilentlyContinue "XymonProcsCpu") -eq $null) {
        $script:XymonProcsCpu = @{ 0 = ( $null, 0, 0, $false) }
        $script:XymonProcsCpuTStart = (Get-Date).ticks
        $script:XymonProcsCpuElapsed = 0
    }
    else {
        $script:XymonProcsCpuElapsed = (Get-Date).ticks - $script:XymonProcsCpuTStart
        $script:XymonProcsCpuTStart = (Get-Date).Ticks
    }
    $script:XymonProcsCpuElapsed *= $script:numcores
    
    foreach ($p in $script:procs) {
        # store the process name in XymonProcsCpu
        # and if $p.name differs but id matches, need to pick up new command line etc and zero counters
        # - this covers the case where a process id is reused
        $thisp = $script:XymonProcsCpu[$p.Id]
        if ($p.Id -ne 0 -and ($thisp -eq $null -or $thisp[0].Name -ne $p.Name))
        {
            # either we have not seen this process before ($thisp -eq $null)
            # OR
            # the name of the process for ID x does not equal the cached process name
            if ($thisp -eq $null)
            {
                WriteLog "New process $($p.Id) detected: $($p.Name)"
            }
            else
            {
                WriteLog "Process $($p.Id) appears to have changed from $($thisp[0].Name) to $($p.Name)"
            }

            $cmdline = ''
            $owner = ''
            if ($script:XymonSettings.GetProcessInfoCommandLine -eq 1)
            {
                $cmdline = [ProcessInformation]::GetCommandLineByProcessId($p.Id)
            }
            if ($script:XymonSettings.GetProcessInfoOwner -eq 1)
            {
                $owner = [GetProcessOwner]::GetProcessOwnerByPId($p.Id)
            }
            if ($owner.length -gt 32) { $owner = $owner.substring(0, 32) }

            # New process - create an entry in the curprocs table
            # We use static values here, because some get-process entries have null values
            # for the tick-count (The "SYSTEM" and "Idle" processes).
            $script:XymonProcsCpu[$p.Id] = @($null, 0, 0, $false, $cmdline, $owner)
            $thisp = $script:XymonProcsCpu[$p.Id]
        }

        $thisp[3] = $true
        $thisp[2] = $p.TotalProcessorTime.Ticks - $thisp[1]
        $thisp[1] = $p.TotalProcessorTime.Ticks
        $thisp[0] = $p
    }
}

function UserSessionCount
{
    if ($HaveCmd.qwinsta)
    {
        $script:usersessions = qwinsta /counter
        ($script:usersessions -match ' Active ').Length
    }
    else
    {
        $q = get-wmiobject win32_logonsession | %{ $_.logonid}
        $service = Get-WmiObject -ComputerName $server -Class Win32_Service -Filter "Name='$xymonsvc'"
        $s = 0
        get-wmiobject win32_session | ?{ 2,10 -eq $_.LogonType} | ?{$q -eq $_.logonid} | %{
            $z = $_.logonid
            get-wmiobject win32_sessionprocess | ?{ $_.Antecedent -like "*LogonId=`"$z`"*" } | %{
                if($_.Dependent -match "Handle=`"(\d+)`"") {
                    get-wmiobject win32_process -filter "processid='$($matches[1])'" }
            } | select -first 1 | %{ $s++ }
        }
        $s
    }
}

function XymonCollectInfo
{
    WriteLog "Executing XymonCollectInfo"

    CleanXymonProcsCpu
    WriteLog "XymonCollectInfo: Process info"
    $script:procs = Get-Process | Sort-Object -Property Id
    WriteLog "XymonCollectInfo: calling XymonProcsCPUUtilisation"
    XymonProcsCPUUtilisation

    WriteLog "XymonCollectInfo: CPU info (WMI)"
    $script:cpuinfo = @(Get-WmiObject -Class Win32_Processor)
    #$script:totalload = 0
    $script:numcpus  = $cpuinfo.Count
    $script:numcores = 0
    $script:numvcpus = 0
    foreach ($cpu in $cpuinfo) { 
        #$script:totalload += $cpu.LoadPercentage
        $script:numcores += $cpu.NumberOfCores
        $script:numvcpus += $cpu.NumberOfLogicalProcessors
    }
    #$script:totalload /= $numcpus

    WriteLog "Found $($script:numcpus) CPUs, total of $($script:numcores) cores"

    WriteLog "XymonCollectInfo: OS info (including memory) (WMI)"
    $script:osinfo = Get-WmiObject -Class Win32_OperatingSystem
    WriteLog "XymonCollectInfo: Service info (WMI)"
    $script:svcs = Get-WmiObject -Class Win32_Service | Sort-Object -Property Name
    WriteLog "XymonCollectInfo: Disk info"
    $mydisks = @()
    try
    {
        $volumes = [VolumeInfo]::GetVolumes()
        foreach ($disktype in $script:XymonSettings.wanteddisksList) { 
            $mydisks += @( ($volumes | where { $_.DriveTypeId -eq $disktype } ))
        }
    }
    catch
    {
        $volumes = @()
        WriteLog "Error getting volume information: $_"
    }
    $script:disks = $mydisks | Sort-Object FileSys

    WriteLog "XymonCollectInfo: Building table of service processes (uses WMI data)"
    $script:svcprocs = @{([int]-1) = ""}
    foreach ($s in $svcs) {
        if ($s.State -eq "Running") {
            if ($svcprocs[([int]$s.ProcessId)] -eq $null) {
                $script:svcprocs += @{ ([int]$s.ProcessId) = $s.Name }
            }
            else {
                $script:svcprocs[([int]$s.ProcessId)] += ("/" + $s.Name)
            }
        }
    }

    WriteLog "XymonCollectInfo: Date processing (uses WMI data)"
    $script:localdatetime = $osinfo.ConvertToDateTime($osinfo.LocalDateTime)
    $script:uptime = $localdatetime - $osinfo.ConvertToDateTime($osinfo.LastBootUpTime)
    
    WriteLog "XymonCollectInfo: Adding CPU usage etc to main process data"
    XymonProcesses

    WriteLog "XymonCollectInfo: calling UserSessionCount"
    $script:usercount = UserSessionCount

    WriteLog "XymonCollectInfo finished"
}

function WMIProp($class)
{
    $wmidata = Get-WmiObject -Class $class
    $props = ($wmidata | Get-Member -MemberType Property | Sort-Object -Property Name | where { $_.Name -notlike "__*" })
    foreach ($p in $props) {
        $p.Name + " : " + $wmidata.($p.Name)
    }
}

function UnixDate([System.DateTime] $t)
{
    $t.ToString("ddd dd MMM HH:mm:ss yyyy")
}

function epochTimeUtc([System.DateTime] $t)
{
    [int64]($t.ToUniversalTime() - $UnixEpochOriginUTC).TotalSeconds
}

function filesize($file,$clsize=4KB)
{
    return [math]::floor((($_.Length -1)/$clsize + 1) * $clsize/1KB)
}

function du([string]$dir,[int]$clsize=0)
{
    if($clsize -eq 0) {
        $drive = "{0}:" -f [string](get-item $dir | %{ $_.psdrive })
        $clsize = [int](Get-WmiObject win32_Volume | ? { $_.DriveLetter -eq $drive }).BlockSize
        if($clsize -eq 0 -or $clsize -eq $null) { $clsize = 4096 } # default in case not found
    }
    $sum = 0
    $dulist = ""
    get-childitem $dir -Force | % {
        if( $_.Attributes -like "*Directory*" ) {
           $dulist += du ("{0}\{1}" -f [string]$dir,$_.Name) $clsize | out-string
           $sum += $dulist.Split("`n")[-2].Split("`t")[0] # get size for subdir
        } else { 
           $sum += filesize $_ $clsize
        }
    }
    "$dulist$sum`t$dir"
}

function XymonPrintProcess($pobj, $name, $pct)
{
    $pcpu = (("{0:F1}" -f $pct) + "`%").PadRight(8)
    $ppid = ([string]($pobj.Id)).PadRight(9)
    
    if ($name.length -gt 30) { $name = $name.substring(0, 30) }
    $pname = $name.PadRight(32)

    $pprio = ([string]$pobj.BasePriority).PadRight(5)
    $ptime = (([string]($pobj.TotalProcessorTime)).Split(".")[0]).PadRight(9)
    $pmem = ([string]($pobj.WorkingSet64 / 1KB)) + "k"

    $pcpu + $ppid + $pname + $pprio + $ptime + $pmem
}

function XymonDate
{
    "[date]"
    UnixDate $localdatetime
}

function XymonClock
{
    $epoch = epochTimeUtc $localdatetime

    "[clock]"
    "epoch: " + $epoch
    "local: " + (UnixDate $localdatetime)
    "UTC: " + (UnixDate $localdatetime.ToUniversalTime())
    $timesource = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters').Type
    "Time Synchronisation type: " + $timesource
    if ($timesource -eq "NTP") {
        "NTP server: " + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters').NtpServer
    }
    $w32qs = w32tm /query /status  # will not run on 2003, XP or earlier
    if($?) { $w32qs }
}

function XymonUptime
{
    "[uptime]"
    "sec: " + [string] ([int]($uptime.Ticks / 10000000))
    ([string]$uptime.Days) + " days " + ([string]$uptime.Hours) + " hours " + ([string]$uptime.Minutes) + " minutes " + ([string]$uptime.Seconds) + " seconds"
    "Bootup: " + $osinfo.LastBootUpTime
}

function XymonUname
{
    "[uname]"
    $osinfo.Caption + " " + $osinfo.CSDVersion + " (build " + $osinfo.BuildNumber + ")"
}

function XymonClientVersion
{
    "[clientversion]"
    $Version
}

function XymonProcesses
{
    # gather process and timing information and add this to $script:procs
    # variable
    # XymonCpu and XymonProcs use this information to output
 
    WriteLog "XymonProcesses start"

    foreach ($p in $script:procs)
    {
        if ($svcprocs[($p.Id)] -ne $null) {
            $procname = "SVC:" + $svcprocs[($p.Id)]
        }
        else {
            $procname = $p.Name
        }
           
        Add-Member -MemberType NoteProperty `
            -Name XymonProcessName -Value $procname `
            -InputObject $p

        $thisp = $script:XymonProcsCpu[$p.Id]
        if ($thisp -ne $null -and $thisp[3] -eq $true) 
        {
            if ($script:XymonProcsCpuElapsed -gt 0)
            {
                $usedpct = ([int](10000*($thisp[2] / $script:XymonProcsCpuElapsed))) / 100
            }
            else
            {
                $usedpct = 0
            }
            Add-Member -MemberType NoteProperty `
                -Name CommandLine -Value $thisp[4] `
                -InputObject $p
            Add-Member -MemberType NoteProperty `
                -Name Owner -Value $thisp[5] `
                -InputObject $p
        }
        else 
        {
            $usedpct = 0
        }

        Add-Member -MemberType NoteProperty `
            -Name CPUPercent -Value $usedpct `
            -InputObject $p

        $elapsedRuntime = 0
        if ($p.StartTime -ne $null)
        {
            $elapsedRuntime = ($script:localdatetime - $p.StartTime).TotalMinutes 
        }
        Add-Member -MemberType NoteProperty `
            -Name ElapsedSinceStart -Value $elapsedRuntime `
            -InputObject $p

        $pws     = "{0,8:F0}/{1,-8:F0}" -f ($p.WorkingSet64 / 1KB), ($p.PeakWorkingSet64 / 1KB)
        $pvmem   = "{0,8:F0}/{1,-8:F0}" -f ($p.VirtualMemorySize64 / 1KB), ($p.PeakVirtualMemorySize64 / 1KB)
        $ppgmem  = "{0,8:F0}/{1,-8:F0}" -f ($p.PagedMemorySize64 / 1KB), ($p.PeakPagedMemorySize64 / 1KB)
        $pnpgmem = "{0,8:F0}" -f ($p.NonPagedSystemMemorySize64 / 1KB)

        Add-Member -MemberType NoteProperty `
            -Name XymonPeakWorkingSet -Value $pws `
            -InputObject $p
        Add-Member -MemberType NoteProperty `
            -Name XymonPeakVirtualMem -Value $pvmem `
            -InputObject $p
        Add-Member -MemberType NoteProperty `
            -Name XymonPeakPagedMem -Value $ppgmem `
            -InputObject $p
        Add-Member -MemberType NoteProperty `
            -Name XymonNonPagedSystemMem -Value $pnpgmem `
            -InputObject $p
    }

    WriteLog "XymonProcesses finished."
}


function XymonCpu
{
    WriteLog "XymonCpu start"

    $totalcpu = ($script:procs | Measure-Object -Sum -Property CPUPercent | Select -ExpandProperty Sum)
    $totalcpu = [Math]::Round($totalcpu, 2)

    "[cpu]"
    "up: {0} days, {1} users, {2} procs, load={3}%" -f [string]$uptime.Days, $usercount, $procs.count, [string]$totalcpu
    ""
    "CPU states:"
    "`ttotal`t{0}`%" -f [string]$totalcpu
    "`tcores: {0}" -f [string]$script:numcores

    if ($script:XymonProcsCpuElapsed -gt 0) {
        ""
        "CPU".PadRight(9) + "PID".PadRight(8) + "Image Name".PadRight(32) + "Pri".PadRight(5) + "Time".PadRight(9) + "MemUsage"

        $script:procs | Sort-Object -Descending { $_.CPUPercent } `
            | foreach `
            { 
                $skipFlag = $false
                if ($script:clientlocalcfg_entries.ContainsKey('slimmode'))
                {
                    if ($script:clientlocalcfg_entries.slimmode.ContainsKey('processes'))
                    {
                        # skip this process if we are in slimmode and this process is not one of the 
                        # requested processes
                        if ($script:clientlocalcfg_entries.slimmode.processes -notcontains $_.XymonProcessName)
                        {
                            $skipFlag = $true
                        }
                    }
                }
                
                if (!$skipFlag)
                {
                    XymonPrintProcess $_ $_.XymonProcessName $_.CPUPercent 
                }
            }
    }
    WriteLog "XymonCpu finished."
}

function XymonDisk
{
    $MountpointWidth = 10
    $LabelWidth = 10
    $FilesysWidth = 10

    # work out column widths
    foreach ($d in $script:disks)
    {
        $mplength = "/FIXED/$($d.MountPoint)".Length
        if ($mplength -gt $MountpointWidth)
        {
            $MountpointWidth = $mplength
        }
        if ($d.FileSys.Length -gt $FilesysWidth)
        {
            $FilesysWidth = $d.FileSys.Length
        }
        if ($d.VolumeName.Length -gt $LabelWidth)
        {
            $LabelWidth = $d.VolumeName.Length
        }
    }

    WriteLog "XymonDisk start"
    "[disk]"
    "{0,-$FilesysWidth} {1,12} {2,12} {3,12} {4,9}  {5,-$MountpointWidth} {6,-$LabelWidth} {7}" -f `
        "Filesystem", `
        "1K-blocks", `
        "Used", `
        "Avail", `
        "Capacity", `
        "Mounted", `
        "Label", `
        "Summary(Total\Avail GB)"
    foreach ($d in $script:disks) {
        $diskusedKB = $d.UsedBytesKB
        $disksizeKB = $d.TotalBytesKB

        $dsKB = "{0:F0}" -f ($d.TotalBytes / 1KB); $dsGB = "{0:F2}" -f ($d.TotalBytes / 1GB)
        $duKB = "{0:F0}" -f ($diskusedKB); $duGB = "{0:F2}" -f ($diskusedKB / 1KB);
        $dfKB = "{0:F0}" -f ($d.FreeBytes / 1KB); $dfGB = "{0:F2}" -f ($d.FreeBytes / 1GB)

        $mountpoint = "/FIXED/$($d.MountPoint)"
       
        "{0,-$FilesysWidth} {1,12} {2,12} {3,12} {4,9:0}% {5,-$MountpointWidth} {6,-$LabelWidth} {7}" -f `
            $d.FileSys, `
            $dsKB, `
            $duKB, `
            $dfKB, `
            $d.UsedPercent, `
            $mountpoint, `
            $d.VolumeName, `
            $dsGB + "\" + $dfGB
    }

    $script:diskpartData

    WriteLog "XymonDisk finished."
}

function XymonMemory
{
    WriteLog "XymonMemory start"
    $physused  = [int](($osinfo.TotalVisibleMemorySize - $osinfo.FreePhysicalMemory)/1KB)
    $phystotal = [int]($osinfo.TotalVisibleMemorySize / 1KB)
    $pageused  = [int](($osinfo.SizeStoredInPagingFiles - $osinfo.FreeSpaceInPagingFiles) / 1KB)
    $pagetotal = [int]($osinfo.SizeStoredInPagingFiles / 1KB)
    $virtused  = [int](($osinfo.TotalVirtualMemorySize - $osinfo.FreeVirtualMemory) / 1KB)
    $virttotal = [int]($osinfo.TotalVirtualMemorySize / 1KB)

    "[memory]"
    "memory    Total    Used"
    "physical: $phystotal $physused"
    if($script:XymonSettings.clientbbwinmembug -eq 0) {     # 0 = report correctly, 1 = page and virtual switched
        "virtual: $virttotal $virtused"
        "page: $pagetotal $pageused"
    } else {
        "virtual: $pagetotal $pageused"
        "page: $virttotal $virtused"
    }
    WriteLog "XymonMemory finished."
}

# ContainsLike - whether or not $compare matches
# one of the entries in $arrayOfLikes using the -like operator
# returns $null (no match) or the matching entry from $arrayOfLikes
function ContainsLike([string[]] $ArrayOfLikes, [string] $Compare)
{
    foreach ($l in $ArrayOfLikes)
    {
        if ($Compare -like $l)
        {
            return $l
        }
    }
    return $null
}

function XymonMsgs
{
    if ($script:XymonSettings.reportevt -eq 0) {return}

    $sinceMs = (New-Timespan -Minutes $script:XymonSettings.maxlogage).TotalMilliseconds

    # xml template
    #   {0} = log name e.g. Application
    #   {1} = milliseconds - how far back in time to go
    $filterXMLTemplate = `
@' 
    <QueryList>
      <Query Id="0" Path="{0}">
        <Select Path="{0}">*[System[TimeCreated[timediff(@SystemTime) &lt;= {1}] and ({2})]]</Select>
      </Query>
    </QueryList>
'@

    $eventLevels = @{ 
        '0' = 'Information';
        '1' = 'Critical';
        '2' = 'Error';
        '3' = 'Warning';
        '4' = 'Information';
        '5' = 'Verbose';
    }

    # default logs - may be overridden by config
    $wantedlogs = "Application", "System", "Security"
    $wantedLevels = @('Critical', 'Warning', 'Error', 'Information', 'Verbose')
    $maxpayloadlength = 1024
    $payload = ''

    # $wantedEventLogs
    # each key is an event log name
    # each value is an array of wanted levels
    # defaults set below
    # can be overridden by eventlogswanted config 
    $wantedEventLogs = `
        @{ `
            'Application' = @('Critical', 'Warning', 'Error', 'Information', 'Verbose'); `
            'System' = @('Critical', 'Warning', 'Error', 'Information', 'Verbose'); `
            'Security' = @('Critical', 'Warning', 'Error', 'Information', 'Verbose'); `
        }
    # any config from server should override this default config
    $wantedEventLogsPriority = -1

    # this function no longer uses $script:XymonSettings.wantedlogs
    # - it now uses eventlogswanted from the remote config
    # eventlogswanted:[optional priority]:<logs/levels>:max payload:[optional default levels]
    $script:clientlocalcfg_entries.keys | where { $_ -match '^eventlogswanted:(?:(\d+):)?(.+):(\d+):?(.+)?$' } | foreach `
    {
        $thisSectionPriority = 0
        WriteLog "Processing eventlogswanted config: $($matches[0])"
        # config priority (if present)
        # we only want the configuration with the highest priority
        if ($matches[1] -ne $null)
        {
            $thisSectionPriority = [int]($matches[1])
        }
        if ($wantedEventLogsPriority -gt $thisSectionPriority)
        {
            WriteLog "Previous priority $wantedEventLogsPriority greater than this config ($($thisSectionPriority)), skipping"
            $skip = $true
        }
        else
        {
            WriteLog "This config priority $($thisSectionPriority) greater than/equal to previous config ($($wantedEventLogsPriority)), processing"
            $wantedEventLogsPriority = $thisSectionPriority
            $skip = $false
        }

        # $wantedlogs
        # might be a list of logs - e.g. application,system
        # or a list of logs and levels - e.g. application|information&critical,system|critical&error
        if (-not ($skip))
        {
            $wantedEventLogs = @{}
            $wantedlogs = $matches[2] -split ','
            $maxpayloadlength = $matches[3]
            if ($matches[4] -ne $null)
            {
                $wantedLevels = $matches[4] -split ','
            }

            foreach ($log in $wantedlogs)
            {
                if ($log -like '*|*')
                {
                    $logParams = @($log -split '\|')
                    if ($logParams.Length -eq 2)
                    {
                        $levelParams = $logParams[1] -replace '&
