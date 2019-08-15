using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Renci.SshNet.Cng
{
    internal static class NCryptUtils
    {
        public static String GetPropertyString(IntPtr hObject, String propertyName)
        {
            IntPtr dataPtr = IntPtr.Zero;
            UInt32 cbResult = 0;
            GCHandle gch = GCHandle.Alloc(dataPtr, GCHandleType.Pinned);
            try
            {
                if (NCryptGetProperty(hObject, propertyName, gch.AddrOfPinnedObject(), (UInt32)IntPtr.Size, ref cbResult, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
                {
                    throw new Win32Exception("NCryptGetProperty failed.");
                }
            }
            finally
            {
                gch.Free();
            }
            return Marshal.PtrToStringUni(dataPtr);
        }

        #region P/Invoke declarations
        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptGetProperty
        (
            IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)] String pszProperty,
            IntPtr pbOutput,
            UInt32 cbOutput,
            ref UInt32 pcbResult,
            UInt32 dwFlags
        );

        private const UInt32 ERROR_SUCCESS = 0x00000000;
        private const UInt32 NCRYPT_SILENT_FLAG = 0x00000040;
        #endregion
    }
}
