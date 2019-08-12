using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Renci.SshNet.Cng
{
    public class BCryptAlgorithmProvider : IDisposable
    {
        private IntPtr hAlgorithm = IntPtr.Zero;

        public BCryptAlgorithmProvider(String algId)
        {
            if (BCryptOpenAlgorithmProvider(ref hAlgorithm, algId, null, 0) != ERROR_SUCCESS)
            {
                throw new Win32Exception("BCryptOpenAlgorithmProvider failed.");
            }
        }

        private UInt32 GetHashLength()
        {
            Byte[] bOutput = new Byte[4];
            UInt32 cbResult = 0;
            if (BCryptGetProperty(hAlgorithm, "HashDigestLength", bOutput, (UInt32)bOutput.Length, ref cbResult, 0) != ERROR_SUCCESS)
            {
                throw new Win32Exception("BCryptGetProperty failed.");
            }

            return (UInt32)bOutput[0] | ((UInt32)bOutput[1] << 8) | ((UInt32)bOutput[2] << 16) | ((UInt32)bOutput[3] << 24);
        }

        public Byte[] ComputeHash(Byte[] data)
        {
            UInt32 hashLength = GetHashLength();

            Byte[] bOutput = new Byte[hashLength];
            if (BCryptHash(hAlgorithm, null, 0, data, (UInt32)data.Length, bOutput, (UInt32)bOutput.Length) != ERROR_SUCCESS)
            {
                throw new Win32Exception("BCryptHash failed.");
            }
            return bOutput;
        }

        public void Dispose()
        {
            if (hAlgorithm != IntPtr.Zero)
            {
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                hAlgorithm = IntPtr.Zero;
            }
        }

        ~BCryptAlgorithmProvider()
        {
            Dispose();
        }

        #region PInvoke declarations
        private const UInt32 ERROR_SUCCESS = 0;

        [DllImport("Bcrypt.dll")]
        private extern static UInt32 BCryptOpenAlgorithmProvider
        (
            ref IntPtr phAlgorithm,
            [MarshalAs(UnmanagedType.LPWStr)] String pszAlgId,
            [MarshalAs(UnmanagedType.LPWStr)] String pszImplementation,
            UInt32 dwFlags
        );

        [DllImport("Bcrypt.dll")]
        private extern static UInt32 BCryptCloseAlgorithmProvider
        (
            IntPtr hAlgorithm,
            UInt32 dwFlags
        );

        [DllImport("Bcrypt.dll")]
        private extern static UInt32 BCryptHash
        (
            IntPtr hAlgorithm,
            Byte[] pbSecret,
            UInt32 cbSecret,
            Byte[] pbInput,
            UInt32 cbInput,
            Byte[] pbOutput,
            UInt32 cbOutput
        );

        [DllImport("Bcrypt.dll")]
        private extern static UInt32 BCryptGetProperty
        (
            IntPtr hObject,
            [MarshalAs(UnmanagedType.LPWStr)] String pszProperty,
            Byte[] pbOutput,
            UInt32 cbOutput,
            ref UInt32 pcbResult,
            UInt32 dwFlags
        );
        #endregion
    }
}
