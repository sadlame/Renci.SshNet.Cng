using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Renci.SshNet.Cng
{
    public class NCryptKey : IDisposable
    {
        private IntPtr hKey = IntPtr.Zero;

        public NCryptKey(IntPtr _hKey)
        {
            hKey = _hKey;
        }

        private static UInt32 ReverseEndianness(UInt32 src)
        {
            UInt32 dest;
            dest = (src & 0x000000FF) << 24;
            dest |= (src & 0x0000FF00) << 8;
            dest |= (src & 0x00FF0000) >> 8;
            dest |= (src & 0xFF000000) >> 24;
            return dest;
        }

        public Byte[] ExportBlob(String keyName)
        {
            UInt32 cbOutput = 0;
            if (NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, null, 0, ref cbOutput, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptExportKey(null) failed.");
            }

            Byte[] keyBlob = new Byte[cbOutput];
            UInt32 cbResult = 0;
            if (NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, keyBlob, cbOutput, ref cbResult, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptExportKey(Byte[]) failed.");
            }

            GCHandle gch = GCHandle.Alloc(keyBlob, GCHandleType.Pinned);

            BCRYPT_RSAKEY_BLOB keyBlobHeader = (BCRYPT_RSAKEY_BLOB)Marshal.PtrToStructure(gch.AddrOfPinnedObject(), typeof(BCRYPT_RSAKEY_BLOB));

            gch.Free();

            using (MemoryStream blobStream = new MemoryStream())
            {
                using (BinaryWriter blobWriter = new BinaryWriter(blobStream))
                {
                    blobWriter.Write(ReverseEndianness(7));
                    blobWriter.Write(Encoding.ASCII.GetBytes(keyName));
                    Byte publicExpMsb = keyBlob[Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB))];
                    if ((publicExpMsb & 0x80) != 0)
                    {
                        blobWriter.Write(ReverseEndianness(keyBlobHeader.cbPublicExp + 1));
                        blobWriter.Write((Byte)0);
                    }
                    else
                    {
                        blobWriter.Write(ReverseEndianness(keyBlobHeader.cbPublicExp));
                    }
                    blobWriter.Write(keyBlob, Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB)), (int)keyBlobHeader.cbPublicExp);
                    Byte publicModMsb = keyBlob[Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB)) + (int)keyBlobHeader.cbPublicExp];
                    if ((publicModMsb & 0x80) != 0)
                    {
                        blobWriter.Write(ReverseEndianness(keyBlobHeader.cbModulus + 1));
                        blobWriter.Write((Byte)0);
                    }
                    else
                    {
                        blobWriter.Write(ReverseEndianness(keyBlobHeader.cbModulus));
                    }
                    blobWriter.Write(keyBlob, Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB)) + (int)keyBlobHeader.cbPublicExp, (int)keyBlobHeader.cbModulus);
                }

                return blobStream.ToArray();
            }
        }

        public String ExportToOpenSSHFormat(String keyName, String hostname = "")
        {
            return String.Format("{0} {1} {2}", keyName, Convert.ToBase64String(ExportBlob(keyName)), hostname);
        }

        public Byte[] SignHash(BCryptAlgorithmProvider hashAlgorithm, Byte[] data)
        {
            Byte[] hash = hashAlgorithm.ComputeHash(data);

            BCRYPT_PKCS1_PADDING_INFO paddingInfo = new BCRYPT_PKCS1_PADDING_INFO()
            {
                pszAlgId = "SHA1"
            };
            UInt32 cbResult = 0;
            if (NCryptSignHash(hKey, ref paddingInfo, hash, (UInt32)hash.Length, null, 0, ref cbResult, BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptSignHash(null) failed.");
            }
            Byte[] signature = new Byte[cbResult];
            if (NCryptSignHash(hKey, ref paddingInfo, hash, (UInt32)hash.Length, signature, (UInt32)signature.Length, ref cbResult, BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptSignHash(Byte[]) failed.");
            }
            return signature;
        }

        public Boolean VerifySignature(BCryptAlgorithmProvider hashAlgorithm, Byte[] data, Byte[] signature)
        {
            Byte[] hash = hashAlgorithm.ComputeHash(data);

            BCRYPT_PKCS1_PADDING_INFO paddingInfo = new BCRYPT_PKCS1_PADDING_INFO()
            {
                pszAlgId = "SHA1"
            };
            UInt32 hr = NCryptVerifySignature(hKey, ref paddingInfo, hash, (UInt32)hash.Length, signature, (UInt32)signature.Length, BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG);
            if (hr == NTE_BAD_SIGNATURE)
            {
                return false;
            }
            else if (hr != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptVerifySignature failed.");
            }
            return true;
        }

        public void Delete()
        {
            if (NCryptDeleteKey(hKey, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptDeleteKey failed.");
            }
            hKey = IntPtr.Zero;
        }

        public void Dispose()
        {
            if (hKey != IntPtr.Zero)
            {
                NCryptFreeObject(hKey);
                hKey = IntPtr.Zero;
            }
        }

        ~NCryptKey()
        {
            Dispose();
        }

        #region P/Invoke declarations
        private struct BCRYPT_RSAKEY_BLOB
        {
            public UInt32 Magic;
            public UInt32 BitLength;
            public UInt32 cbPublicExp;
            public UInt32 cbModulus;
            public UInt32 cbPrime1;
            public UInt32 cbPrime2;
        }

        private struct BCRYPT_PKCS1_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)] public String pszAlgId;
        }

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptSignHash
        (
            IntPtr hKey,
            ref BCRYPT_PKCS1_PADDING_INFO pPaddingInfo,
            Byte[] pbHashValue,
            UInt32 cbHashValue,
            Byte[] pbSignature,
            UInt32 cbSignature,
            ref UInt32 pcbResult,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptVerifySignature
        (
            IntPtr hKey,
            ref BCRYPT_PKCS1_PADDING_INFO pPaddingInfo,
            Byte[] pbHashValue,
            UInt32 cbHashValue,
            Byte[] pbSignature,
            UInt32 cbSignature,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptExportKey
        (
            IntPtr hKey,
            IntPtr hExportKey,
            [MarshalAs(UnmanagedType.LPWStr)] String pszBlobType,
            IntPtr pParameterList,
            Byte[] pbOutput,
            UInt32 cbOutput,
            ref UInt32 pcbResult,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptDeleteKey
        (
            IntPtr kKey,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptGetProperty
        (
            IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)] String pszProperty,
            Byte[] pbOutput,
            UInt32 cbOutput,
            ref UInt32 pcbResult,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptFreeObject
        (
            IntPtr hObject
        );

        private const UInt32 ERROR_SUCCESS = 0x00000000;
        private const UInt32 NCRYPT_SILENT_FLAG = 0x00000040;
        private const UInt32 BCRYPT_PAD_PKCS1 = 0x00000002;
        private const UInt32 NTE_BAD_SIGNATURE = 0x80090006;
        #endregion
    }
}
