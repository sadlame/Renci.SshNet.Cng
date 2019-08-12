using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Renci.SshNet.Cng
{
    public class NCryptStorageProvider : IDisposable
    {
        private IntPtr hProvider = IntPtr.Zero;

        public static String[] EnumProviders()
        {
            UInt32 dwProviderCount = 0;
            IntPtr providerNames = IntPtr.Zero;

            if (NCryptEnumStorageProviders(ref dwProviderCount, ref providerNames, 0) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptEnumStorageProviders failed.");
            }

            String[] providerNamesArray = new String[dwProviderCount];
            for (UInt32 i = 0; i < dwProviderCount; i++)
            {
                NCryptProviderName providerName = (NCryptProviderName)Marshal.PtrToStructure(new IntPtr(providerNames.ToInt64() + Marshal.SizeOf(typeof(NCryptProviderName)) * i), typeof(NCryptProviderName));

                providerNamesArray[i] = providerName.pszName;
            }

            if (NCryptFreeBuffer(providerNames) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptFreeBuffer failed.");
            }

            return providerNamesArray;
        }

        public NCryptStorageProvider(String providerName)
        {
            if (NCryptOpenStorageProvider(ref hProvider, providerName, 0) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptOpenStorageProvider failed.");
            }
        }

        public String[] EnumKeys(Boolean machineKeyFlag = false)
        {
            UInt32 dwFlags = NCRYPT_SILENT_FLAG;
            if (machineKeyFlag)
                dwFlags |= NCRYPT_MACHINE_KEY_FLAG;

            List<String> keyNames = new List<String>();
            IntPtr enumState = IntPtr.Zero;
            while (true)
            {
                IntPtr keyDataPtr = IntPtr.Zero;
                UInt32 hr = NCryptEnumKeys(hProvider, null, ref keyDataPtr, ref enumState, dwFlags);
                if (hr == NTE_NO_MORE_ITEMS)
                {
                    break;
                }
                else if (hr != ERROR_SUCCESS)
                {
                    throw new Win32Exception("NCryptEnumKeys failed.");
                }
                NCryptKeyName keyData = (NCryptKeyName)Marshal.PtrToStructure(keyDataPtr, typeof(NCryptKeyName));
                keyNames.Add(keyData.pszName);
                if (NCryptFreeBuffer(keyDataPtr) != ERROR_SUCCESS)
                {
                    throw new Win32Exception("NCryptFreeBuffer failed.");
                }
            }
            return keyNames.ToArray();
        }

        public NCryptKey CreateKey(String keyName, Boolean machineKeyFlag = false)
        {
            UInt32 dwFlags = NCRYPT_SILENT_FLAG;
            if (machineKeyFlag)
                dwFlags |= NCRYPT_MACHINE_KEY_FLAG;

            IntPtr hKey = IntPtr.Zero;
            if (NCryptCreatePersistedKey(hProvider, ref hKey, "RSA", keyName, 0, dwFlags) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptCreatePersistedKey failed.");
            }
            if (NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptFinalizeKey failed.");
            }
            return new NCryptKey(hKey);
        }

        public NCryptKey OpenKey(String keyName, Boolean machineKeyFlag = false)
        {
            UInt32 dwFlags = NCRYPT_SILENT_FLAG;
            if (machineKeyFlag)
                dwFlags |= NCRYPT_MACHINE_KEY_FLAG;

            IntPtr hKey = IntPtr.Zero;
            UInt32 hr = NCryptOpenKey(hProvider, ref hKey, keyName, 0, dwFlags);

            if (hr == NTE_BAD_KEYSET)
            {
                return null;
            }
            else if (hr != ERROR_SUCCESS)
            {
                throw new Win32Exception("NCryptOpenKey failed.");
            }
            return new NCryptKey(hKey);
        }

        public NCryptKey OpenOrCreateKey(String keyName, Boolean machineKeyFlag = false)
        {
            NCryptKey key = OpenKey(keyName, machineKeyFlag);

            if (key is null)
            {
                key = CreateKey(keyName, machineKeyFlag);
            }
            return key;
        }

        public Boolean DeleteKey(String keyName, Boolean machineKeyFlag = false)
        {
            NCryptKey key = OpenKey(keyName, machineKeyFlag);

            if (!(key is null))
            {
                key.Delete();
                return true;
            }
            return false;
        }

        public void Dispose()
        {
            if (hProvider != IntPtr.Zero)
            {
                NCryptFreeObject(hProvider);
                hProvider = IntPtr.Zero;
            }
        }

        ~NCryptStorageProvider()
        {
            Dispose();
        }

        #region P/Invoke declarations
        private struct NCryptProviderName
        {
            [MarshalAs(UnmanagedType.LPWStr)] public String pszName;
            [MarshalAs(UnmanagedType.LPWStr)] public String pszComment;
        }

        private struct NCryptKeyName
        {
            [MarshalAs(UnmanagedType.LPWStr)] public String pszName;
            [MarshalAs(UnmanagedType.LPWStr)] public String pszAlgId;
            UInt32 dwLegacyKeySpec;
            UInt32 dwFlags;
        }

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptEnumStorageProviders
        (
            ref UInt32 pdwProviderCount,
            ref IntPtr ppProviderList,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptOpenStorageProvider
        (
            ref IntPtr phProvider,
            [MarshalAs(UnmanagedType.LPWStr)] String pszProviderName,
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
        private extern static UInt32 NCryptEnumKeys
        (
            IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)] String pszScope,
            ref IntPtr ppKeyName,
            ref IntPtr ppEnumState,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptOpenKey
        (
            IntPtr hProvider,
            ref IntPtr phKey,
            [MarshalAs(UnmanagedType.LPWStr)] String pszKeyName,
            UInt32 dwLegacyKeySpec,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptCreatePersistedKey
        (
            IntPtr hProvider,
            ref IntPtr phKey,
            [MarshalAs(UnmanagedType.LPWStr)] String pszAlgId,
            [MarshalAs(UnmanagedType.LPWStr)] String pszKeyName,
            UInt32 dwLegacyKeySpec,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptFinalizeKey
        (
            IntPtr hKey,
            UInt32 dwFlags
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptFreeObject
        (
            IntPtr hObject
        );

        [DllImport("Ncrypt.dll")]
        private extern static UInt32 NCryptFreeBuffer
        (
            IntPtr pvInput
        );

        private const UInt32 ERROR_SUCCESS = 0x00000000;
        private const UInt32 NTE_BAD_KEYSET = 0x80090016;
        private const UInt32 NTE_NO_MORE_ITEMS = 0x8009002A;
        private const UInt32 NCRYPT_MACHINE_KEY_FLAG = 0x00000020;
        private const UInt32 NCRYPT_SILENT_FLAG = 0x00000040;
        #endregion
    }
}
