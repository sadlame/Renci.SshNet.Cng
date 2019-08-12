using System;
using System.IO;
using System.Text;
using Renci.SshNet.Cng;

namespace Renci.SshNet.Security
{
    public class CngHostAlgorithm : HostAlgorithm
    {
        private NCryptKey key;
        private BCryptAlgorithmProvider hashAlgorithm;

        public override Byte[] Data
        {
            get
            {
                return key.ExportBlob(Name);
            }
        }

        public CngHostAlgorithm(String providerName, String keyName)
            : base("ssh-rsa")
        {
            using (NCryptStorageProvider provider = new NCryptStorageProvider(providerName))
            {
                key = provider.OpenKey(keyName);
            }
            hashAlgorithm = new BCryptAlgorithmProvider("SHA1");
        }

        private static UInt32 ReverseEndianness(UInt32 src)
        {
            UInt32 dest = 0;
            dest = (src & 0x000000FF) << 24;
            dest |= (src & 0x0000FF00) << 8;
            dest |= (src & 0x00FF0000) >> 8;
            dest |= (src & 0xFF000000) >> 24;
            return dest;
        }

        public override Byte[] Sign(Byte[] data)
        {
            Byte[] signature = key.SignHash(hashAlgorithm, data);

            using (MemoryStream stream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    writer.Write(ReverseEndianness(7));
                    writer.Write(Encoding.ASCII.GetBytes(Name));
                    writer.Write(ReverseEndianness((UInt32)signature.Length));
                    writer.Write(signature);
                }
                return stream.ToArray();
            }
        }

        public override Boolean VerifySignature(Byte[] data, Byte[] signature)
        {
            Byte[] signatureData;
            using (MemoryStream stream = new MemoryStream(signature))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    UInt32 nameLength = ReverseEndianness(reader.ReadUInt32());
                    reader.ReadBytes((Int32)nameLength);
                    UInt32 signatureLength = ReverseEndianness(reader.ReadUInt32());
                    signatureData = reader.ReadBytes((Int32)signatureLength);
                }
            }
            return key.VerifySignature(hashAlgorithm, data, signatureData);
        }
    }
}
