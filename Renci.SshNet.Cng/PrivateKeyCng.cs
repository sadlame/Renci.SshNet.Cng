using System;
using Renci.SshNet.Security;

namespace Renci.SshNet
{
    public class PrivateKeyCng : IPrivateKeySource
    {
        public HostAlgorithm HostKey { get; private set; }

        public PrivateKeyCng(String providerName, String keyName)
        {
            HostKey = new CngHostAlgorithm(providerName, keyName);
        }
    }
}
