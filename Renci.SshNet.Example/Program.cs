using System;
using Renci.SshNet;
using Renci.SshNet.Cng;

namespace Sample1
{
    class Program
    {
        private Program()
        {

        }

        private void EnumerateProviders()
        {
            String[] providers = NCryptStorageProvider.EnumProviders();

            foreach (String provider in providers)
            {
                Console.WriteLine(provider);
            }
        }

        private String SelectProvider()
        {
            String[] providerNames = NCryptStorageProvider.EnumProviders();

            int providerIndex = SelectFromMenu("Choose a Key Storage Provider", providerNames);

            return providerNames[providerIndex];
        }

        private void EnumerateKeys()
        {
            using (NCryptStorageProvider provider = new NCryptStorageProvider(SelectProvider()))
            {
                String[] keyNames = provider.EnumKeys();

                foreach (String keyName in keyNames)
                {
                    Console.WriteLine(keyName);
                }
            }
        }

        private void CreateKey()
        {
            using (NCryptStorageProvider provider = new NCryptStorageProvider(SelectProvider()))
            {
                Console.WriteLine("Enter a name for the new key:");

                String keyName = Console.ReadLine();

                provider.OpenOrCreateKey(keyName);

                Console.WriteLine("Key \"{0}\" created.", keyName);
            }
        }

        private String SelectKey(NCryptStorageProvider provider)
        {
            String[] keyNames = provider.EnumKeys();

            int keyIndex = SelectFromMenu("Choose a key", keyNames);

            return keyNames[keyIndex];
        }

        private void ExportKey()
        {
            using (NCryptStorageProvider provider = new NCryptStorageProvider(SelectProvider()))
            {
                using (NCryptKey key = provider.OpenKey(SelectKey(provider)))
                {
                    Console.WriteLine(key.ExportToOpenSSHFormat("ssh-rsa", ""));
                }
            }
        }

        private void DeleteKey()
        {
            using (NCryptStorageProvider provider = new NCryptStorageProvider(SelectProvider()))
            {
                using (NCryptKey key = provider.OpenKey(SelectKey(provider)))
                {
                    key.Delete();
                }
            }
        }

        private void Login()
        {
            String providerName = SelectProvider();
            String keyName;
            using (NCryptStorageProvider provider = new NCryptStorageProvider(providerName))
            {
                keyName = SelectKey(provider);
            }

            Console.WriteLine("Enter hostname:");
            String hostname = Console.ReadLine();
            if (hostname.Length == 0)
                return;

            Console.WriteLine("Enter username:");
            String username = Console.ReadLine();
            if (username.Length == 0)
                return;

            Console.WriteLine("Logging into {0}@{1}...", username, hostname);

            using (SshClient client = new SshClient(hostname, username, new PrivateKeyCng(providerName, keyName)))
            {
                client.Connect();

                Console.WriteLine("Successfully connected to host.");

                client.RunCommand("echo 'Hello World!!'");

                client.Disconnect();
            }
        }

        private void Run(String[] args)
        {
            Console.WriteLine("This is a sample program to demonstrate the usage of SshNet.Cng.");

            while (true)
            {
                switch (SelectFromMenu("What would you like to do?", new String[]
                {
                    "Enumerate Key Storage Providers on your system",
                    "Enumerate keys stored in a Key Storage Provider",
                    "Create a new key in a Key Storage Provider",
                    "Export a key in a Key Storage Provider",
                    "Delete a key in a Key Storage Provider",
                    "Attempt an SSH Login to a remote host",
                    "Quit application"
                }))
                {
                case 0:
                    EnumerateProviders();
                    break;
                case 1:
                    EnumerateKeys();
                    break;
                case 2:
                    CreateKey();
                    break;
                case 3:
                    ExportKey();
                    break;
                case 4:
                    DeleteKey();
                    break;
                case 5:
                    Login();
                    break;
                case 6:
                    return;
                }
            }
        }

        static void Main(String[] args)
        {
            Program program = new Program();

            program.Run(args);
        }

        private static int SelectFromMenu(String prompt, String[] options)
        {
            Console.WriteLine(prompt);
            Console.WriteLine("(Enter number and press ENTER):");

            for (int i = 0; i < options.Length; i++)
            {
                Console.WriteLine("{0:d}: {1}", i + 1, options[i]);
            }

            while (true)
            {
                int choice = Convert.ToInt32(Console.ReadLine());
                if (1 <= choice && choice <= options.Length)
                    return choice - 1;
                Console.WriteLine("Invalid choice. Try again.");
            }
        }
    }
}
