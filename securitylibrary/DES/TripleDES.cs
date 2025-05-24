using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES algorithm = new DES();
            string step1 = algorithm.Decrypt(cipherText, key[0]);
            string step2 = algorithm.Encrypt(step1, key[1]);
            string plainText = algorithm.Decrypt(step2, key[0]);

            return plainText;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES algorithm = new DES();
            string step1 = algorithm.Encrypt(plainText, key[0]);
            string step2 = algorithm.Decrypt(step1, key[1]);
            string cipherText = algorithm.Encrypt(step2, key[0]);

            return cipherText;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
