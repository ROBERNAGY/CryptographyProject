using System;
using System.Collections.Generic;
using System.Numerics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipher = new List<long>();
            int K = (int)(BigInteger.Pow(y, k) % q);  // K = (Yb ^ k) % q
            int c1 = (int)(BigInteger.Pow(alpha, k) % q);  // c1 = (alpha ^ k) % q
            int c2 = (int)(BigInteger.Multiply(K, m) % q);  // c2 = (K*m) % q
            cipher.Add(c1);
            cipher.Add(c2);
            return cipher;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            int K = (int)(BigInteger.Pow(c1, x) % q);  // K = (c1 ^ x) % q
            int invK = extendedEuclid.GetMultiplicativeInverse(K, q);  // Inverse K = (K ^ -1)
            int m = (int)BigInteger.Multiply(c2, invK) % q;  // m = (c2 * invK) % q
            return m;

        }
    }
}