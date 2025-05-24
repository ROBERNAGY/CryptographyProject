using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            long n = p * q;
            return (int)BigInteger.ModPow(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            long n = p * q;
            BigInteger fn = BigInteger.Multiply(p - 1, q - 1);
            long eInverse = MultiplicativeInverse(e, (int)fn);
            long d =Mod(eInverse, (long)fn);
            return (int)BigInteger.ModPow(C, d, n);
        }
        public static int MultiplicativeInverse(int n, int mod)
        {
            ExtendedEuclid extendedEuclidean = new ExtendedEuclid();
            int result = extendedEuclidean.GetMultiplicativeInverse((int)Mod(n, mod), mod);

            if (result == -1)
                throw new Exception("no inverse");

            return result;
        }

        public static long Mod(long number, long mod)
        {
            if (number >= 0)
            {
                return number % mod;
            }
            else
            {
                long temp = -number % mod;
                return -temp + mod;
            }
        }
    }
}
