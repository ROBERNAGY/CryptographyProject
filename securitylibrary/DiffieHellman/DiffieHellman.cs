using System;
using System.Collections.Generic;
using System.Numerics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> k = new List<int>() { };
            BigInteger g = new BigInteger(alpha);
            BigInteger a = new BigInteger(xa);
            BigInteger b = new BigInteger(xb);

            BigInteger public1 = BigInteger.ModPow(g, a, q);
            BigInteger public2 = BigInteger.ModPow(g, b, q);

            BigInteger private1 = BigInteger.ModPow(public2, a, q);
            BigInteger private2 = BigInteger.ModPow(public1, b, q);

            int k1 = (int)private1;
            int k2 = (int)private2;

            k.Add(k1);
            k.Add(k2);
            return k;
        }
    }
}
