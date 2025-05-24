using System;
using System.Collections.Generic;
using System.Numerics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            bool indicator = true;
            byte[] Sbox = getSBoxMatrix(indicator);

            string[,] mat1 = new string[4, 4];
            mat1 = PutTheStringsInMatrix(cipherText, 2);

            string[,] mat2 = new string[4, 4];
            mat2 = PutTheStringsInMatrix(key, 2);

            mat1 = XOR(mat2, mat1);

            for (int loop = 10; loop >= 1; loop--)
            {

                mat1 = shiftMatrix(mat1, indicator);

                byte[,] mat1Bytes = new byte[4, 4];
                GetFromSbox(ref mat1, ref mat1Bytes, Sbox);

                string[] rotword = new string[4];
                rotword = getRotword(mat2);
                GetFromSboxForRotword(ref rotword, Sbox);

                string[] racon = new string[4] { "01", "00", "00", "00" };
                getRacon(ref racon, loop, false);
                getRoundKey(ref mat2, rotword, racon);
                getRoundMatrix(ref mat2);

                mat1 = XOR(mat2, mat1);

                string[,] MixCoulmns = new string[4, 4];
                MixCoulmns = getMixCoulmnsMatrix(indicator);

                mat1 = mixCoulmns(MixCoulmns, mat1);

                if (loop == 1)
                {
                    mat1 = shiftMatrix(mat1, indicator);

                    GetFromSbox(ref mat1, ref mat1Bytes, Sbox);

                    getRacon(ref racon, loop, false);
                    getRoundKey(ref mat2, rotword, racon);
                    getRoundMatrix(ref mat2);

                    mat1 = XOR(mat2, mat1);
                }
            }
            string output = "";
            output = convertMatrixToString(mat1);
            return output;
        }

        public override string Encrypt(string plainText, string key)
        {
            bool indicator = false;
            byte[] Sbox = getSBoxMatrix(indicator);

            string[,] mat1 = new string[4, 4];
            mat1 = PutTheStringsInMatrix(plainText, 2);

            string[,] mat2 = new string[4, 4];
            mat2 = PutTheStringsInMatrix(key, 2);

            string[,] mat3 = new string[4, 4];
            mat3 = XOR(mat1, mat2);

            for (int loop = 1; loop <= 10; loop++)
            {
                byte[,] mat3Bytes = new byte[4, 4];
                GetFromSbox(ref mat3, ref mat3Bytes, Sbox);

                string[,] shiftedMat3 = new string[4, 4];
                shiftedMat3 = shiftMatrix(mat3, indicator);

                string[,] MixCoulmns = new string[4, 4];
                MixCoulmns = getMixCoulmnsMatrix(indicator);

                string[,] mixedMat3 = new string[4, 4];
                mixedMat3 = mixCoulmns(MixCoulmns, shiftedMat3);

                string[] rotword = new string[4];
                rotword = getRotword(mat2);
                GetFromSboxForRotword(ref rotword, Sbox);

                string[] racon = new string[4] { "01", "00", "00", "00" };
                getRacon(ref racon, loop, indicator);

                getRoundKey(ref mat2, rotword, racon);

                getRoundMatrix(ref mat2);

                if (loop != 10)
                {
                    mat3 = XOR(mat2, mixedMat3);
                }
                else
                {
                    mat3 = XOR(mat2, shiftedMat3);
                }
            }
            string output = "0x";
            output = convertMatrixToString(mat3);
            return output;
        }

        //step 1 choose the Sbox or the inverse
        static byte[] getSBoxMatrix(bool indicator)
        {
            if (!indicator)
            {
                byte[] Sbox = new byte[256]{
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            };

                return Sbox;
            }
            else
            {
                byte[] InverseSbox = new byte[256]{
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            };
                return InverseSbox;
            }
        }
        //step 2 convert string to matrix
        static string[,] PutTheStringsInMatrix(string str, int counter)
        {
            string[,] mat = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mat[j, i] = str[counter].ToString() + str[counter + 1].ToString();
                    counter += 2;
                }
            }
            return mat;
        }
        //step 3 XOR between plain and key
        static string[,] XOR(string[,] mat1, string[,] mat2)
        {
            string[,] mat = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mat[i, j] = Convert.ToString((Convert.ToInt64(mat2[i, j], 16) ^ Convert.ToInt64(mat1[i, j], 16)), 2);
                    mat[i, j] = String.Format("{0:X2}", Convert.ToUInt64(mat[i, j], 2));
                }
            }
            return mat;
        }
        //step 4 map the output of XOR with SBOX
        static void GetFromSbox(ref string[,] mat3, ref byte[,] mat_temp, byte[] Sbox)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = mat3[i, j];
                    byte inputByte = Convert.ToByte(hexValue, 16);
                    byte substitutedByte = Sbox[inputByte];
                    mat_temp[i, j] = substitutedByte;
                    mat3[i, j] = String.Format("{0:X2}", substitutedByte);
                }
            }
        }
        //step 5 shift the matrix left or right
        static string[,] shiftMatrix(string[,] mat3, bool indicator)
        {
            string[,] mat = new string[4, 4];
            if (!indicator)
            {
                for (int col = 0; col < 4; col++)
                {
                    mat[0, col] = mat3[0, col];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[1, col] = mat3[1, (col + 1) % 4];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[2, col] = mat3[2, (col + 2) % 4];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[3, col] = mat3[3, (col + 3) % 4];
                }
            }
            else
            {
                for (int col = 0; col < 4; col++)
                {
                    mat[0, col] = mat3[0, col];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[1, col] = mat3[1, (col + 3) % 4];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[2, col] = mat3[2, (col + 2) % 4];
                }
                for (int col = 0; col < 4; col++)
                {
                    mat[3, col] = mat3[3, (col + 1) % 4];
                }
            }

            return mat;
        }
        //step 6 get the shift matrix
        static string[,] getMixCoulmnsMatrix(bool indicator)
        {
            if (!indicator)
            {
                string[,] MixCoulmns = new string[4, 4] { { "02","03", "01" ,"01" },
                                                  { "01", "02", "03", "01" },
                                                  { "01", "01", "02", "03" },
                                                  { "03", "01", "01", "02" }};
                return MixCoulmns;
            }
            else
            {
                string[,] InverseMixColumns = new string[4, 4] {
                                { "0E", "0B", "0D", "09" },
                                { "09", "0E", "0B", "0D" },
                                { "0D", "09", "0E", "0B" },
                                { "0B", "0D", "09", "0E" } };
                return InverseMixColumns;
            }
        }
        //step 7 mix the shifted matrix with the coulmn matrix
        static string[,] mixCoulmns(string[,] MixCoulmns, string[,] shiftedMat3)
        {
            string[,] mixedMat = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    int shiftedValue1 = Convert.ToInt32(shiftedMat3[0, col], 16);
                    int shiftedValue2 = Convert.ToInt32(shiftedMat3[1, col], 16);
                    int shiftedValue3 = Convert.ToInt32(shiftedMat3[2, col], 16);
                    int shiftedValue4 = Convert.ToInt32(shiftedMat3[3, col], 16);

                    int mixValue1 = Convert.ToInt32(MixCoulmns[row, 0], 16);
                    int mixValue2 = Convert.ToInt32(MixCoulmns[row, 1], 16);
                    int mixValue3 = Convert.ToInt32(MixCoulmns[row, 2], 16);
                    int mixValue4 = Convert.ToInt32(MixCoulmns[row, 3], 16);

                    int product1 = GaloisMultiply(shiftedValue1, mixValue1);
                    int product2 = GaloisMultiply(shiftedValue2, mixValue2);
                    int product3 = GaloisMultiply(shiftedValue3, mixValue3);
                    int product4 = GaloisMultiply(shiftedValue4, mixValue4);

                    int result = product1 ^ product2 ^ product3 ^ product4;

                    mixedMat[row, col] = result.ToString("X2");
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (mixedMat[i, j].Length == 3)
                    {
                        mixedMat[i, j] = Convert.ToString(mixedMat[i, j][1]) + Convert.ToString(mixedMat[i, j][2]);
                    }
                }
            }
            return mixedMat;
        }
        //step 8 rotward
        static string[] getRotword(string[,] mat2)
        {
            string[] rotword = new string[4];
            for (int i = 0; i < 4; i++)
            {
                rotword[i] = mat2[(i + 1) % 4, 3];
            }
            return rotword;
        }
        //step 9 map in SBOX for rotward
        static void GetFromSboxForRotword(ref string[] roword, byte[] Sbox)
        {
            byte[] byte_roword = new byte[4];
            for (int i = 0; i < 4; i++)
            {

                string hexValue = roword[i];
                byte inputByte = Convert.ToByte(hexValue, 16);
                byte substitutedByte = Sbox[inputByte];
                byte_roword[i] = substitutedByte;
                roword[i] = String.Format("{0:X2}", substitutedByte);
            }
        }
        //step 10 racon
        static void getRacon(ref string[] racon, int loop, bool indicator)
        {
            if (indicator)
            {
                if (loop == 1)
                {
                    racon[0] = "36";
                }
                else if (loop == 2)
                {
                    racon[0] = "1B";
                }
                else if (loop == 3)
                {
                    racon[0] = "80";
                }
                else if (loop == 4)
                {
                    racon[0] = "40";
                }
                else if (loop == 5)
                {
                    racon[0] = "20";
                }
                else if (loop == 6)
                {
                    racon[0] = "10";
                }
                else if (loop == 7)
                {
                    racon[0] = "08";
                }
                else if (loop == 8)
                {
                    racon[0] = "04";
                }
                else if (loop == 9)
                {
                    racon[0] = "02";
                }
                else if (loop == 10)
                {
                    racon[0] = "01";
                }
            }
            else
            {
                if (loop == 1)
                {
                    racon[0] = "01";
                }
                else if (loop == 2)
                {
                    racon[0] = "02";
                }
                else if (loop == 3)
                {
                    racon[0] = "04";
                }
                else if (loop == 4)
                {
                    racon[0] = "08";
                }
                else if (loop == 5)
                {
                    racon[0] = "10";
                }
                else if (loop == 6)
                {
                    racon[0] = "20";
                }
                else if (loop == 7)
                {
                    racon[0] = "40";
                }
                else if (loop == 8)
                {
                    racon[0] = "80";
                }
                else if (loop == 9)
                {
                    racon[0] = "1B";
                }
                else if (loop == 10)
                {
                    racon[0] = "36";
                }
            }
        }
        //step 11 get the RoundKey
        static void getRoundKey(ref string[,] mat2, string[] rotword, string[] racon)
        {
            for (int i = 0; i < 4; i++)
            {
                mat2[i, 0] = Convert.ToString((Convert.ToInt64(rotword[i], 16) ^ Convert.ToInt64(mat2[i, 0], 16) ^ Convert.ToInt64(racon[i], 16)), 2);
                mat2[i, 0] = String.Format("{0:X2}", Convert.ToUInt64(mat2[i, 0], 2));
            }
        }
        //step 12 get the RoundMatrix
        static void getRoundMatrix(ref string[,] mat2)
        {
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mat2[j, i] = Convert.ToString((Convert.ToInt64(mat2[j, i - 1], 16) ^ Convert.ToInt64(mat2[j, i], 16)), 2);
                    mat2[j, i] = String.Format("{0:X2}", Convert.ToUInt64(mat2[j, i], 2));
                }
            }
        }
        //step 13 convert matrix to string
        static string convertMatrixToString(string[,] mat)
        {
            string str = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str += mat[j, i].ToString();
                }
            }
            return str;
        }
        static int GaloisMultiply(int a, int b)
        {
            int p = 0;
            int hiBitSet;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                {
                    p ^= a;
                }
                hiBitSet = (a & 0x80);
                a <<= 1;
                if (hiBitSet == 0x80)
                {
                    a ^= 0x1B; // AES polynomial x^8 + x^4 + x^3 + x + 1
                }
                b >>= 1;
            }
            return p;
        }
    }
}
