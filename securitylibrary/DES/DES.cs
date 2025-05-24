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
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[,,] sBox = {
                {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },
                {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
            };

            string[] reversedKeys = new string[16];
            string binaryPlain = "", plainByte = "", plainText = "0x";
            int reverse = 15;

            string[] permutedKeys = KeyPermutation(key);
            for (int k = 0; k < 16; k++)
            {
                reversedKeys[reverse] = permutedKeys[k];
                reverse--;
            }

            binaryPlain += MsgPermutation(reversedKeys, cipherText, sBox);
            for (int i = 0; i < binaryPlain.Length; i += 4)
            {
                plainByte += binaryPlain[i];
                plainByte += binaryPlain[i + 1];
                plainByte += binaryPlain[i + 2];
                plainByte += binaryPlain[i + 3];

                plainText += BinToHex(plainByte);
                plainByte = "";
            }
            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            int[,,] sBox = {
                {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },
                {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
            };

            string cipherText = "0x", binaryCipher = "", cipherByte = "";

            string[] permutedKes = KeyPermutation(key);
            binaryCipher += MsgPermutation(permutedKes, plainText, sBox);

            for (int i = 0; i < binaryCipher.Length; i += 4)
            {
                cipherByte += binaryCipher[i];
                cipherByte += binaryCipher[i + 1];
                cipherByte += binaryCipher[i + 2];
                cipherByte += binaryCipher[i + 3];

                cipherText += BinToHex(cipherByte);
                cipherByte = "";
            }
            return cipherText;
        }

        private string[] KeyPermutation(string key)
        {
            string binaryKey = "";
            binaryKey += HexToBin(key);

            string kPlus = "";
            string[] C = new string[17];
            string[] D = new string[17];
            string[] finalKeys = new string[16];
            string[] CD = new string[17];
            int index = 64 - 8 + 1;
            int shift = 2;

            //key permutation choice 1
            for (int i = 0; i < 56; i++)
            {
                if (index < 0 && i < 28)
                    index += (64 + 1);
                else if (i == 28)
                    index = 63;
                else if (index < 0 && i > 28 && index != -3)
                    index += (64 - 1);
                else if (index == -3)
                    index = 28;
                kPlus += binaryKey[index - 1];                     // -1 for 0 base
                index -= 8;

                if (i < 28)
                    C[0] += kPlus[i];
                else
                    D[0] += kPlus[i];
            }

            CD[0] += C[0];
            CD[0] += D[0];

            //C & D shift left permutation
            for (int cdNum = 1; cdNum <= 16; cdNum++)
            {
                if (cdNum == 1 || cdNum == 2 || cdNum == 9 || cdNum == 16)
                    shift = 1;

                //
                for (int bits = 0; bits < 28 - shift; bits++)
                {
                    C[cdNum] += C[cdNum - 1][bits + shift];
                    D[cdNum] += D[cdNum - 1][bits + shift];
                }
                C[cdNum] += C[cdNum - 1][0];
                D[cdNum] += D[cdNum - 1][0];

                if (shift == 2)
                {
                    C[cdNum] += C[cdNum - 1][1];
                    D[cdNum] += D[cdNum - 1][1];
                }
                shift = 2;
                //concatenate C & D = CnDn
                CD[cdNum] += C[cdNum];
                CD[cdNum] += D[cdNum];
            }

            //key permutation choice 2
            for (int n = 0; n < 16; n++)
            {
                finalKeys[n] += CD[n + 1][14 - 1];
                finalKeys[n] += CD[n + 1][17 - 1];
                finalKeys[n] += CD[n + 1][11 - 1];
                finalKeys[n] += CD[n + 1][24 - 1];
                finalKeys[n] += CD[n + 1][1 - 1];
                finalKeys[n] += CD[n + 1][5 - 1];
                finalKeys[n] += CD[n + 1][3 - 1];
                finalKeys[n] += CD[n + 1][28 - 1];
                finalKeys[n] += CD[n + 1][15 - 1];
                finalKeys[n] += CD[n + 1][6 - 1];
                finalKeys[n] += CD[n + 1][21 - 1];
                finalKeys[n] += CD[n + 1][10 - 1];
                finalKeys[n] += CD[n + 1][23 - 1];
                finalKeys[n] += CD[n + 1][19 - 1];
                finalKeys[n] += CD[n + 1][12 - 1];
                finalKeys[n] += CD[n + 1][4 - 1];
                finalKeys[n] += CD[n + 1][26 - 1];
                finalKeys[n] += CD[n + 1][8 - 1];
                finalKeys[n] += CD[n + 1][16 - 1];
                finalKeys[n] += CD[n + 1][7 - 1];
                finalKeys[n] += CD[n + 1][27 - 1];
                finalKeys[n] += CD[n + 1][20 - 1];
                finalKeys[n] += CD[n + 1][13 - 1];
                finalKeys[n] += CD[n + 1][2 - 1];
                finalKeys[n] += CD[n + 1][41 - 1];
                finalKeys[n] += CD[n + 1][52 - 1];
                finalKeys[n] += CD[n + 1][31 - 1];
                finalKeys[n] += CD[n + 1][37 - 1];
                finalKeys[n] += CD[n + 1][47 - 1];
                finalKeys[n] += CD[n + 1][55 - 1];
                finalKeys[n] += CD[n + 1][30 - 1];
                finalKeys[n] += CD[n + 1][40 - 1];
                finalKeys[n] += CD[n + 1][51 - 1];
                finalKeys[n] += CD[n + 1][45 - 1];
                finalKeys[n] += CD[n + 1][33 - 1];
                finalKeys[n] += CD[n + 1][48 - 1];
                finalKeys[n] += CD[n + 1][44 - 1];
                finalKeys[n] += CD[n + 1][49 - 1];
                finalKeys[n] += CD[n + 1][39 - 1];
                finalKeys[n] += CD[n + 1][56 - 1];
                finalKeys[n] += CD[n + 1][34 - 1];
                finalKeys[n] += CD[n + 1][53 - 1];
                finalKeys[n] += CD[n + 1][46 - 1];
                finalKeys[n] += CD[n + 1][42 - 1];
                finalKeys[n] += CD[n + 1][50 - 1];
                finalKeys[n] += CD[n + 1][36 - 1];
                finalKeys[n] += CD[n + 1][29 - 1];
                finalKeys[n] += CD[n + 1][32 - 1];
            }

            return finalKeys;
        }

        private string MsgPermutation(string[] keys, string msg, int[,,] sBox)
        {
            string binaryMsg = "", IP = "", cipher = "";
            string[] left = new string[32];
            string[] right = new string[32];
            string eRight = "", xor = "", f = "", permutedF = "";
            string RL = "";

            binaryMsg += HexToBin(msg);

            int index = 64 - 8 + 2;
            for (int i = 0; i < 64; i++)
            {
                if (i == 32)
                    index = 64 - 8 + 1;
                else if (index < 1)
                    index += (64 + 2);
                IP += binaryMsg[index - 1];
                index -= 8;

                if (i < 32)
                    left[0] += IP[i];
                else
                    right[0] += IP[i];
            }

            for (int j = 1; j < 17; j++)
            {
                left[j] = right[j - 1];
                eRight = EBitSelection(right[j - 1], eRight);
                xor = XOR(keys[j - 1], eRight);
                f = F_SBox(xor, sBox);
                permutedF = FPermutation(f);
                right[j] = XOR(left[j - 1], permutedF);

                eRight = "";
                xor = "";
                f = "";
                permutedF = "";
            }
            RL += right[16];
            RL += left[16];

            cipher += InversePermutation(RL);
            return cipher;
        }

        private string HexToBin(string hex)
        {
            string bin = "";
            int hexNum;

            //i = 2 to discard 0x (the begining of hex number)
            for (int i = 2; i < hex.Length; i++)
            {
                if (hex[i] == 'A')
                    bin += "1010";
                else if (hex[i] == 'B')
                    bin += "1011";
                else if (hex[i] == 'C')
                    bin += "1100";
                else if (hex[i] == 'D')
                    bin += "1101";
                else if (hex[i] == 'E')
                    bin += "1110";
                else if (hex[i] == 'F')
                    bin += "1111";
                else
                {
                    int count = 0;
                    string oneByte = "";
                    hexNum = hex[i] - '0';

                    while (count < 4)
                    {
                        if (hexNum == 0)
                        {
                            oneByte += '0';
                            count++;
                            continue;
                        }                                       // oneByte = 1010
                        oneByte += (hexNum % 2).ToString();   // hexNum = 5/2 = 2/2 = 1/2 = 0
                        hexNum /= 2;
                        count++;
                    }
                    bin += oneByte[3];
                    bin += oneByte[2];
                    bin += oneByte[1];
                    bin += oneByte[0];
                }
            }
            return bin;
        }

        private string XOR(string first, string second)
        {
            string xor = "";
            for (int i = 0; i < second.Length; i++)
            {
                if (second[i] == first[i])
                    xor += '0';
                else
                    xor += '1';
            }

            return xor;
        }

        private int BinToDec(string bin)
        {
            double result = 0;
            int index = bin.Length - 1;
            for (int i = 0; i < bin.Length; i++)
            {
                if (bin[i] == '1')
                    result += (Math.Pow(2, index));
                index--;
            }
            int dec = Convert.ToInt32(result);
            return dec;
        }

        private string DecToBin(int dec)
        {
            string bin = "";
            int count = 0;
            string oneByte = "";

            while (count < 4)
            {
                if (dec == 0)
                {
                    oneByte += '0';
                    count++;
                    continue;
                }
                oneByte += (dec % 2).ToString();
                dec /= 2;
                count++;
            }
            bin += oneByte[3];
            bin += oneByte[2];
            bin += oneByte[1];
            bin += oneByte[0];

            return bin;
        }

        private string BinToHex(string bin)
        {
            string hex = "", temp = "";
            int dec = BinToDec(bin);

            if (dec > 9)
            {
                temp = dec.ToString();
                if (temp == "10")
                    hex += "A";
                else if (temp == "11")
                    hex += "B";
                else if (temp == "12")
                    hex += "C";
                else if (temp == "13")
                    hex += "D";
                else if (temp == "14")
                    hex += "E";
                if (temp == "15")
                    hex += "F";
                return hex;
            }
            hex += dec.ToString();
            return hex;
        }

        private string EBitSelection(string oldRight, string eRight)
        {
            eRight += oldRight[31];
            int i = 0;

            for (; i < 32;)
            {
                eRight += oldRight[i];
                if ((i + 1) % 4 == 0 && i != 31)
                {
                    eRight += oldRight[i + 1];
                    eRight += oldRight[i];
                    eRight += oldRight[i + 1];

                    i += 2;
                    continue;
                }
                i++;
            }
            eRight += oldRight[0];
            return eRight;
        }

        private string F_SBox(string xor, int[,,] sBox)
        {
            string f = "";
            string[] rows = new string[8];
            string[] cols = new string[8];
            int rowNum, colNum, sValue;

            for (int i = 0; i < 48; i++)
            {
                if (i % 6 == 0 || (i + 1) % 6 == 0)
                    rows[i / 6] += xor[i];
                else
                    cols[i / 6] += xor[i];
            }

            for (int j = 0; j < 8; j++)
            {
                rowNum = BinToDec(rows[j]);
                colNum = BinToDec(cols[j]);

                sValue = sBox[j, rowNum, colNum];
                f += DecToBin(sValue);
            }

            return f;
        }

        private string FPermutation(string f)
        {
            string permutedF = "";

            permutedF += f[16 - 1];
            permutedF += f[7 - 1];
            permutedF += f[20 - 1];
            permutedF += f[21 - 1];
            permutedF += f[29 - 1];
            permutedF += f[12 - 1];
            permutedF += f[28 - 1];
            permutedF += f[17 - 1];
            permutedF += f[1 - 1];
            permutedF += f[15 - 1];
            permutedF += f[23 - 1];
            permutedF += f[26 - 1];
            permutedF += f[5 - 1];
            permutedF += f[18 - 1];
            permutedF += f[31 - 1];
            permutedF += f[10 - 1];
            permutedF += f[2 - 1];
            permutedF += f[8 - 1];
            permutedF += f[24 - 1];
            permutedF += f[14 - 1];
            permutedF += f[32 - 1];
            permutedF += f[27 - 1];
            permutedF += f[3 - 1];
            permutedF += f[9 - 1];
            permutedF += f[19 - 1];
            permutedF += f[13 - 1];
            permutedF += f[30 - 1];
            permutedF += f[6 - 1];
            permutedF += f[22 - 1];
            permutedF += f[11 - 1];
            permutedF += f[4 - 1];
            permutedF += f[25 - 1];

            return permutedF;
        }

        private string InversePermutation(string RL)
        {
            string inverseIP = "";
            int index = 40;

            for (int i = 0; i < 64; i++)
            {
                inverseIP += RL[index - 1];

                if ((i + 1) % 8 == 0)
                {
                    index += 7;
                    continue;
                }
                if (i % 2 == 0)
                    index -= 32;
                else
                    index += 40;
            }
            return inverseIP;
        }

    }
}