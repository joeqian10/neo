using Neo.IO;
using Neo.Network.P2P.Payloads;
using ECPoint = Neo.Cryptography.ECC.ECPoint;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Security.Cryptography;

namespace Neo.Cryptography
{
    /// <summary>
    /// A helper class for cryptography
    /// </summary>
    public static class Helper
    {
        /// <summary>
        /// Computes the hash value for the specified byte array using the ripemd160 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] RIPEMD160(this byte[] value)
        {
            using var ripemd160 = new RIPEMD160Managed();
            return ripemd160.ComputeHash(value);
        }

        /// <summary>
        /// Computes the hash value for the specified byte array using the ripemd160 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] RIPEMD160(this ReadOnlySpan<byte> value)
        {
            byte[] source = value.ToArray();
            return source.RIPEMD160();
        }

        /// <summary>
        /// Computes the hash value for the specified byte array using the murmur algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <param name="seed">The seed used by the murmur algorithm.</param>
        /// <returns>The computed hash code.</returns>
        public static uint Murmur32(this byte[] value, uint seed)
        {
            using Murmur3 murmur = new(seed);
            return BinaryPrimitives.ReadUInt32LittleEndian(murmur.ComputeHash(value));
        }

        /// <summary>
        /// Computes the hash value for the specified byte array using the sha256 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] Sha256(this byte[] value)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(value);
        }

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array using the sha256 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <param name="offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="count">The number of bytes in the array to use as data.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] Sha256(this byte[] value, int offset, int count)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(value, offset, count);
        }

        /// <summary>
        /// Computes the hash value for the specified byte array using the sha256 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] Sha256(this ReadOnlySpan<byte> value)
        {
            byte[] buffer = new byte[32];
            using var sha256 = SHA256.Create();
            sha256.TryComputeHash(value, buffer, out _);
            return buffer;
        }

        /// <summary>
        /// Computes the hash value for the specified byte array using the sha256 algorithm.
        /// </summary>
        /// <param name="value">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static byte[] Sha256(this Span<byte> value)
        {
            return Sha256((ReadOnlySpan<byte>)value);
        }

        internal static bool Test(this BloomFilter filter, Transaction tx)
        {
            if (filter.Check(tx.Hash.ToArray())) return true;
            if (tx.Signers.Any(p => filter.Check(p.Account.ToArray())))
                return true;
            return false;
        }

        internal static byte[] ToAesKey(this string password)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] passwordHash = sha256.ComputeHash(passwordBytes);
            byte[] passwordHash2 = sha256.ComputeHash(passwordHash);
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
            Array.Clear(passwordHash, 0, passwordHash.Length);
            return passwordHash2;
        }

        internal static byte[] ToAesKey(this SecureString password)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] passwordBytes = password.ToArray();
            byte[] passwordHash = sha256.ComputeHash(passwordBytes);
            byte[] passwordHash2 = sha256.ComputeHash(passwordHash);
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
            Array.Clear(passwordHash, 0, passwordHash.Length);
            return passwordHash2;
        }

        internal static byte[] ToArray(this SecureString s)
        {
            if (s == null)
                throw new NullReferenceException();
            if (s.Length == 0)
                return Array.Empty<byte>();
            List<byte> result = new();
            IntPtr ptr = SecureStringMarshal.SecureStringToGlobalAllocAnsi(s);
            try
            {
                int i = 0;
                do
                {
                    byte b = Marshal.ReadByte(ptr, i++);
                    if (b == 0)
                        break;
                    result.Add(b);
                } while (true);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(ptr);
            }
            return result.ToArray();
        }

        public static byte[] AES256Decrypt(this byte[] block, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(block, 0, block.Length);
                }
            }
        }

        public static byte[] AES256Encrypt(this byte[] block, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(block, 0, block.Length);
                }
            }
        }

        public static byte[] ECEncrypt(byte[] message, ECPoint pubKey)
        {
            // 1. choose a random number, k < n
            BigInteger k, r;
            ECPoint R;
            var curve = pubKey.Curve;
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                do
                {
                    do
                    {
                        k = rng.NextBigInteger((int)curve.N.GetBitLength());
                    }
                    while (k.Sign == 0 || k.CompareTo(curve.N) >= 0);
                    R = ECPoint.Multiply(curve.G, k);
                    BigInteger x = R.X.Value;
                    r = x.Mod(curve.N);
                }
                while (r.Sign == 0);
            }

            // 2. using point compression for R
            byte[] RBar = R.EncodePoint(true);

            // 3. get the shared secret field element
            var z = ECPoint.Multiply(pubKey, k).X; // z = k * v.pubKey = k * d * G

            // 4. get Z
            var Z = z.ToByteArray();

            // 5. using KDF, todo

            // 6. get EK, using sha256 instead
            var EK = Z.Sha256();

            // 7. encrypt M under EK as EM
            var EM = message.AES256Encrypt(EK);

            // 8. get tag D, skip

            // 9. concat
            return RBar.Concat(EM).ToArray();
        }

        public static byte[] ECDecrypt(byte[] cypher, byte[] priKey, ECPoint pubKey)
        {
            // 1. get RBar, since using encoded format, lenght is 33, starting with 0x02 or 0x03
            if (cypher is null || cypher.Length < 33)
                throw new ArgumentException();
            if (cypher[0] != 0x02 && cypher[0] != 0x03)
                throw new ArgumentException();
            var RBar = cypher.Take(33).ToArray();
            var EM = cypher.Skip(33).ToArray();

            // 2. convert RBar to ECPoint R
            var R = ECPoint.FromBytes(RBar, pubKey.Curve);

            // 3. validate R, skip

            // 4. get z
            var d = new BigInteger(priKey.Reverse().Concat(new byte[1]).ToArray());
            var z = ECPoint.Multiply(R, d).X; // z = d * R = d * k * G

            // 5. get Z
            var Z = z.ToByteArray();

            // 6. using KDF, todo

            // 7. get EK, using sha256 instead
            var EK = Z.Sha256();

            // 8. get D, skip

            // 9. decrypt EM under EK as M
            var M = EM.AES256Decrypt(EK);

            // 10. return M
            return M;
        }
    }
}
