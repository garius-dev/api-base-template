using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using HashidsNet;
using Microsoft.Extensions.Options;
using System;
using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;
using static GariusWeb.Api.Configuration.AppSecretsConfiguration;

namespace GariusWeb.Api.Application.Services
{
    public class HashIdService : IHashIdService
    {
        private readonly byte[] _saltBytes;

        public HashIdService(IOptions<HashidSettings> hashidSettings)
        {
            var saltString = hashidSettings.Value.SecretKey;

            if (string.IsNullOrWhiteSpace(saltString))
            {
                throw new InternalServerErrorAppException("Url Decoder Error.");
            }

            using (var sha256 = SHA256.Create())
            {
                var hashedSalt = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltString));
                _saltBytes = new byte[16];
                Array.Copy(hashedSalt, 0, _saltBytes, 0, 16);
            }
        }
        public Guid DecodeGuid(string encoded)
        {
            if (string.IsNullOrWhiteSpace(encoded) || encoded.Length != 22)
                throw new InternalServerErrorAppException("Url Decoder Error.");

            string base64 = encoded.Replace('-', '+').Replace('_', '/') + "==";
            byte[] bytes = Convert.FromBase64String(base64);

            var originalBytes = XorBytes(bytes);
            return new Guid(originalBytes);
        }

        public string EncodeGuid(Guid guid)
        {
            var guidBytes = guid.ToByteArray();
            var xoredBytes = XorBytes(guidBytes);

            string base64 = Convert.ToBase64String(xoredBytes);
            base64 = base64.Replace('+', '-').Replace('/', '_');
            return base64.Substring(0, 22);
        }

        private byte[] XorBytes(byte[] inputBytes)
        {
            var resultBytes = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                resultBytes[i] = (byte)(inputBytes[i] ^ _saltBytes[i]);
            }
            return resultBytes;
        }
    }
}
