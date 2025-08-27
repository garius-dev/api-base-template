using Ganss.Xss;
using GariusWeb.Api.Application.Exceptions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.WebUtilities;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace GariusWeb.Api.Extensions
{
    public static class TextExtensions
    {
        private static readonly HtmlSanitizer _sanitizer = new();

        public static string CreateOneTimeCode(int byteLen = 32)
        {
            if (byteLen < 32) throw new ArgumentOutOfRangeException(nameof(byteLen), "Use >= 32 bytes.");
            Span<byte> bytes = stackalloc byte[byteLen];
            RandomNumberGenerator.Fill(bytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        public static string? DecodeOneTimeCode(string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return null;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(code);
                return System.Text.Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                return null;
            }
        }

        public static bool TryGetCodeHash(string? code, out string hexHash)
        {
            hexHash = string.Empty;
            if (string.IsNullOrWhiteSpace(code)) return false;

            if (code.Length > 512) return false;

            try
            {
                byte[] codeBytes = WebEncoders.Base64UrlDecode(code);
                byte[] hash = SHA256.HashData(codeBytes);
                hexHash = Convert.ToHexString(hash);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string SanitizeInput(this string input)
        {
            return string.IsNullOrEmpty(input)
                ? string.Empty
                : _sanitizer.Sanitize(input);
        }

        public static string ToFormattedErrorString(this ModelStateDictionary modelState)
        {
            if (modelState?.IsValid != false)
                return string.Empty;

            var sb = new StringBuilder();

            foreach (var entry in modelState)
            {
                var fieldKey = entry.Key;
                var errors = entry.Value.Errors;

                foreach (var error in errors)
                {

                    var errorMessage = !string.IsNullOrWhiteSpace(error.ErrorMessage)
                        ? error.ErrorMessage
                        : error.Exception?.Message ?? "Erro desconhecido";


                    sb.Append($"{errorMessage}; ");
                }
            }

            // Remove o último "; " se houver
            if (sb.Length >= 2)
                sb.Length -= 2;

            return sb.ToString();
        }

        public static string MaskConnectionString(this string? connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                return string.Empty;

            var parts = connectionString.Split(';');

            return string.Join(';', parts.Select(p =>
                p.StartsWith("Password=", StringComparison.OrdinalIgnoreCase) ? "Password=***" : p));
        }

        public static bool ToBoolean(this string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            return value.Trim().ToLower(CultureInfo.InvariantCulture) switch
            {
                "true" => true,
                "1" => true,
                "yes" => true,
                "y" => true,
                _ => false,
            };
        }
    }
}