using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace GariusWeb.Api.Helpers.Attributes
{
    public class CNPJAttribute : ValidationAttribute
    {
        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is null)
                return ValidationResult.Success; // opcional

            var stringValue = value as string;
            if (string.IsNullOrWhiteSpace(stringValue))
                return ValidationResult.Success; // opcional

            var cnpj = stringValue
                .Replace(".", string.Empty)
                .Replace("/", string.Empty)
                .Replace("-", string.Empty);

            if (!IsCnpjValid(cnpj))
                return new ValidationResult(ErrorMessage ?? "CNPJ inválido.");

            return ValidationResult.Success;
        }

        private bool IsCnpjValid(string cnpj)
        {
            if (string.IsNullOrWhiteSpace(cnpj)) return false;

            // Garante que só tenha 14 dígitos
            if (!Regex.IsMatch(cnpj, @"^\d{14}$")) return false;

            // Evita sequências iguais tipo 11111111111111
            if (cnpj.All(c => c == cnpj[0])) return false;

            int[] multiplier1 = { 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 };
            int[] multiplier2 = { 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 };

            int digit1 = CalculateDigit(cnpj, multiplier1);
            int digit2 = CalculateDigit(cnpj, multiplier2);

            return cnpj.EndsWith($"{digit1}{digit2}");
        }

        private int CalculateDigit(string cnpj, int[] multipliers)
        {
            int sum = 0;
            for (int i = 0; i < multipliers.Length; i++)
                sum += (cnpj[i] - '0') * multipliers[i];

            int remainder = sum % 11;
            return remainder < 2 ? 0 : 11 - remainder;
        }
    }
}
