using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace GariusWeb.Api.Helpers.Attributes
{
    public class CPFAttribute : ValidationAttribute
    {
        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is null)
                return ValidationResult.Success; // Permitir nulo, se for opcional

            var stringValue = value as string;
            if (string.IsNullOrWhiteSpace(stringValue))
                return ValidationResult.Success; // Permitir nulo, se for opcional

            var cpf = stringValue
                .Replace(".", string.Empty)
                .Replace("-", string.Empty);

            if (!IsCpfValid(cpf))
                return new ValidationResult(ErrorMessage ?? "CPF inválido.");

            return ValidationResult.Success;
        }

        private bool IsCpfValid(string cpf)
        {
            if (!Regex.IsMatch(cpf, @"^\d{11}$")) return false;
            if (cpf.All(c => c == cpf[0])) return false; // evita sequências iguais

            int[] multiplier1 = { 10, 9, 8, 7, 6, 5, 4, 3, 2 };
            int[] multiplier2 = { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2 };

            int digit1 = CalculateDigit(cpf, multiplier1);
            int digit2 = CalculateDigit(cpf, multiplier2);

            return cpf.EndsWith($"{digit1}{digit2}");
        }

        private static int CalculateDigit(string cpf, int[] multipliers)
        {
            int sum = 0;
            for (int i = 0; i < multipliers.Length; i++)
                sum += (cpf[i] - '0') * multipliers[i];

            int remainder = sum % 11;
            return remainder < 2 ? 0 : 11 - remainder;
        }
    }
}
