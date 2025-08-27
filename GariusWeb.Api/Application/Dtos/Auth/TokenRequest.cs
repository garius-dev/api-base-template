using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class TokenRequest
    {
        [FromForm(Name = "grant_type")]
        [Required]
        public string GrantType { get; set; } = string.Empty;

        [FromForm(Name = "client_id")]
        [Required]
        public string ClientId { get; set; } = string.Empty;

        [FromForm(Name = "client_secret")]
        [Required]
        public string ClientSecret { get; set; } = string.Empty;
    }
}
