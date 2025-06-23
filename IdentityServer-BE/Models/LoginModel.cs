using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class LoginModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string? TwoFactorCode { get; set; }
    }
}