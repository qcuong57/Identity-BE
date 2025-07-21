using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class LoginWith2FAModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP code must be exactly 6 digits")]
        public string Code { get; set; }
    }
}