using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class ResetPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Token { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [MinLength(6)]
        public string NewPassword { get; set; }
    }
}