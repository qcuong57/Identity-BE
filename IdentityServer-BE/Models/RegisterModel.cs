using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class RegisterModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [MinLength(6)]  
        public string Password { get; set; }

        [Phone]
        public string? PhoneNumber { get; set; }
    }
}