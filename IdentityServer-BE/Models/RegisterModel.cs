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
        [Required] // Nếu số điện thoại là bắt buộc
        public string PhoneNumber { get; set; }

        [Required]
        public string Address { get; set; }
    }
}