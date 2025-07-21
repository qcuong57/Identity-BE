using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class ResendVerificationModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; }
    }
}