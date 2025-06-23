using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class TwoFactorModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Code { get; set; }
    }
}