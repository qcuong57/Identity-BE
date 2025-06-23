using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models
{
    public class UpdateProfileModel
    {
        [Phone]
        public string? PhoneNumber { get; set; }

        [Url]
        public string? AvatarUrl { get; set; }
    }
}