using System.ComponentModel.DataAnnotations;

namespace IdentityServer_BE.Models.DTOs
{
    public class UpdateUserDto
    {
        public string? Email { get; set; }
        
        public string? PhoneNumber { get; set; }
        
        public string? Address { get; set; }
        
        public string? AvatarUrl { get; set; }
        
        public UpdateUserDto()
        {
            Email = string.Empty;
            PhoneNumber = string.Empty;
            Address = string.Empty;
        }
    }
    
    
}