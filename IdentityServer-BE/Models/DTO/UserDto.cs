namespace IdentityServer_BE.Models.DTOs
{
    public class UserDto
    {
        private string _id = Guid.NewGuid().ToString();

        public string Id
        {
            get => _id;
            set => _id = string.IsNullOrEmpty(value) ? Guid.NewGuid().ToString() : value;
        }

        public string Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? AvatarUrl { get; set; }
        public string Status { get; set; } = "Active";
        public string Role { get; set; } = "User";
        public string? Address { get; set; }
        public string? Password { get; set; } // Chỉ dùng khi tạo hoặc cập nhật password
    }
}