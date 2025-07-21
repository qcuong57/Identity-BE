using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson.Serialization.Attributes;

namespace IdentityServer_BE.Models
{
    public class User : MongoIdentityUser<string>
    {
        [BsonElement("avatarUrl")]
        public string? AvatarUrl { get; set; }

        [BsonElement("status")]
        public string Status { get; set; } = "Active";

        [BsonElement("role")]
        public string Role { get; set; } = "User";

        [BsonElement("address")]
        public string? Address { get; set; }

        // Thêm các trường cho 2FA OTP
        [BsonElement("otpCode")]
        public string? OtpCode { get; set; }

        [BsonElement("otpExpiry")]
        public DateTime? OtpExpiry { get; set; }

        [BsonElement("otpAttempts")]
        public int OtpAttempts { get; set; } = 0;

        [BsonElement("otpLockoutTime")]
        public DateTime? OtpLockoutTime { get; set; }
    }
}