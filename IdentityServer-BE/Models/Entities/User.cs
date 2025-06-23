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
    }
}