using AspNetCore.Identity.MongoDbCore.Models;
using MongoDB.Bson.Serialization.Attributes;

namespace IdentityServer_BE.Models
{
    public class Role : MongoIdentityRole<string>
    {
        [BsonElement("description")]
        public string? Description { get; set; }

        [BsonElement("isActive")]
        public bool IsActive { get; set; } = true;
    }
}