using IdentityServer_BE.Models;
using MongoDB.Driver;

namespace IdentityServer_BE.Data
{
    public interface IUserRepository
    {
        Task<User> FindByIdAsync(string userId);
        Task<User> FindByEmailAsync(string email);
        IMongoCollection<User> GetCollection();
    }
}