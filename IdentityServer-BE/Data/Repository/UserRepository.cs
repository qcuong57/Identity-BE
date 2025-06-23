using IdentityServer_BE.Models;
using MongoDB.Driver;

namespace IdentityServer_BE.Data
{
    public class UserRepository : IUserRepository
    {
        private readonly MongoDbContext _context;
        private readonly IMongoCollection<User> _users;

        public UserRepository(MongoDbContext context)
        {
            _context = context;
            _users = _context.GetCollection<User>("users");
        }

        public async Task<User> FindByIdAsync(string userId)
        {
            return await _users.Find(u => u.Id == userId).FirstOrDefaultAsync();
        }

        public async Task<User> FindByEmailAsync(string email)
        {
            return await _users.Find(u => u.Email == email).FirstOrDefaultAsync();
        }

        public IMongoCollection<User> GetCollection()
        {
            return _users;
        }
    }
}