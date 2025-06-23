using IdentityServer_BE.Models;
using MongoDB.Driver;

namespace IdentityServer_BE.Data
{
    public class RoleRepository : IRoleRepository
    {
        private readonly MongoDbContext _context;
        private readonly IMongoCollection<Role> _roles;

        public RoleRepository(MongoDbContext context)
        {
            _context = context;
            _roles = _context.GetCollection<Role>("roles");
        }

        public async Task<Role> FindByIdAsync(string roleId)
        {
            return await _roles.Find(r => r.Id == roleId).FirstOrDefaultAsync();
        }

        public async Task<Role> FindByNameAsync(string roleName)
        {
            return await _roles.Find(r => r.NormalizedName == roleName).FirstOrDefaultAsync();
        }

        public async Task CreateAsync(Role role)
        {
            await _roles.InsertOneAsync(role);
        }

        public async Task UpdateAsync(Role role)
        {
            var filter = Builders<Role>.Filter.Eq(r => r.Id, role.Id);
            await _roles.ReplaceOneAsync(filter, role);
        }

        public async Task DeleteAsync(Role role)
        {
            var filter = Builders<Role>.Filter.Eq(r => r.Id, role.Id);
            await _roles.DeleteOneAsync(filter);
        }

        public IMongoCollection<Role> GetCollection()
        {
            return _roles;
        }
    }
}