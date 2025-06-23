using IdentityServer_BE.Models;
using MongoDB.Driver;

namespace IdentityServer_BE.Data
{
    public interface IRoleRepository
    {
        Task<Role> FindByIdAsync(string roleId);
        Task<Role> FindByNameAsync(string roleName);
        Task CreateAsync(Role role);
        Task UpdateAsync(Role role);
        Task DeleteAsync(Role role);
        IMongoCollection<Role> GetCollection();
    }
}