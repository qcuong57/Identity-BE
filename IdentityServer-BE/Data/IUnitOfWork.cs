using IdentityServer_BE.Data;

namespace IdentityServer_BE.Data
{
    public interface IUnitOfWork
    {
        IUserRepository UserRepository { get; }
        IRoleRepository RoleRepository { get; }
        Task SaveChangesAsync();
    }
}