using IdentityServer_BE.Data;

namespace IdentityServer_BE.Data
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly MongoDbContext _context;
        public IUserRepository UserRepository { get; private set; }
        public IRoleRepository RoleRepository { get; private set; }

        public UnitOfWork(MongoDbContext context)
        {
            _context = context;
            UserRepository = new UserRepository(context);
            RoleRepository = new RoleRepository(context);
        }

        public async Task SaveChangesAsync()
        {
            await Task.CompletedTask;
        }
    }
}