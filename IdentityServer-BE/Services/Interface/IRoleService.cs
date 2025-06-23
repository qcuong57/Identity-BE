using IdentityServer_BE.Models.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityServer_BE.Services
{
    public interface IRoleService
    {
        Task<List<RoleDto>> GetAllRolesAsync();
        Task CreateRoleAsync(RoleDto model);
    }
}