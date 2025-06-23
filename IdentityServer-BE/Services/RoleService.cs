
using IdentityServer_BE.Models;
using IdentityServer_BE.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer_BE.Data;

namespace IdentityServer_BE.Services
{
    public class RoleService : IRoleService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly RoleManager<Role> _roleManager;

        public RoleService(IUnitOfWork unitOfWork, RoleManager<Role> roleManager)
        {
            _unitOfWork = unitOfWork;
            _roleManager = roleManager;
        }

        public async Task<List<RoleDto>> GetAllRolesAsync()
        {
            var roles = await _unitOfWork.RoleRepository.GetCollection()
                .Find(Builders<Role>.Filter.Empty)
                .ToListAsync();

            return roles.Select(r => new RoleDto
            {
                Id = r.Id,
                Name = r.Name,
                Description = r.Description,
                IsActive = r.IsActive
            }).ToList();
        }

        public async Task CreateRoleAsync(RoleDto model)
        {
            var roleExists = await _roleManager.RoleExistsAsync(model.Name);
            if (roleExists)
                throw new InvalidOperationException($"Role {model.Name} already exists");

            var role = new Role
            {
                Id = model.Id ?? Guid.NewGuid().ToString(),
                Name = model.Name,
                NormalizedName = model.Name.ToUpper(),
                Description = model.Description,
                IsActive = model.IsActive
            };

            var result = await _roleManager.CreateAsync(role);
            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            await _unitOfWork.SaveChangesAsync();
        }
    }
}