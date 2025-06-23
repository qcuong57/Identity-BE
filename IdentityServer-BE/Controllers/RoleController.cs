using IdentityServer_BE.Models.DTOs;
using IdentityServer_BE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer_BE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class RoleController : ControllerBase
    {
        private readonly IRoleService _roleService;

        public RoleController(IRoleService roleService)
        {
            _roleService = roleService;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetAllRoles()
        {
            var roles = await _roleService.GetAllRolesAsync();
            return Ok(roles);
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateRole([FromBody] RoleDto model)
        {
            try
            {
                await _roleService.CreateRoleAsync(model);
                return Ok($"Role {model.Name} created successfully");
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}