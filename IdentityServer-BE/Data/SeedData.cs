using IdentityServer_BE.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace IdentityServer_BE.Data
{
    public static class SeedData
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<Role>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<User>>();

            // Tạo vai trò
            string[] roleNames = { "Admin", "User" };
            foreach (var roleName in roleNames)
            {
                var roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    var role = new Role
                    {
                        Name = roleName,
                        NormalizedName = roleName.ToUpper(),
                        Description = $"{roleName} role",
                        IsActive = true
                    };
                    var roleResult = await roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception($"Failed to create role {roleName}: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                    }
                }
            }

            // Tạo admin
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                var user = new User
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Status = "Active",
                    Role = "Admin",
                    EmailConfirmed = true
                };
                var createResult = await userManager.CreateAsync(user, "Admin@123!");
                if (!createResult.Succeeded)
                {
                    throw new Exception($"Failed to create admin user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
                }

                // Gán vai trò Admin
                var roleResult = await userManager.AddToRoleAsync(user, "Admin");
                if (!roleResult.Succeeded)
                {
                    throw new Exception($"Failed to assign Admin role to user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                }
            }
            else
            {
                // Kiểm tra và cập nhật vai trò nếu cần
                if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
                {
                    var roleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception($"Failed to assign Admin role to existing user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                    }
                    adminUser.Role = "Admin";
                    await userManager.UpdateAsync(adminUser);
                }
            }
        }
    }
}