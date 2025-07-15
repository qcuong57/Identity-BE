using IdentityServer_BE.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace IdentityServer_BE.Data
{
    public static class SeedData
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<Role>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<User>>();

            // Create roles
            string[] roleNames = { "Admin", "User" };
            foreach (var roleName in roleNames)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (!roleExists)
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

            // Create admin user
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                var user = new User
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Status = "Active",
                    Role = "Admin", // Custom field for tracking role
                    EmailConfirmed = true
                };
                var createResult = await userManager.CreateAsync(user, "Admin@123!");
                if (!createResult.Succeeded)
                {
                    throw new Exception($"Failed to create admin user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
                }

                // Assign Admin role
                var roleResult = await userManager.AddToRoleAsync(user, "Admin");
                if (!roleResult.Succeeded)
                {
                    throw new Exception($"Failed to assign Admin role to user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                }
            }
            else
            {
                // Ensure existing admin user has the Admin role
                if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
                {
                    var roleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception($"Failed to assign Admin role to existing user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                    }
                    adminUser.Role = "Admin"; // Update custom field
                    var updateResult = await userManager.UpdateAsync(adminUser);
                    if (!updateResult.Succeeded)
                    {
                        throw new Exception($"Failed to update admin user: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
                    }
                }
            }

            // Example: Create a regular user (optional, for demonstration)
            var regularUserEmail = "user@example.com";
            var regularUser = await userManager.FindByEmailAsync(regularUserEmail);
            if (regularUser == null)
            {
                var user = new User
                {
                    UserName = regularUserEmail,
                    Email = regularUserEmail,
                    Status = "Active",
                    Role = "User", // Custom field for tracking role
                    EmailConfirmed = true
                };
                var createResult = await userManager.CreateAsync(user, "User@123!");
                if (!createResult.Succeeded)
                {
                    throw new Exception($"Failed to create regular user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
                }

                // Assign User role
                var roleResult = await userManager.AddToRoleAsync(user, "User");
                if (!roleResult.Succeeded)
                {
                    throw new Exception($"Failed to assign User role to user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                }
            }
            else
            {
                // Ensure existing regular user has the User role
                if (!await userManager.IsInRoleAsync(regularUser, "User"))
                {
                    var roleResult = await userManager.AddToRoleAsync(regularUser, "User");
                    if (!roleResult.Succeeded)
                    {
                        throw new Exception($"Failed to assign User role to existing user: {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
                    }
                    regularUser.Role = "User"; // Update custom field
                    var updateResult = await userManager.UpdateAsync(regularUser);
                    if (!updateResult.Succeeded)
                    {
                        throw new Exception($"Failed to update regular user: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
                    }
                }
            }
        }
    }
}