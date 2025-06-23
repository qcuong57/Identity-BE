using IdentityServer_BE.Data;
using IdentityServer_BE.Models;
using IdentityServer_BE.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace IdentityServer_BE.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly IUnitOfWork _unitOfWork;

        public UserService(UserManager<User> userManager, IUnitOfWork unitOfWork)
        {
            _userManager = userManager;
            _unitOfWork = unitOfWork;
        }

        private string GenerateRandomPassword()
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*";
            var randomBytes = RandomNumberGenerator.GetBytes(12);
            var chars = new char[12];
            for (int i = 0; i < 12; i++)
            {
                chars[i] = validChars[randomBytes[i] % validChars.Length];
            }
            return new string(chars);
        }

        public async Task<string> CreateUserAsync(UserDto model)
        {
            if (model.Role != "Admin" && model.Role != "User")
                return "Invalid role. Role must be 'Admin' or 'User'.";

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
                return "Email is already in use.";

            var user = new User
            {
                Id = model.Id ?? Guid.NewGuid().ToString(),
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                AvatarUrl = model.AvatarUrl,
                Status = model.Status ?? "Active",
                Role = model.Role
            };
            var password = GenerateRandomPassword();
            var result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                // Gán vai trò vào AspNetUserRoles
                await _userManager.AddToRoleAsync(user, model.Role);
                await _unitOfWork.SaveChangesAsync();
                return user.Id;
            }
            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        public async Task UpdateUserAsync(string userId, UserDto model)
        {
            if (model.Role != "Admin" && model.Role != "User")
                throw new InvalidOperationException("Invalid role. Role must be 'Admin' or 'User'.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null && existingUser.Id != userId)
                throw new InvalidOperationException("Email is already in use.");

            user.Email = model.Email;
            user.UserName = model.Email;
            user.PhoneNumber = model.PhoneNumber;
            user.AvatarUrl = model.AvatarUrl;
            user.Status = model.Status ?? "Active";
            user.Role = model.Role;

            if (!string.IsNullOrEmpty(user.PhoneNumber) && !new System.ComponentModel.DataAnnotations.PhoneAttribute().IsValid(user.PhoneNumber))
                throw new InvalidOperationException("Invalid phone number format");

            if (!string.IsNullOrEmpty(user.AvatarUrl) && !new System.ComponentModel.DataAnnotations.UrlAttribute().IsValid(user.AvatarUrl))
                throw new InvalidOperationException("Invalid URL format for avatar");

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            // Cập nhật vai trò
            var currentRoles = await _userManager.GetRolesAsync(user);
            if (!currentRoles.Contains(model.Role))
            {
                await _userManager.RemoveFromRolesAsync(user, currentRoles);
                await _userManager.AddToRoleAsync(user, model.Role);
            }

            await _unitOfWork.SaveChangesAsync();
        }

        public async Task LockUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");
            user.Status = "Locked";
            await _userManager.UpdateAsync(user);
            await _unitOfWork.SaveChangesAsync();
        }

        public async Task UnlockUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");
            user.Status = "Active";
            await _userManager.UpdateAsync(user);
            await _unitOfWork.SaveChangesAsync();
        }

        public async Task DeleteUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");
            await _userManager.DeleteAsync(user);
            await _unitOfWork.SaveChangesAsync();
        }

        public async Task<UserDto> GetUserByIdAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new InvalidOperationException("User not found");

            var roles = await _userManager.GetRolesAsync(user);
            var role = roles.FirstOrDefault() ?? user.Role ?? "User";

            return new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                AvatarUrl = user.AvatarUrl,
                Status = user.Status,
                Role = role
            };
        }

        public async Task<PagedUserResponseDto> GetAllUsersAsync(int pageNumber = 1, int pageSize = 10)
        {
            var filter = Builders<User>.Filter.Empty;
            var totalCount = await _unitOfWork.UserRepository.GetCollection().CountDocumentsAsync(filter);

            var users = await _unitOfWork.UserRepository.GetCollection()
                .Find(filter)
                .Skip((pageNumber - 1) * pageSize)
                .Limit(pageSize)
                .ToListAsync();

            var userDtos = new List<UserDto>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var role = roles.FirstOrDefault() ?? user.Role ?? "User";
                userDtos.Add(new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    AvatarUrl = user.AvatarUrl,
                    Status = user.Status,
                    Role = role
                });
            }

            return new PagedUserResponseDto
            {
                Users = userDtos,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalCount = (int)totalCount
            };
        }
    }
}