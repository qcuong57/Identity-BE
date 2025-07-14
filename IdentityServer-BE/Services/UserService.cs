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
                Role = model.Role,
                Address = model.Address
            };

            // Sử dụng password được cung cấp hoặc tạo random password
            var password = !string.IsNullOrEmpty(model.Password) ? model.Password : GenerateRandomPassword();
            
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
            user.Address = model.Address;

            if (!string.IsNullOrEmpty(user.PhoneNumber) && !new System.ComponentModel.DataAnnotations.PhoneAttribute().IsValid(user.PhoneNumber))
                throw new InvalidOperationException("Invalid phone number format");

            if (!string.IsNullOrEmpty(user.AvatarUrl) && !new System.ComponentModel.DataAnnotations.UrlAttribute().IsValid(user.AvatarUrl))
                throw new InvalidOperationException("Invalid URL format for avatar");

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            // Cập nhật password nếu được cung cấp
            if (!string.IsNullOrEmpty(model.Password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var passwordResult = await _userManager.ResetPasswordAsync(user, token, model.Password);
                if (!passwordResult.Succeeded)
                    throw new InvalidOperationException(string.Join(", ", passwordResult.Errors.Select(e => e.Description)));
            }

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
                Role = role,
                Address = user.Address
                // Không trả về password vì lý do bảo mật
            };
        }

        public async Task<PagedUserResponseDto> GetAllUsersAsync(
            int pageNumber = 1, 
            int pageSize = 10, 
            string search = "", 
            string status = "")
        {
            // Xây dựng filter cho MongoDB
            var filters = new List<FilterDefinition<User>>();

            // Thêm filter cho search (email hoặc phone)
            if (!string.IsNullOrEmpty(search))
            {
                var searchFilter = Builders<User>.Filter.Or(
                    Builders<User>.Filter.Regex(u => u.Email, new MongoDB.Bson.BsonRegularExpression(search, "i")),
                    Builders<User>.Filter.Regex(u => u.PhoneNumber, new MongoDB.Bson.BsonRegularExpression(search, "i"))
                );
                filters.Add(searchFilter);
            }

            // Thêm filter cho status
            if (!string.IsNullOrEmpty(status))
            {
                var statusFilter = Builders<User>.Filter.Eq(u => u.Status, status);
                filters.Add(statusFilter);
            }

            // Kết hợp tất cả filters
            var combinedFilter = filters.Count > 0 
                ? Builders<User>.Filter.And(filters) 
                : Builders<User>.Filter.Empty;

            var totalCount = await _unitOfWork.UserRepository.GetCollection().CountDocumentsAsync(combinedFilter);

            var users = await _unitOfWork.UserRepository.GetCollection()
                .Find(combinedFilter)
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
                    Role = role,
                    Address = user.Address
                    // Không trả về password vì lý do bảo mật
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

        // Thêm method riêng để thay đổi password
        public async Task ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");

            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            await _unitOfWork.SaveChangesAsync();
        }

        // Thêm method để reset password (dành cho admin)
        public async Task ResetPasswordAsync(string userId, string newPassword)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new InvalidOperationException("User not found");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            if (!result.Succeeded)
                throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            await _unitOfWork.SaveChangesAsync();
        }
    }
}