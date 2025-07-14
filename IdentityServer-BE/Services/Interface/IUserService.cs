using IdentityServer_BE.Models;
using IdentityServer_BE.Models.DTOs;

namespace IdentityServer_BE.Services
{
    public interface IUserService
    {
        Task<string> CreateUserAsync(UserDto model);
        Task UpdateUserAsync(string userId, UserDto model);
        Task LockUserAsync(string userId);
        Task UnlockUserAsync(string userId);
        Task DeleteUserAsync(string userId);
        Task<UserDto> GetUserByIdAsync(string userId);
        Task<PagedUserResponseDto> GetAllUsersAsync(int pageNumber = 1, int pageSize = 10, string search = "", string status = "");
        Task ChangePasswordAsync(string userId, string currentPassword, string newPassword);
        Task ResetPasswordAsync(string userId, string newPassword);
    }
}