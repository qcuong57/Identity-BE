using IdentityServer_BE.Models;
using IdentityServer_BE.Models.DTOs;
using IdentityServer_BE.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IO;

namespace IdentityServer_BE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("create")]
        [AllowAnonymous]
        public async Task<IActionResult> CreateUser([FromForm] UserDto model, IFormFile avatar = null)
        {
            try
            {
                // Xử lý file ảnh nếu có
                string avatarUrl = null;
                if (avatar != null)
                {
                    // Validate file type and size
                    var allowedTypes = new[] { "image/jpeg", "image/jpg", "image/png", "image/gif" };
                    if (!allowedTypes.Contains(avatar.ContentType))
                    {
                        return BadRequest(new { Message = "Chỉ chấp nhận file ảnh (JPEG, PNG, GIF)" });
                    }
                    if (avatar.Length > 5 * 1024 * 1024) // 5MB
                    {
                        return BadRequest(new { Message = "Kích thước file không được vượt quá 5MB" });
                    }

                    // Tạo tên file duy nhất
                    var fileName = $"{Guid.NewGuid()}{Path.GetExtension(avatar.FileName)}";
                    var filePath = Path.Combine("wwwroot/avatars", fileName);
                    var fullPath = Path.Combine(Directory.GetCurrentDirectory(), filePath);

                    // Đảm bảo thư mục tồn tại
                    Directory.CreateDirectory(Path.GetDirectoryName(fullPath));

                    // Lưu file
                    using (var stream = new FileStream(fullPath, FileMode.Create))
                    {
                        await avatar.CopyToAsync(stream);
                    }

                    // Tạo URL cho ảnh
                    avatarUrl = $"/avatars/{fileName}";
                    model.AvatarUrl = avatarUrl;
                }

                var userId = await _userService.CreateUserAsync(model);
                if (!string.IsNullOrEmpty(userId) && !userId.Contains("Invalid"))
                    return Ok(new { UserId = userId, Message = "User created successfully" });
                return BadRequest(new { Message = userId });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = $"Lỗi khi tạo tài khoản: {ex.Message}" });
            }
        }

        [HttpPut("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> UpdateUser(string userId, [FromBody] UserDto model)
        {
            try
            {
                await _userService.UpdateUserAsync(userId, model);
                return Ok(new { Message = "User updated successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/lock")]
        [AllowAnonymous]
        public async Task<IActionResult> LockUser(string userId)
        {
            try
            {
                await _userService.LockUserAsync(userId);
                return Ok(new { Message = "User locked successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/unlock")]
        [AllowAnonymous]
        public async Task<IActionResult> UnlockUser(string userId)
        {
            try
            {
                await _userService.UnlockUserAsync(userId);
                return Ok(new { Message = "User unlocked successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpDelete("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            try
            {
                await _userService.DeleteUserAsync(userId);
                return Ok(new { Message = "User deleted successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpGet("{userId}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetUser(string userId)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                return Ok(user);
            }
            catch (InvalidOperationException ex)
            {
                return NotFound(new { Message = ex.Message });
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetAllUsers(
            int pageNumber = 1,
            int pageSize = 10,
            string search = "",
            string status = "")
        {
            var users = await _userService.GetAllUsersAsync(pageNumber, pageSize, search, status);
            return Ok(users);
        }

        [HttpPut("{userId}/change-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ChangePassword(string userId, [FromBody] ChangePasswordDto model)
        {
            try
            {
                await _userService.ChangePasswordAsync(userId, model.CurrentPassword, model.NewPassword);
                return Ok(new { Message = "Password changed successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPut("{userId}/reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string userId, [FromBody] ResetPasswordDto model)
        {
            try
            {
                await _userService.ResetPasswordAsync(userId, model.NewPassword);
                return Ok(new { Message = "Password reset successfully" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ResetPasswordDto
    {
        public string NewPassword { get; set; }
    }
}