﻿namespace IdentityServer_BE.Models.DTOs
{
    public class RoleDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string? Description { get; set; }
        public bool IsActive { get; set; }
    }
}   