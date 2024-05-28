using Application.DTOs.Request.Account;
using Application.DTOs.Response.Account;
using Application.DTOs.Response;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IAccountService
    {
        Task CreateAdmin();
        Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
        Task<LoginResponse> LogInAccountAsync(LoginDTO model);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model);
        Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model);
      //  Task<IEnumerable<GetRoleDTO>> GetRolesAsync();
        Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync();
        Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);
    }
}
