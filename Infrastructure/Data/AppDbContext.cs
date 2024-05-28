using Domain.Entity.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Data
{
    public class AppDbContext : IdentityDbContext<ApplicationUser, ApplicationUserRole, int>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)   
        {
            
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
