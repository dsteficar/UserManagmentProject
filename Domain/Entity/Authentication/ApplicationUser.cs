﻿using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entity.Authentication
{
    public class ApplicationUser : IdentityUser<int>
    {
        public string? Name { get; set; }
    }
}
