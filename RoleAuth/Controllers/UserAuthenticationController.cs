using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RoleAuth.Models.DTO;
using RoleAuth.Repositories.Abstract;

namespace RoleAuth.Controllers
{
    public class UserAuthenticationController : Controller
    {
        private readonly IUserAuthenticationService _service;
        public UserAuthenticationController(IUserAuthenticationService service)
        {
            _service = service;
        }
        public IActionResult Login()
        {
            return View();
        }

        public IActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Registration(RegistrationModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            model.Role = "User";
            var result = await _service.RegisterAsync(model);
            TempData["msg"] = result.Message;

            return RedirectToAction(nameof(Registration));
        }

        //used for once to create admin
        public async Task<IActionResult> reg()
        {
            RegistrationModel model = new RegistrationModel
            {
                Name = "Raghav",
                Username = "Admin010",
                Email = "admin010@gmail.com",
                Password = "Admin@010"
            };
            model.Role = "admin";
            var result = await _service.RegisterAsync(model);
            return Ok(result);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        { 
        if(!ModelState.IsValid)
            {
                return View(model);
            }
        var result = await _service.LoginAsync(model);

            if(result.StatusCode == 1)
            {
                return RedirectToAction("Display", "DashBoard");
            }
            else
            {
                TempData["msg"] = result.Message;
                return RedirectToAction(nameof(Login));
            }
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
           await _service.LogoutAsync();
            return RedirectToAction(nameof(Login));
        }
      
    }
}
