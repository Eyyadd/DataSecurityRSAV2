using DataSecurityRSAV2.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataSecurityRSAV2.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly string userFile = "Data/users.txt";
        public IActionResult Register() => View();

        [HttpPost]
        public IActionResult Register(string name, string email, string password)
        {
            string hash = ComputeSha256Hash(password);

            var user = new User { Name = name, Email = email, PasswordHash = hash };

            if (!System.IO.Directory.Exists("Data"))
                System.IO.Directory.CreateDirectory("Data");

            var users = System.IO.File.Exists(userFile)
                ? System.IO.File.ReadAllLines(userFile)
                    .Select(line => JsonSerializer.Deserialize<User>(line))
                    .ToList()!
                : new List<User>();

            if (users.Any(u => u.Email == email))
            {
                ViewBag.Message = "User already exists";
                return View();
            }

            System.IO.File.AppendAllText(userFile, JsonSerializer.Serialize(user) + "\n");
            return RedirectToAction("Login");
        }

        public IActionResult Login() => View();
        [HttpPost]
        public IActionResult Login(string email, string password)
        {
            var users = System.IO.File.ReadAllLines(userFile)
                .Select(line => JsonSerializer.Deserialize<User>(line))
                .ToList();

            var user = users.FirstOrDefault(u => u.Email == email);
            if (user == null || user.PasswordHash != ComputeSha256Hash(password))
            {
                ViewBag.Message = "Invalid credentials";
                return View();
            }

            HttpContext.Session.SetString("user", email);
            return RedirectToAction("Index", "Home");
        }

        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        public IActionResult ChangePassword()
        {
            if (!HttpContext.Session.TryGetValue("user", out _))
                return RedirectToAction("Login");

            return View();
        }

        [HttpPost]
        public IActionResult ChangePassword(string oldPassword, string newPassword)
        {
            if (!HttpContext.Session.TryGetValue("user", out var userBytes))
                return RedirectToAction("Login");

            string email = Encoding.UTF8.GetString(userBytes);

            var users = System.IO.File.ReadAllLines(userFile)
            .Select(line => JsonSerializer.Deserialize<User>(line)!)
            .Where(u => u != null)
            .ToList();


            var user = users.FirstOrDefault(u => u.Email == email);
            if (user == null || user.PasswordHash != ComputeSha256Hash(oldPassword))
            {
                ViewBag.Message = "Old password is incorrect.";
                return View();
            }

            user.PasswordHash = ComputeSha256Hash(newPassword);

            // Rewrite the file with updated user
            var updatedContent = users
                .Where(u => u != null) // filter out nulls
                .Select(u => JsonSerializer.Serialize(u!)); // tell the compiler it's safe
            System.IO.File.WriteAllLines(userFile, updatedContent);

            ViewBag.Message = "Password changed successfully.";
            return View();
        }

        public IActionResult ResetRequest() => View("ResetPassword");

        [HttpPost]
        public IActionResult ResetRequest(string email)
        {
            var users = System.IO.File.ReadAllLines(userFile)
                .Select(line => JsonSerializer.Deserialize<User>(line))
                .Where(u => u != null)
                .ToList();

            var user = users.FirstOrDefault(u => u.Email == email);
            if (user == null)
            {
                ViewBag.Message = "No user found with this email.";
                return View();
            }

            ViewBag.Email = email;
            return View("ResetPasswordV");
        }

        [HttpPost]
        public IActionResult ResetPassword(string email, string newPassword)
        {
            var users = System.IO.File.ReadAllLines(userFile)
                .Select(line => JsonSerializer.Deserialize<User>(line))
                .Where(u => u != null)
                .ToList();

            var user = users.FirstOrDefault(u => u.Email == email);
            if (user == null)
            {
                return RedirectToAction("ResetRequest");
            }

            user.PasswordHash = ComputeSha256Hash(newPassword);

            var updatedContent = users
                .Where(u => u != null)
                .Select(u => JsonSerializer.Serialize(u));

            System.IO.File.WriteAllLines(userFile, updatedContent);

            return RedirectToAction("Login");
        }



        private static string ComputeSha256Hash(string rawData)
        {
            using var sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }
}
