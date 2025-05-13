using DataSecurityRSAV2.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace DataSecurityRSAV2.Controllers
{
    public class EncryptionRSAController : Controller
    {
        private readonly string storagePath = Path.Combine(Directory.GetCurrentDirectory(), "App_Data");

        public IActionResult Encrypt()
        {
            return View("Encryption");
        }

        [HttpPost]
        public IActionResult Encrypt(EncrytpionRSA model)
        {
            using RSA rsa = RSA.Create(2048);

            var publicKey = rsa.ExportRSAPublicKey();
            var privateKey = rsa.ExportRSAPrivateKey();

            var encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(model.PlainText), RSAEncryptionPadding.OaepSHA256);
            model.EncryptedText = Convert.ToBase64String(encryptedBytes);

            // Get user from session
            var username = HttpContext.Session.GetString("user") ?? "anonymous";

            // Create user-specific folder
            var userFolder = Path.Combine(storagePath, username);
            if (!Directory.Exists(userFolder))
                Directory.CreateDirectory(userFolder);

            // Save encrypted data and private key
            System.IO.File.WriteAllText(Path.Combine(userFolder, "encrypted.txt"), model.EncryptedText);
            System.IO.File.WriteAllText(Path.Combine(userFolder, "private.key"), Convert.ToBase64String(privateKey));

            ViewBag.Message = "Encryption successful. Encrypted data saved.";
            return View("Encryption", model);
        }


        public IActionResult Decrypt()
        {
            var model = new EncrytpionRSA();

            var username = HttpContext.Session.GetString("user") ?? "anonymous";
            var userFolder = Path.Combine(storagePath, username);

            var encryptedPath = Path.Combine(userFolder, "encrypted.txt");
            var privateKeyPath = Path.Combine(userFolder, "private.key");

            if (System.IO.File.Exists(encryptedPath) && System.IO.File.Exists(privateKeyPath))
            {
                var encryptedText = System.IO.File.ReadAllText(encryptedPath);
                var privateKey = Convert.FromBase64String(System.IO.File.ReadAllText(privateKeyPath));

                using RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(privateKey, out _);

                var decryptedBytes = rsa.Decrypt(Convert.FromBase64String(encryptedText), RSAEncryptionPadding.OaepSHA256);
                model.DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
                model.EncryptedText = encryptedText;

                ViewBag.Message = "Decryption successful.";
            }
            else
            {
                ViewBag.Message = "No encrypted data or key found for this user.";
            }

            return View("Decryption", model);
        }

    }
}
