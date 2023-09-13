using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

Console.WriteLine("Private-------");
RSA rsa = RSA.Create();
Console.WriteLine(rsa.ToXmlString(true));
Console.WriteLine("\n\n\n Public-------");
Console.WriteLine(rsa.ToXmlString(false));
