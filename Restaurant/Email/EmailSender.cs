using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Threading.Tasks;

namespace Restaurant.Email
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailOptions _options;

        public EmailSender(IOptions<EmailOptions> emailOptions)
        {
            _options = emailOptions.Value ?? throw new ArgumentNullException(nameof(emailOptions), "EmailOptions yapılandırması eksik.");
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            if (string.IsNullOrEmpty(_options.SendGridKey))
            {
                throw new ArgumentNullException(nameof(_options.SendGridKey), "SendGrid API anahtarı bulunamadı.");
            }

            var client = new SendGridClient(_options.SendGridKey);
            var mesaj = new SendGridMessage()
            {
                From = new EmailAddress("aktassila4@gmail.com", "Aktas Cafe"),
                Subject = subject,
                PlainTextContent = htmlMessage,
                HtmlContent = htmlMessage
            };
            mesaj.AddTo(new EmailAddress(email));

            return client.SendEmailAsync(mesaj);
        }
    }
}
