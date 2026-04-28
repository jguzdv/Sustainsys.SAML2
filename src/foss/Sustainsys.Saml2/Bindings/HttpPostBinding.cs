// Copyright (c) Sustainsys AB. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Sustainsys.Saml2.AspNetCore;
using Sustainsys.Saml2.Xml;
using System.Globalization;
using System.Text;
using System.Xml;

namespace Sustainsys.Saml2.Bindings;

/// <summary>
/// Saml Http POST Binding
/// </summary>
public class HttpPostBinding() : FrontChannelBinding(Constants.BindingUris.HttpPOST)
{
    /// <inheritdoc/>
    public override bool CanUnBind(HttpRequest httpRequest)
        => httpRequest.Method == "POST"
        && httpRequest.Form.Keys.Any(
            k => k == Constants.SamlRequest || k == Constants.SamlResponse);

    /// <inheritdoc/>
    protected override Task<InboundSaml2Message> DoUnBindAsync(
        HttpRequest httpRequest,
        BindingOptions bindingOptions,
        Func<string, Task<Saml2Entity>> getSaml2Entity)
    {
        if (!CanUnBind(httpRequest))
        {
            throw new InvalidOperationException("Cannot unbind from this request. Always call CanUnbind before UnbindAsync to validate.");
        }

        var name = ExtractMessageName(httpRequest);
        var xml = DecodeMessage(httpRequest, name, bindingOptions);

        // TODO: Size limit of incoming message.

        // TODO: Size limit of RelayState

        var xd = XmlHelpers.LoadXml(xml);

        return Task.FromResult(new InboundSaml2Message
        {
            Destination = httpRequest.PathBase + httpRequest.Path,
            Name = name,
            RelayState = httpRequest.Form[Constants.RelayState].SingleOrDefault(),
            Xml = xd.DocumentElement!,
            Binding = Identifier
        });
    }

    private static string DecodeMessage(HttpRequest httpRequest, string name, BindingOptions bindingOptions)
    {
        var encoded = httpRequest.Form[name].Single() ?? throw new InvalidOperationException($"No value found for {name}");

        // Base64 encoding gives ~33% length increase
        if (encoded.Length > bindingOptions.MaxMessageSize + bindingOptions.MaxMessageSize / 3)
        {
            throw new InvalidOperationException($"Encoded size of {name} is {encoded.Length} " +
                $"which is too large for configured max message size of {bindingOptions.MaxMessageSize}");
        }

        var decoded = Convert.FromBase64String(encoded);

        if (decoded.Length > bindingOptions.MaxMessageSize)
        {
            throw new InvalidOperationException($"Decoded size of {name} is {decoded.Length} " +
                $"which is larger than allowed {bindingOptions.MaxMessageSize}");
        }

        return Encoding.UTF8.GetString(decoded);
    }

    private static string ExtractMessageName(HttpRequest httpRequest)
    {
        string name;
        if (httpRequest.Form.ContainsKey(Constants.SamlRequest))
        {
            if (httpRequest.Form.ContainsKey(Constants.SamlResponse))
            {
                throw new ArgumentException("Either SamlResponse or SamlRequest should be defined, not both.");
            }
            name = Constants.SamlRequest;
        }
        else
        {
            if (httpRequest.Form.ContainsKey(Constants.SamlResponse))
            {
                name = Constants.SamlResponse;
            }
            else
            {
                // No need to handle case where none was present - CanUnbind should have taken care of that.
                throw new NotImplementedException();
            }
        }

        return name;
    }

    /// <inheritdoc/>
    protected override async Task DoBindAsync(
        HttpResponse httpResponse,
        OutboundSaml2Message message)

    {
        var xmlDoc = message.Xml;
        if (message.SigningCertificate != null)
        {
            var issuerElement = xmlDoc["Issuer", Constants.Namespaces.SamlUri]!;

            xmlDoc.Sign(message.SigningCertificate, issuerElement);
        }

        // TODO: Change to use string interpolation instead, it has better performance
        // TODO: Should RelayState be encoded to avoid XSS?
        var relayStateHtml = string.IsNullOrEmpty(message.RelayState) ? null
            : string.Format(CultureInfo.InvariantCulture, PostHtmlRelayStateFormatString, message.RelayState);

        var encodedXml = Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlDoc.OuterXml));

        // TODO: Change to use string interpolation instead, it has better performance
        var content = string.Format(
                    CultureInfo.InvariantCulture,
                    PostHtmlFormatString,
                    message.Destination,
                    relayStateHtml,
                    message.Name,
                    encodedXml);

        httpResponse.ContentType = "text/html";
        await httpResponse.WriteAsync(content);
    }

    private const string PostHtmlRelayStateFormatString = @"
<input type=""hidden"" name=""RelayState"" value=""{0}""/>";

    // TODO: Is xml marker and doctype needed? Bindings 3.5.4 requires XHTML.

    private const string PostHtmlFormatString = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE html PUBLIC ""-//W3C//DTD XHTML 1.1//EN""
""http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd"">
<html xmlns=""http://www.w3.org/1999/xhtml"" xml:lang=""en"">
<head>
<meta http-equiv=""Content-Security-Policy"" content=""script-src 'sha256-H3SVZBYrbqBt3ncrT/nNmOb6nwCjC12cPQzh5jnW4Y0='"">
</head>
<body>
<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript, 
you must press the Continue button once to proceed.
</p>
</noscript>
<form action=""{0}"" method=""post"" name=""sustainsysSamlPostBindingSubmit"">
<div>{1}
<input type=""hidden"" name=""{2}""
value=""{3}""/>
</div>
<noscript>
<div>
<input type=""submit"" value=""Continue""/>
</div>
</noscript>
</form>
<script type=""text/javascript"">
document.forms.sustainsysSamlPostBindingSubmit.submit();
</script>
</body>
</html>";

}