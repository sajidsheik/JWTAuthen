using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthen
{
public class Startup
{
    static string KEYFACTORY = "RSA";
	static string JWT_TYPE = "JWT";
	static string JWT_ALGORITHM = "RS256";
    static string publickey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzWKPMwumwUso/sQLwAUyj3c040SPwaRhNcFN5dmjl5NOG3XizxPXD3E20CLeMCQ6mdsO6wrKfQVS0nGaYim9PNWiYteJd5cZk6faxLq9T7W6JUupTqqEajHMkbkWusp5o3zDMgXL0I8CBWHGs8ymQvdheTi1QiaSaGwAYZO2KJJGgtaRVwRcU9t5PghBqiEy/keqm2sK/ypykdHY5SbNHw/pcZOGYYIVEZNwePEMlA/kpv6tNJPHg4hIkam+EREV947QOfYCWf0lPRi/JmEmoPFsdFBXW/QTyDTnLNujChmlp63Yp7IXgXfV3ENZ65FszqdTvrg5SnUql3Ctceq5wrIQfkqvVJ2poogk/8jR24pbzkKNeUVYWDem0nIVlfHMI3e66D+EQctgDaivOaw4LR1/j3Um25mcyM+fsrWE+ugD8YlTEnm7i2jxdFlOZ63S2hIcioLBwpfvotlj61LikTecn+QojjKRnaeMBa22RrLkvBxtGNbtM8tDID+OWBkoa4f0q0Uz1s55Bc4CW7FKGXprDylfimzvo+ZMuG4M39nmJWZrRP7YBDLc6+6JWnv7EsJ+4fhocaajXBlKjvTYJUaOP22uGBMvaZlbqv6K1wVyz5p81bJkL7d4eBUxCI1NaUe12M3rLe8gZzJsu2EJYZC3lRHgNs/2uLL6WErn6KECAwEAAQ==";
    string iss = "apigateway-nonprod";
    string sub = "hyperion";
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }



    // This method gets called by the runtime. Use this method to add services to the container.
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
    // configure jwt authentication
    //var key = Encoding.ASCII.GetBytes(publickey);
    byte[] key = null;

             // byte[] publicBytes = Convert.FromBase64String(publickey);// Base64.getDecoder().decode(publickey.getBytes());
           // byte[] bytes = Encoding.ASCII.GetBytes(publickey);
            byte[] textAsBytes = System.Convert.FromBase64String(publickey);

           // X509EncodedKeySpec x509 = new X509EncodedKeySpec(textAsBytes);
    // keyFactory_ = System.KeyFactory.getInstance("RSA");
           

    services.AddAuthentication(x =>
    {
        x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(x =>
    {
        x.RequireHttpsMetadata = false;
        x.SaveToken = true;
        x.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });

    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IHostingEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseMvc();
    }
}
}
