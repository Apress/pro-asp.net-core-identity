# Errata for *Pro ASP.NET Core Identity*

**Chapter 3** 

On page 32, the commands that install the `libman` package and use it to get Bootstrap do not work. This can be resolved using a more recent version of the `libman` package, as follows:

    dotnet tool uninstall --global Microsoft.Web.LibraryManager.Cli
    dotnet tool install --global Microsoft.Web.LibraryManager.Cli --version 2.1.175
    libman init -p cdnjs
    libman install twitter-bootstrap@4.5.0 -d wwwroot/lib/twitter-bootstrap

(Thanks to Aaron Day for reporting this problem)

---

**Chapter 4**

The files created in Listings 4-9 and 4-10 should be created in the `Views/Shared` folder and not `Pages/Shared` as stated in the text.

(Thanks to Jason Perry for reporting this problem)
***

**Chapter 12**

The example in the **Enabling CORS** section omits a configuration statement that allows the JavaScript code to send a cookie to the ASP.NET Core server. Add the following statement to the `Startup` class:

    opts.Cookie.SameSite = SameSiteMode.None; 

The statement should be included in the function passed to the `ConfigureApplicationCookie` method, like this:

<pre><code>    services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
        <b>opts.Cookie.SameSite = SameSiteMode.None; // <-- this statement</b>
    });
</code></pre>

(Thanks to Felix Rabinovich for reporting this problem)

***
**Chapter 12**

The expiry timestamp for the token in Listing 12-23 is created with the wrong timezone:

<pre><code>Expires = DateTime.<b>Now</b>.AddMinutes(int.Parse(Configuration["BearerTokens:ExpiryMins"])),</code></pre>

The token should be created in UTC, like this:

<pre><code>Expires = DateTime.<b>UtcNow</b>.AddMinutes(int.Parse(Configuration["BearerTokens:ExpiryMins"])),</code></pre>

(Thanks to Greg Balajewicz for reporting this problem)

***


