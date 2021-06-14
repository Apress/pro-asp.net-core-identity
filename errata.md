# Errata for *Pro ASP.NET Core Identity*

**Chapter 4**

The files created in Listings 4-9 and 4-10 should be created in the `Views/Shared` folder and not `Pages/Shared` as stated in the text.

(Thanks to Jason Perry for reporting this problem)

**Chapter 12**

The example in the **Enabling CORS** section omits a configuration statement that allows the JavaScript code to send a cookie to the ASP.NET Core server. Add the following statement to the `Startup` class:

    opts.Cookie.SameSite = SameSiteMode.None; 

The statement should be included in the function passed to the `ConfigureApplicationCookie` method, like this:

    services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
        opts.Cookie.SameSite = SameSiteMode.None; // <-- this statement
    });

(Thanks to Felix Rabinovich for reporting this problem)

