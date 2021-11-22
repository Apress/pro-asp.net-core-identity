# Update for ASP.NET Core 6

## Overview

The features and API provided by ASP.NET Core Identity have not changed in ASP.NET Core 6, but they way they are applied in ASP.NET Core projects is different. ASP.NET Core introduces a new approach to configuring the platform, so that the statements that were previously defined in the `Startup` class are now applied in the `Program.cs` file. This file contains top-level C# statements, which are a new feature that allows one code file in a project to define code outside of a class, which will be executed when the application starts.

ASP.NET Core 6 projects also use null state analysis, which prevents null values being assigned to non-nullable reference types. These changes in ASP.NET Core 6 require many small changes to the examples in this book, even though the examples work in the same way and use the same ASP.NET Core Identity features. 

## Contents of this Update 
This update contains a complete set of replacement projects that have been updated to work with ASP.NET Core 6. The changes required for individual listings can be found in the [Updates Notes](Update%20Notes) folder, grouped by chapter.
This update has been written for .NET version 6.0.100. If you are using Visual Studio, you must update to Visual Studio 2022.

## Summary of Changes for ASP.NET Core 6
The changes for each chapter can be found in the individual notes in the [Updates Notes](Update%20Notes) folder and are categorized in the following sections.

### Category 1: Breaking Changes 
There is one change in the way that ASP.NET Core Identity 6 behaves. In Chapter 12, the default settings for the cookie that is used to identify users has changed and will not be accepted by the browser without the additional configuration settings shown in Listing 11-15:

    ...
    builder.Services.ConfigureApplicationCookie(opts => {
        opts.LoginPath = "/Identity/SignIn";
        opts.LogoutPath = "/Identity/SignOut";
        opts.AccessDeniedPath = "/Identity/Forbidden";
        opts.Events.DisableRedirectionForApiClients();
        opts.Cookie.HttpOnly = false;
        opts.Cookie.SameSite = SameSiteMode.None;
    });
    ...

 To my embarrassment, one of these changes is from a correction to the original code, which was added as an erratum for the ASP.NET Core 3 examples.

### Category 2: Attention Required 
Microsoft has not fully updated ASP.NET Core Identity to deal with the changes to the ASP.NET Core platform. One issue is that the `dotnet aspnet-codegenerator` command used in Chapter 6 adds configuration statements to the `Program.cs` file, even when the database it is using has been configured. These statements are added close to the top of the Program.cs file, like this:

    ...
    var connectionString = builder.Configuration.GetConnectionString("IdentityDbContextConnection");
    builder.Services.AddDbContext<IdentityDbContext>(options => options.UseSqlServer(connectionString));
    ...

The notes for Chapter 6 detail the listings after which these statements must be removed from the `Program.cs` file. 
Microsoft hasn’t updated all of the Identity API with the annotations required to support null state analysis, which means that some Identity interfaces cannot be implemented without causing compiler warnings. For these listings, I have used a `#pragma` directive to disable specific warnings. These changes are contained in the updated listings where this issue arises and can be found in the notes for Chapters 10, 17, 19 and 22.

### Category 3: Integration Changes 

The majority of changes contained in this update are to support the use of the Program.cs file and to introduce nullable reference types and null checks. These are optional changes, which I have included them for completeness. 
---

Adam Freeman, November 2021.