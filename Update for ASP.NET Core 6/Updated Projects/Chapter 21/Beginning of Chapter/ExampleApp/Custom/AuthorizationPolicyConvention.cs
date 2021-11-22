using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace ExampleApp.Custom {

    public class AuthorizationPolicyConvention : IActionModelConvention {
        private string controllerName;
        private string? actionName;
        private IAuthorizeData attr = new AuthData();

        public AuthorizationPolicyConvention(string controller,
                string? action = null, string? policy = null,
                string? roles = null, string ?schemes = null) {
            controllerName = controller;
            actionName = action;
            attr.Policy = policy;
            attr.Roles = roles;
            attr.AuthenticationSchemes = schemes;
        }

        public void Apply(ActionModel action) {
            if (controllerName == action.Controller.ControllerName
                    && (actionName == null || actionName == action.ActionName)) {
                foreach (var s in action.Selectors) {
                    s.EndpointMetadata.Add(attr);
                }
            }
        }
    }

    class AuthData : IAuthorizeData {
        public string? AuthenticationSchemes { get; set; }
        public string? Policy { get; set; }
        public string? Roles { get; set; }
    }
}
